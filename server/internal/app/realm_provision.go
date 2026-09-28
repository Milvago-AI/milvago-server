package app

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// An organization realm is created from the root realm's own settings and custom flows,
// then converged like it: the root realm is converged by the installation scripts, and
// what Keycloak does not carry over on creation (changes to its built-in flows and
// required actions, the SMTP password it never returns) is applied here.

// realmSettings are the root realm settings a new organization realm starts from.
var realmSettings = []string{
	"sslRequired", "registrationAllowed", "resetPasswordAllowed", "rememberMe", "verifyEmail",
	"loginWithEmailAllowed", "duplicateEmailsAllowed", "editUsernameAllowed", "bruteForceProtected",
	"permanentLockout", "maxFailureWaitSeconds", "minimumQuickLoginWaitSeconds", "waitIncrementSeconds",
	"quickLoginCheckMilliSeconds", "maxDeltaTimeSeconds", "failureFactor", "passwordPolicy", "otpPolicyType",
	"otpPolicyAlgorithm", "otpPolicyDigits", "otpPolicyPeriod", "otpPolicyLookAheadWindow", "loginTheme",
	"emailTheme", "accountTheme", "internationalizationEnabled", "supportedLocales", "defaultLocale",
	"accessTokenLifespan", "ssoSessionIdleTimeout", "ssoSessionMaxLifespan", "offlineSessionIdleTimeout",
	"browserFlow", "firstBrokerLoginFlow", "resetCredentialsFlow", "directGrantFlow", "registrationFlow",
	"clientAuthenticationFlow", "dockerAuthenticationFlow", "attributes",
}

// managementRoles are the realm-management roles of an organization's service account.
var managementRoles = []string{"manage-users", "query-users", "view-users", "manage-realm", "view-realm", "manage-clients", "view-clients", "manage-identity-providers", "view-identity-providers"}

// identityBase is the address the server reaches Keycloak at.
func (a *App) identityBase() (string, error) {
	if a.config.InternalOIDC != "" {
		return strings.TrimRight(a.config.InternalOIDC, "/"), nil
	}
	u, e := url.Parse(a.config.Issuer)
	if e != nil || u.Host == "" {
		return "", errors.New("invalid OIDC issuer")
	}
	return u.Scheme + "://" + u.Host, nil
}

// ensureOrganizationRealms gives every organization without a realm its own, and
// converges each realm, the root one included (Enterprise). A failure is logged and
// retried at the next start: sign-in to that organization's realm fails until then.
func (a *App) ensureOrganizationRealms(ctx context.Context) {
	if a.config.Issuer == "" || a.config.AdminClientSecret == "" {
		return
	}
	if admin, e := a.identityAdmin(ctx); e == nil {
		if e = convergeBrowserRedirector(ctx, admin); e != nil {
			a.log.Warn("root realm sign-in flow not converged", "error", e)
		}
	}
	if Edition != "commercial" {
		return
	}
	rows, e := a.db.Query(ctx, `SELECT o.id,o.name FROM organizations o, app_config c WHERE o.id<>c.organization_id`)
	if e != nil {
		a.log.Warn("organization realms not converged", "error", e)
		return
	}
	type org struct{ id, name string }
	var orgs []org
	for rows.Next() {
		var o org
		if rows.Scan(&o.id, &o.name) == nil {
			orgs = append(orgs, o)
		}
	}
	rows.Close()
	origin, e := a.publicIdentityOrigin(ctx)
	if e != nil {
		a.log.Warn("organization realms not converged", "error", e)
		return
	}
	for _, o := range orgs {
		if e := a.ensureOrganizationRealm(ctx, origin, o.id, o.name); e != nil {
			a.log.Warn("organization realm not converged", "organization", o.id, "error", e)
		}
	}
}

// ensureOrganizationRealm creates the realm of a child organization when missing, then
// converges it.
func (a *App) ensureOrganizationRealm(ctx context.Context, origin, org, name string) error {
	// Without a realm in the configured issuer there is no identity administration at
	// all (identityAdminFor refuses), hence no realm to create.
	if Edition != "commercial" || a.rootRealm() == "" {
		return nil
	}
	realm := childRealm(org)
	exists, e := a.realmExists(ctx, realm)
	if e != nil {
		return e
	}
	root, e := a.identityAdmin(ctx)
	if e != nil {
		return e
	}
	if !exists {
		if e = a.createOrganizationRealm(ctx, root, origin, realm, name); e != nil {
			return e
		}
	}
	admin, e := a.identityAdminFor(ctx, realm)
	if e != nil {
		return e
	}
	return convergeRealm(ctx, root, admin)
}

func (a *App) realmExists(ctx context.Context, realm string) (bool, error) {
	base, e := a.identityBase()
	if e != nil {
		return false, e
	}
	client := &http.Client{Timeout: 15 * time.Second}
	request, e := http.NewRequestWithContext(ctx, "GET", base+"/realms/"+url.PathEscape(realm)+"/.well-known/openid-configuration", nil)
	if e != nil {
		return false, e
	}
	response, e := client.Do(request)
	if e != nil {
		return false, apiError{502, "identity_unavailable", "Could not contact the identity provider."}
	}
	response.Body.Close()
	switch response.StatusCode {
	case 200:
		return true, nil
	case 404:
		return false, nil
	}
	return false, apiError{502, "identity_unavailable", "Could not read the organization realm."}
}

// stripIdentifiers removes Keycloak's own identifiers from an exported representation:
// they belong to the root realm and cannot be reused in another.
func stripIdentifiers(v any) any {
	switch x := v.(type) {
	case []any:
		for i := range x {
			x[i] = stripIdentifiers(x[i])
		}
	case map[string]any:
		delete(x, "id")
		delete(x, "flowId")
		for k := range x {
			x[k] = stripIdentifiers(x[k])
		}
	}
	return v
}

func (a *App) createOrganizationRealm(ctx context.Context, root *identityAdmin, origin, realm, name string) error {
	var rootRealm, exported map[string]any
	if e := adminJSON(ctx, root, "GET", "", nil, 200, &rootRealm); e != nil {
		return e
	}
	if e := adminJSON(ctx, root, "POST", "/partial-export?exportClients=false&exportGroupsAndRoles=false", nil, 200, &exported); e != nil {
		return e
	}
	rep := map[string]any{}
	for _, k := range realmSettings {
		if v, ok := rootRealm[k]; ok {
			rep[k] = v
		}
	}
	custom := []any{}
	flows, _ := exported["authenticationFlows"].([]any)
	for _, f := range flows {
		if flow, ok := f.(map[string]any); ok && flow["builtIn"] != true {
			custom = append(custom, stripIdentifiers(flow))
		}
	}
	// The root realm's attributes, frontendUrl included: it is set only when Keycloak is
	// served under the console's own address, and the child realm is reached the same way.
	attributes, _ := rep["attributes"].(map[string]any)
	if attributes == nil {
		attributes = map[string]any{}
	}
	smtp, e := a.sealedSMTP(ctx)
	if e != nil {
		return e
	}
	if smtp == nil {
		if s, ok := rootRealm["smtpServer"].(map[string]any); ok {
			smtp = map[string]string{}
			for k, v := range s {
				if text, ok := v.(string); ok && k != "password" {
					smtp[k] = text
				}
			}
		}
	}
	realmRoles := map[string]any{"realm-management": managementRoles}
	for k, v := range map[string]any{
		"realm": realm, "enabled": true, "displayName": name, "attributes": attributes, "smtpServer": smtp,
		"authenticationFlows": custom, "authenticatorConfig": stripIdentifiers(exported["authenticatorConfig"]),
		"clients": []any{
			map[string]any{"clientId": a.config.ClientID, "enabled": true, "protocol": "openid-connect", "publicClient": false, "secret": a.config.ClientSecret,
				"standardFlowEnabled": true, "directAccessGrantsEnabled": false, "redirectUris": []string{origin + "/auth/callback"}, "webOrigins": []string{origin},
				"baseUrl": signInURL(origin, realm), "attributes": map[string]string{"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": origin + "/*"},
				"defaultClientScopes": []string{"basic", "profile", "email", "roles", "acr"}},
			map[string]any{"clientId": a.config.AdminClientID, "enabled": true, "protocol": "openid-connect", "publicClient": false, "secret": a.config.AdminClientSecret,
				"serviceAccountsEnabled": true, "standardFlowEnabled": false, "directAccessGrantsEnabled": false},
		},
		"users": []any{map[string]any{"username": "service-account-" + a.config.AdminClientID, "enabled": true, "serviceAccountClientId": a.config.AdminClientID, "clientRoles": realmRoles}},
	} {
		rep[k] = v
	}
	token, e := a.provisionerToken(ctx)
	if e != nil {
		return e
	}
	base, e := a.identityBase()
	if e != nil {
		return e
	}
	provisioner := &identityAdmin{client: &http.Client{Timeout: 30 * time.Second}, token: token, base: base + "/admin/realms"}
	status, _, raw, e := provisioner.call(ctx, "POST", "", rep)
	if e != nil {
		return e
	}
	if status != 201 && status != 409 {
		a.log.Warn("organization realm creation refused", "status", status, "message", keycloakMessage(raw))
		return apiError{502, "identity_unavailable", "The identity provider could not create the organization realm."}
	}
	return nil
}

// provisionerToken authenticates the master-realm client that may create realms and do
// nothing else: its token carries only that role, and the realms it creates are then
// administered by their own service accounts.
func (a *App) provisionerToken(ctx context.Context) (string, error) {
	if a.config.ProvisionerClientSecret == "" {
		return "", apiError{503, "identity_admin_unavailable", "Organization realms need OIDC_PROVISIONER_CLIENT_SECRET."}
	}
	base, e := a.identityBase()
	if e != nil {
		return "", e
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {a.config.ProvisionerClientID}, "client_secret": {a.config.ProvisionerClientSecret}}
	request, e := http.NewRequestWithContext(ctx, "POST", base+"/realms/master/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if e != nil {
		return "", e
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, e := (&http.Client{Timeout: 15 * time.Second}).Do(request)
	if e != nil {
		return "", apiError{502, "identity_unavailable", "Could not contact the identity provider."}
	}
	defer response.Body.Close()
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if response.StatusCode != 200 || json.NewDecoder(io.LimitReader(response.Body, 64*1024)).Decode(&token) != nil || token.AccessToken == "" {
		return "", apiError{502, "identity_unavailable", "The identity provider refused the realm provisioning account."}
	}
	return token.AccessToken, nil
}

// convergeRealm applies to an organization realm what realm creation does not carry
// over from the root one: the enabled required actions, the password-reset second
// factor step, and the provider redirector of the sign-in flow.
func convergeRealm(ctx context.Context, root, admin *identityAdmin) error {
	var rootActions, actions []map[string]any
	if e := adminJSON(ctx, root, "GET", "/authentication/required-actions", nil, 200, &rootActions); e != nil {
		return e
	}
	if e := adminJSON(ctx, admin, "GET", "/authentication/required-actions", nil, 200, &actions); e != nil {
		return e
	}
	wanted := map[any]map[string]any{}
	for _, action := range rootActions {
		wanted[action["alias"]] = action
	}
	for _, action := range actions {
		want, ok := wanted[action["alias"]]
		if !ok || (action["enabled"] == want["enabled"] && action["defaultAction"] == want["defaultAction"]) {
			continue
		}
		action["enabled"], action["defaultAction"] = want["enabled"], want["defaultAction"]
		path := "/authentication/required-actions/" + url.PathEscape(action["alias"].(string))
		if e := adminJSON(ctx, admin, "PUT", path, action, http.StatusNoContent, nil); e != nil {
			return e
		}
	}
	if e := convergeResetSecondFactor(ctx, root, admin); e != nil {
		return e
	}
	return convergeBrowserRedirector(ctx, admin)
}

const resetSecondFactor = "Reset - Conditional OTP"

func convergeResetSecondFactor(ctx context.Context, root, admin *identityAdmin) error {
	requirement := func(a *identityAdmin) (map[string]any, string, error) {
		var realm map[string]any
		if e := adminJSON(ctx, a, "GET", "", nil, 200, &realm); e != nil {
			return nil, "", e
		}
		flow, _ := realm["resetCredentialsFlow"].(string)
		if flow == "" {
			flow = "reset credentials"
		}
		path := flowExecutionsPath(flow)
		var executions []map[string]any
		if e := adminJSON(ctx, a, "GET", path, nil, 200, &executions); e != nil {
			return nil, "", e
		}
		for _, x := range executions {
			if x["displayName"] == resetSecondFactor {
				return x, path, nil
			}
		}
		return nil, path, nil
	}
	want, _, e := requirement(root)
	if e != nil || want == nil {
		return e
	}
	have, path, e := requirement(admin)
	if e != nil || have == nil || have["requirement"] == want["requirement"] {
		return e
	}
	status, _, _, e := admin.call(ctx, "PUT", path, map[string]any{"id": have["id"], "requirement": want["requirement"]})
	if e != nil {
		return e
	}
	if status != http.StatusAccepted && status != http.StatusNoContent {
		return apiError{502, "identity_unavailable", "Could not converge the password reset flow."}
	}
	return nil
}

// convergeBrowserRedirector adds Keycloak's identity-provider redirector to the realm's
// sign-in flow, right after the session cookie: kc_idp_hint then sends an address of an
// organization's domain straight to its provider, and without a hint the sign-in is
// unchanged. A step-up never carries a hint, so it still asks for the second factor.
func convergeBrowserRedirector(ctx context.Context, admin *identityAdmin) error {
	var realm map[string]any
	if e := adminJSON(ctx, admin, "GET", "", nil, 200, &realm); e != nil {
		return e
	}
	flow, _ := realm["browserFlow"].(string)
	if flow == "" {
		return nil
	}
	path := flowExecutionsPath(flow)
	top := func() ([]map[string]any, error) {
		var executions []map[string]any
		if e := adminJSON(ctx, admin, "GET", path, nil, 200, &executions); e != nil {
			return nil, e
		}
		level := []map[string]any{}
		for _, x := range executions {
			if l, _ := x["level"].(float64); l == 0 {
				level = append(level, x)
			}
		}
		return level, nil
	}
	executions, e := top()
	if e != nil {
		return e
	}
	for _, x := range executions {
		if x["providerId"] == "identity-provider-redirector" {
			return nil
		}
	}
	if e = adminJSON(ctx, admin, "POST", path+"/execution", map[string]any{"provider": "identity-provider-redirector"}, 201, nil); e != nil {
		return e
	}
	if executions, e = top(); e != nil {
		return e
	}
	for i, x := range executions {
		if x["providerId"] != "identity-provider-redirector" {
			continue
		}
		x["requirement"] = "ALTERNATIVE"
		status, _, _, e := admin.call(ctx, "PUT", path, x)
		if e != nil {
			return e
		}
		if status != http.StatusAccepted && status != http.StatusNoContent {
			return apiError{502, "identity_unavailable", "Could not converge the sign-in flow."}
		}
		// Added last; raised until it sits right after the session cookie.
		id, _ := x["id"].(string)
		for ; i > 1; i-- {
			status, _, _, e := admin.call(ctx, "POST", "/authentication/executions/"+url.PathEscape(id)+"/raise-priority", nil)
			if e != nil {
				return e
			}
			if status/100 != 2 {
				return apiError{502, "identity_unavailable", "Could not converge the sign-in flow."}
			}
		}
	}
	return nil
}

// sealedSMTP returns the SMTP settings chosen at setup, nil when none were.
func (a *App) sealedSMTP(ctx context.Context) (map[string]string, error) {
	var sealed []byte
	if e := a.db.QueryRow(ctx, `SELECT smtp_sealed FROM app_config`).Scan(&sealed); e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, e
	}
	size := a.config.SessionCipher.NonceSize()
	if len(sealed) <= size {
		return nil, nil
	}
	plain, e := a.config.SessionCipher.Open(nil, sealed[:size], sealed[size:], []byte("smtp"))
	if e != nil {
		// Sealed under another session key: the realm is created without SMTP.
		a.log.Warn("stored SMTP settings cannot be opened")
		return nil, nil
	}
	var smtp map[string]string
	if json.Unmarshal(plain, &smtp) != nil {
		return nil, nil
	}
	return smtp, nil
}

// storeSMTP seals the SMTP settings saved into the root realm, for the realms created
// later.
func (a *App) storeSMTP(ctx context.Context, tx pgx.Tx, smtp map[string]string) error {
	plain, e := json.Marshal(smtp)
	if e != nil {
		return e
	}
	nonce := make([]byte, a.config.SessionCipher.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `UPDATE app_config SET smtp_sealed=$1 WHERE singleton`, a.config.SessionCipher.Seal(nonce, nonce, plain, []byte("smtp")))
	return e
}

// deleteOrganizationRealm removes a deleted organization's realm with that realm's own
// service account.
func (a *App) deleteOrganizationRealm(ctx context.Context, org string) {
	if Edition != "commercial" {
		return
	}
	admin, e := a.identityAdminFor(ctx, childRealm(org))
	if e == nil {
		var status int
		if status, _, _, e = admin.call(ctx, "DELETE", "", nil); e == nil && status != http.StatusNoContent && status != http.StatusNotFound {
			e = errors.New("unexpected status")
		}
	}
	if e != nil {
		a.log.Warn("organization realm not deleted", "organization", org, "error", e)
	}
}
