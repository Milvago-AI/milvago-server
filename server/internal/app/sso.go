package app

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Single sign-on is Keycloak identity brokering, configured from the console so that
// nobody has to open the identity provider's own administration. The realm is shared
// by every organization, so a provider is an instance setting under a fixed alias.
// Keycloak is the only store: no table, and the client secret never comes back out.

const (
	ssoPath = "/identity-provider/instances/"
	// Keycloak's built-in flow: an existing account is linked only after the person
	// signing in proves they control it, never on a matching e-mail alone.
	ssoBrokerLoginFlow = "first broker login"
	microsoftLogin     = "https://login.microsoftonline.com/"
)

var (
	ssoProviders     = []string{"google", "microsoft"}
	ssoClientPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,200}$`)
	guidPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

type ssoBody struct {
	Enabled      bool   `json:"enabled"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	HostedDomain string `json:"hosted_domain"`
	TenantID     string `json:"tenant_id"`
}

type ssoView struct {
	Configured   bool   `json:"configured"`
	Enabled      bool   `json:"enabled"`
	ClientID     string `json:"client_id"`
	HostedDomain string `json:"hosted_domain,omitempty"`
	TenantID     string `json:"tenant_id,omitempty"`
	RedirectURI  string `json:"redirect_uri"`
}

func (a *App) registerSSORoutes() {
	a.console("GET /api/settings/sso", permDirectoryManage, a.ssoSettings)
	// Fresh second factor on both, so session-only: a provider decides who can sign in
	// to every organization, and removing one locks its accounts out.
	a.sessionOnly("PUT /api/settings/sso/{provider}", permDirectoryManage, a.licensed(a.putSSO))
	a.sessionOnly("DELETE /api/settings/sso/{provider}", permDirectoryManage, a.deleteSSO)
}

// publicIssuer is the realm URL browsers reach, which the confirmed public URL may
// have changed since start-up.
func (a *App) publicIssuer() string {
	issuer := a.publicOIDC.Load().issuer
	if !strings.Contains(issuer, "/realms/") {
		issuer = a.config.Issuer
	}
	return strings.TrimRight(issuer, "/")
}

// requireSSOOperator applies the directory's rule: in Enterprise the realm, and so
// every provider, is shared by all tenants.
func requireSSOOperator(ctx context.Context, tx pgx.Tx, s *Session) error {
	operator, e := directoryOperator(ctx, tx, s)
	if e != nil {
		return e
	}
	if !operator {
		return apiError{403, "operator_required", "Only an owner of the root organization can configure single sign-on: every organization's sign-in offers it."}
	}
	return nil
}

func ssoProvider(r *http.Request) (string, error) {
	alias := r.PathValue("provider")
	if !slices.Contains(ssoProviders, alias) {
		return "", apiError{404, "not_found", "Unknown single sign-on provider."}
	}
	return alias, nil
}

// readSSOProvider returns the provider's Keycloak representation, nil when absent.
func readSSOProvider(ctx context.Context, admin *identityAdmin, alias string) (map[string]any, error) {
	status, _, raw, e := admin.call(ctx, "GET", ssoPath+alias, nil)
	if e != nil {
		return nil, e
	}
	if status == 404 {
		return nil, nil
	}
	var current map[string]any
	if status != 200 || json.Unmarshal(raw, &current) != nil {
		return nil, apiError{502, "identity_unavailable", "Could not read the single sign-on provider."}
	}
	return current, nil
}

func ssoConfig(current map[string]any) map[string]any {
	config, _ := current["config"].(map[string]any)
	return config
}

func ssoConfigValue(current map[string]any, key string) string {
	v, _ := ssoConfig(current)[key].(string)
	return v
}

func (a *App) ssoViewOf(alias string, current map[string]any) ssoView {
	v := ssoView{RedirectURI: a.publicIssuer() + "/broker/" + alias + "/endpoint"}
	if current == nil {
		return v
	}
	v.Configured = true
	v.Enabled, _ = current["enabled"].(bool)
	v.ClientID = ssoConfigValue(current, "clientId")
	if alias == "google" {
		v.HostedDomain = ssoConfigValue(current, "hostedDomain")
	} else {
		v.TenantID = strings.TrimSuffix(strings.TrimPrefix(ssoConfigValue(current, "issuer"), microsoftLogin), "/v2.0")
	}
	return v
}

func (a *App) ssoSettings(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	editable, e := directoryOperator(r.Context(), tx, s)
	if e != nil {
		return e
	}
	admin, e := a.identityAdmin(r.Context())
	if e != nil {
		return e
	}
	providers := map[string]ssoView{}
	for _, alias := range ssoProviders {
		current, e := readSSOProvider(r.Context(), admin, alias)
		if e != nil {
			return e
		}
		providers[alias] = a.ssoViewOf(alias, current)
	}
	reply(w, 200, map[string]any{"editable": editable, "providers": providers})
	return nil
}

// validate normalizes and bounds a submission before any value reaches Keycloak.
// Every endpoint is derived from these values here: none is taken from the client.
func (b *ssoBody) validate(alias string) error {
	b.ClientID = strings.TrimSpace(b.ClientID)
	b.HostedDomain = strings.ToLower(strings.TrimSpace(b.HostedDomain))
	b.TenantID = strings.ToLower(strings.TrimSpace(b.TenantID))
	if invalidSecret(b.ClientSecret) {
		return bad("Client secret is too long or malformed.")
	}
	if alias == "google" {
		b.TenantID = ""
		if !ssoClientPattern.MatchString(b.ClientID) {
			return bad("Enter the OAuth client ID Google issued.")
		}
		// Without a domain any Google account could present itself to the broker.
		if len(b.HostedDomain) > 253 || !strings.Contains(b.HostedDomain, ".") || !ldapHostPattern.MatchString(b.HostedDomain) {
			return bad("Enter the organization's Google Workspace domain.")
		}
		return nil
	}
	b.HostedDomain = ""
	b.ClientID = strings.ToLower(b.ClientID)
	if !guidPattern.MatchString(b.ClientID) {
		return bad("Enter the application (client) ID Microsoft Entra issued.")
	}
	// A GUID only: common, organizations and consumers would accept other tenants.
	if !guidPattern.MatchString(b.TenantID) {
		return bad("Enter the directory (tenant) ID of the organization's Microsoft Entra tenant.")
	}
	return nil
}

func (b ssoBody) representation(alias, secret string) map[string]any {
	config := map[string]any{"clientId": b.ClientID, "clientSecret": secret, "defaultScope": "openid profile email", "syncMode": "IMPORT"}
	rep := map[string]any{"alias": alias, "providerId": alias, "enabled": b.Enabled, "trustEmail": true, "storeToken": false, "linkOnly": false, "hideOnLogin": false, "firstBrokerLoginFlowAlias": ssoBrokerLoginFlow, "config": config}
	if alias == "google" {
		// Google verifies its e-mail addresses, and Keycloak checks the token's hd claim.
		config["hostedDomain"] = b.HostedDomain
		rep["displayName"] = "Google"
		return rep
	}
	// Microsoft through the generic OpenID Connect provider, pinned to one tenant: the
	// built-in Microsoft provider has no tenant setting, and the tenant's own issuer is
	// what lets Keycloak reject a token minted by any other tenant.
	tenant := microsoftLogin + b.TenantID
	rep["providerId"], rep["displayName"] = "oidc", "Microsoft"
	// Entra does not guarantee that its e-mail claim was verified.
	rep["trustEmail"] = false
	maps.Copy(config, map[string]any{
		"authorizationUrl": tenant + "/oauth2/v2.0/authorize", "tokenUrl": tenant + "/oauth2/v2.0/token",
		"jwksUrl": tenant + "/discovery/v2.0/keys", "issuer": tenant + "/v2.0", "useJwksUrl": "true",
		"validateSignature": "true", "pkceEnabled": "true", "pkceMethod": "S256",
		"clientAuthMethod": "client_secret_post", "disableUserInfo": "true",
	})
	return rep
}

func (a *App) putSSO(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	alias, err := ssoProvider(r)
	if err != nil {
		return err
	}
	if err = requireSSOOperator(r.Context(), tx, s); err != nil {
		return err
	}
	var body ssoBody
	if err = decode(w, r, &body); err != nil {
		return err
	}
	if err = body.validate(alias); err != nil {
		return err
	}
	if err = a.requireFreshMFA(r, tx, s); err != nil {
		return err
	}
	admin, err := a.identityAdmin(r.Context())
	if err != nil {
		return err
	}
	current, err := readSSOProvider(r.Context(), admin, alias)
	if err != nil {
		return err
	}
	secret := body.ClientSecret
	if secret == "" {
		// A secret belongs to one client: keep it only for the client it was issued to.
		if current == nil || ssoConfigValue(current, "clientId") != body.ClientID {
			return bad("Enter the client secret.")
		}
		secret = secretMask // Keycloak keeps the stored secret
	}
	rep := body.representation(alias, secret)
	if current != nil {
		if err = requireOwnSSOProvider(r.Context(), admin, alias, current, rep); err != nil {
			return err
		}
	}
	// Before the provider exists, so that it is never offered with linking open.
	if err = disableSelfLinking(r.Context(), admin); err != nil {
		return err
	}
	method, path, want := "POST", strings.TrimSuffix(ssoPath, "/"), 201
	if current != nil {
		maps.Copy(current, rep)
		rep, method, path, want = current, "PUT", ssoPath+alias, 204
	}
	status, _, raw, err := admin.call(r.Context(), method, path, rep)
	if err != nil {
		return err
	}
	if status != want {
		message := keycloakMessage(raw)
		if message == "" {
			message = "The identity provider refused the single sign-on configuration."
		}
		return apiError{502, "identity_unavailable", message}
	}
	if err = audit(r.Context(), tx, s.OrganizationID, s.UserID, "sso.update", alias); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	current, err = readSSOProvider(r.Context(), admin, alias)
	if err != nil {
		return err
	}
	reply(w, 200, a.ssoViewOf(alias, current))
	return nil
}

// requireOwnSSOProvider refuses to take over a provider the console did not write:
// a save replaces its configuration, but another provider type, a post-login flow or
// mappers would survive it unseen and keep deciding who signs in and with what.
// Removing it from the console is the explicit way out.
func requireOwnSSOProvider(ctx context.Context, admin *identityAdmin, alias string, current, rep map[string]any) error {
	status, _, raw, e := admin.call(ctx, "GET", ssoPath+alias+"/mappers", nil)
	if e != nil {
		return e
	}
	var mappers []json.RawMessage
	if status != 200 || json.Unmarshal(raw, &mappers) != nil {
		return apiError{502, "identity_unavailable", "Could not read the single sign-on provider."}
	}
	if post, _ := current["postBrokerLoginFlowAlias"].(string); current["providerId"] != rep["providerId"] || post != "" || len(mappers) != 0 {
		return apiError{409, "sso_provider_foreign", "This provider was configured outside the console. Remove it here, then save it again."}
	}
	return nil
}

// disableSelfLinking turns off Keycloak's idp_link required action, which lets a
// signed-in user attach an external account to their own at will: a provider is
// offered for sign-in, and an account links only through the first broker login's
// proof of possession. Enabled by default in Keycloak 26, hence checked on every save.
func disableSelfLinking(ctx context.Context, admin *identityAdmin) error {
	const actionPath = "/authentication/required-actions/idp_link"
	status, _, raw, e := admin.call(ctx, "GET", actionPath, nil)
	if e != nil {
		return e
	}
	var action map[string]any
	if status == 404 {
		return nil // a Keycloak release without the action
	}
	if status != 200 || json.Unmarshal(raw, &action) != nil {
		return apiError{502, "identity_unavailable", "Could not read the account-linking setting."}
	}
	if enabled, _ := action["enabled"].(bool); !enabled {
		return nil
	}
	action["enabled"] = false
	if status, _, _, e = admin.call(ctx, "PUT", actionPath, action); e != nil {
		return e
	}
	if status != 204 {
		return apiError{502, "identity_unavailable", "Could not turn off self-service account linking."}
	}
	return nil
}

func (a *App) deleteSSO(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	alias, err := ssoProvider(r)
	if err != nil {
		return err
	}
	if err = requireSSOOperator(r.Context(), tx, s); err != nil {
		return err
	}
	if err = a.requireFreshMFA(r, tx, s); err != nil {
		return err
	}
	admin, err := a.identityAdmin(r.Context())
	if err != nil {
		return err
	}
	status, _, _, err := admin.call(r.Context(), "DELETE", ssoPath+alias, nil)
	if err != nil {
		return err
	}
	if status != 204 && status != 404 {
		return apiError{502, "identity_unavailable", "The identity provider could not remove the single sign-on provider."}
	}
	if err = audit(r.Context(), tx, s.OrganizationID, s.UserID, "sso.remove", alias); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	reply(w, 200, map[string]bool{"ok": true})
	return nil
}
