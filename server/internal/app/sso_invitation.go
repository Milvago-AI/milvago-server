package app

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/url"
	"strings"
)

// A member invited with an address of the organization's domain signs in with Google or
// Microsoft straight from the invitation: the e-mail link proves the mailbox, and the
// provider answers for the same address. Keycloak's own first login would otherwise ask
// them to prove, a second time, that they own the account created for the invitation.
// Google verifies its addresses within the Workspace domain; Entra does not guarantee its
// e-mail claim, so Microsoft applies only to a domain the owner declares, in the one
// pinned tenant.

const (
	// ssoPendingRole marks an account created by an invitation and not yet used to sign
	// in. It is granted only by the invitation and removed at the first sign-in.
	ssoPendingRole = "milvago-pending-invitation"
	// ssoFirstLoginFlow is the first-login flow of both providers.
	ssoFirstLoginFlow = "milvago-sso-first-login"
	// ssoInvitationDomain is the Microsoft provider setting naming that domain.
	ssoInvitationDomain = "milvagoInvitationDomain"
)

type flowStep struct {
	level       int
	name        string // the authenticator of an execution, the alias of a subflow
	subflow     bool
	requirement string
	config      map[string]string
}

// ssoFirstLoginSteps is Keycloak's first broker login without its profile review, which
// would let the person edit the address before it is matched, and with one change: the
// existing account is named first, then the confirmation and proof are skipped only when
// that account holds the pending-invitation role. A missing role means proof, and the
// link is written only if the whole flow succeeds.
var ssoFirstLoginSteps = []flowStep{
	{0, "milvago-sso-linking", true, "REQUIRED", nil},
	{1, "idp-create-user-if-unique", false, "ALTERNATIVE", nil},
	{1, "milvago-sso-existing", true, "ALTERNATIVE", nil},
	{2, "idp-auto-link", false, "REQUIRED", nil},
	{2, "milvago-sso-proof", true, "CONDITIONAL", nil},
	{3, "conditional-user-role", false, "REQUIRED", map[string]string{"condUserRole": ssoPendingRole, "negate": "true"}},
	{3, "idp-confirm-link", false, "REQUIRED", nil},
	{3, "milvago-sso-verify", true, "REQUIRED", nil},
	{4, "idp-email-verification", false, "ALTERNATIVE", nil},
	{4, "milvago-sso-reauth", true, "ALTERNATIVE", nil},
	{5, "idp-username-password-form", false, "REQUIRED", nil},
	{5, "milvago-sso-reauth-otp", true, "CONDITIONAL", nil},
	{6, "conditional-user-configured", false, "REQUIRED", nil},
	{6, "auth-otp-form", false, "REQUIRED", nil},
}

var errSSOFlowForeign = apiError{409, "sso_flow_foreign", "The single sign-on sign-in flow was changed outside the console; it is not used until it is restored."}

func flowExecutionsPath(alias string) string {
	return "/authentication/flows/" + url.PathEscape(alias) + "/executions"
}

// adminJSON makes one identity administration call that must answer want.
func adminJSON(ctx context.Context, admin *identityAdmin, method, path string, body any, want int, out any) error {
	status, _, raw, e := admin.call(ctx, method, path, body)
	if e != nil {
		return e
	}
	if status != want || (out != nil && json.Unmarshal(raw, out) != nil) {
		return apiError{502, "identity_unavailable", "The identity provider refused the single sign-on sign-in flow."}
	}
	return nil
}

// ensureSSOInvitationLinking creates the role and the first-login flow when they
// are missing, then proves the flow is exactly the one above before it is used.
func ensureSSOInvitationLinking(ctx context.Context, admin *identityAdmin) error {
	if _, e := pendingRole(ctx, admin, true); e != nil {
		return e
	}
	status, _, _, e := admin.call(ctx, "GET", flowExecutionsPath(ssoFirstLoginFlow), nil)
	if e != nil {
		return e
	}
	if status == 404 {
		if e = buildSSOFirstLoginFlow(ctx, admin); e != nil {
			return e
		}
	}
	return verifySSOFirstLoginFlow(ctx, admin)
}

// pendingRole reads the role, creating it when asked to.
func pendingRole(ctx context.Context, admin *identityAdmin, create bool) (map[string]any, error) {
	path := "/roles/" + url.PathEscape(ssoPendingRole)
	status, _, raw, e := admin.call(ctx, "GET", path, nil)
	if e != nil {
		return nil, e
	}
	if status == 404 && create {
		if e = adminJSON(ctx, admin, "POST", "/roles", map[string]any{"name": ssoPendingRole, "description": "Invited, not signed in yet: may link its Google or Microsoft account without further proof."}, 201, nil); e != nil {
			return nil, e
		}
		return pendingRole(ctx, admin, false)
	}
	if status == 404 {
		return nil, nil
	}
	var role map[string]any
	if status != 200 || json.Unmarshal(raw, &role) != nil {
		return nil, apiError{502, "identity_unavailable", "Could not read the invitation role."}
	}
	return role, nil
}

func buildSSOFirstLoginFlow(ctx context.Context, admin *identityAdmin) error {
	if e := adminJSON(ctx, admin, "POST", "/authentication/flows", map[string]any{"alias": ssoFirstLoginFlow, "providerId": "basic-flow", "topLevel": true, "builtIn": false, "description": "Milvago single sign-on first login"}, 201, nil); e != nil {
		return e
	}
	parents := []string{ssoFirstLoginFlow}
	for _, step := range ssoFirstLoginSteps {
		parents = parents[:step.level+1]
		parent := parents[step.level]
		var before []map[string]any
		if e := adminJSON(ctx, admin, "GET", flowExecutionsPath(parent), nil, 200, &before); e != nil {
			return e
		}
		known := map[any]bool{}
		for _, x := range before {
			known[x["id"]] = true
		}
		if step.subflow {
			if e := adminJSON(ctx, admin, "POST", flowExecutionsPath(parent)+"/flow", map[string]any{"alias": step.name, "type": "basic-flow", "provider": "registration-page-form", "description": step.name}, 201, nil); e != nil {
				return e
			}
			parents = append(parents, step.name)
		} else if e := adminJSON(ctx, admin, "POST", flowExecutionsPath(parent)+"/execution", map[string]any{"provider": step.name}, 201, nil); e != nil {
			return e
		}
		var after []map[string]any
		if e := adminJSON(ctx, admin, "GET", flowExecutionsPath(parent), nil, 200, &after); e != nil {
			return e
		}
		var added map[string]any
		for _, x := range after {
			if !known[x["id"]] {
				added = x
			}
		}
		if added == nil {
			return errSSOFlowForeign
		}
		added["requirement"] = step.requirement
		// Keycloak answers 202 or 204 depending on the release.
		status, _, _, e := admin.call(ctx, "PUT", flowExecutionsPath(parent), added)
		if e != nil {
			return e
		}
		if status != http.StatusAccepted && status != http.StatusNoContent {
			return apiError{502, "identity_unavailable", "The identity provider refused the single sign-on sign-in flow."}
		}
		if step.config != nil {
			id, _ := added["id"].(string)
			if e := adminJSON(ctx, admin, "POST", "/authentication/executions/"+url.PathEscape(id)+"/config", map[string]any{"alias": ssoFirstLoginFlow + "-pending-invitation", "config": step.config}, 201, nil); e != nil {
				return e
			}
		}
	}
	return nil
}

func verifySSOFirstLoginFlow(ctx context.Context, admin *identityAdmin) error {
	var executions []map[string]any
	if e := adminJSON(ctx, admin, "GET", flowExecutionsPath(ssoFirstLoginFlow), nil, 200, &executions); e != nil {
		return e
	}
	if len(executions) != len(ssoFirstLoginSteps) {
		return errSSOFlowForeign
	}
	for i, step := range ssoFirstLoginSteps {
		x := executions[i]
		level, _ := x["level"].(float64)
		subflow, _ := x["authenticationFlow"].(bool)
		name := x["providerId"]
		if subflow {
			name = x["displayName"]
		}
		if int(level) != step.level || subflow != step.subflow || name != step.name || x["requirement"] != step.requirement {
			return errSSOFlowForeign
		}
		configID, _ := x["authenticationConfig"].(string)
		if (step.config == nil) != (configID == "") {
			return errSSOFlowForeign
		}
		if step.config == nil {
			continue
		}
		var config struct {
			Config map[string]string `json:"config"`
		}
		if e := adminJSON(ctx, admin, "GET", "/authentication/config/"+url.PathEscape(configID), nil, 200, &config); e != nil {
			return e
		}
		if !maps.Equal(config.Config, step.config) {
			return errSSOFlowForeign
		}
	}
	return nil
}

// invitationProvider reports whether an invitation to email can sign in directly: an
// offered provider runs the flow above and answers for the address's domain.
func invitationProvider(ctx context.Context, admin *identityAdmin, email string) (bool, error) {
	_, domain, _ := strings.Cut(email, "@")
	for _, alias := range ssoProviders {
		current, e := readSSOProvider(ctx, admin, alias)
		if e != nil {
			return false, e
		}
		if current == nil {
			continue
		}
		enabled, _ := current["enabled"].(bool)
		owned := ssoConfigValue(current, "hostedDomain")
		if alias == "microsoft" {
			owned = ssoConfigValue(current, ssoInvitationDomain)
		}
		if enabled && current["firstBrokerLoginFlowAlias"] == ssoFirstLoginFlow && owned != "" && strings.EqualFold(domain, owned) {
			return true, nil
		}
	}
	return false, nil
}

// markPendingInvitation grants the role to an account the invitation just created.
func markPendingInvitation(ctx context.Context, admin *identityAdmin, subject string) error {
	role, e := pendingRole(ctx, admin, false)
	if e != nil {
		return e
	}
	if role == nil {
		return apiError{502, "identity_unavailable", "The invitation role is missing."}
	}
	return adminJSON(ctx, admin, "POST", keycloakUsersPath+url.PathEscape(subject)+"/role-mappings/realm", []any{role}, http.StatusNoContent, nil)
}

// clearPendingInvitation removes the role at the first sign-in, whatever its method:
// from then on, linking another Google or Microsoft account needs the usual proof.
func clearPendingInvitation(ctx context.Context, admin *identityAdmin, subject string) error {
	path := keycloakUsersPath + url.PathEscape(subject) + "/role-mappings/realm"
	var roles []map[string]any
	if e := adminJSON(ctx, admin, "GET", path, nil, 200, &roles); e != nil {
		return e
	}
	for _, role := range roles {
		if role["name"] == ssoPendingRole {
			return adminJSON(ctx, admin, "DELETE", path, []any{role}, http.StatusNoContent, nil)
		}
	}
	return nil
}
