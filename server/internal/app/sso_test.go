package app

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// adminProviders serves Keycloak's brokered identity providers and the idp_link
// required action. Like Keycloak, it never returns a client secret and keeps the
// stored one when an update carries the mask. p.mu is held by admin().
func (p *testIdentity) adminProviders(w http.ResponseWriter, r *http.Request, path string) {
	if path == "/authentication/required-actions/idp_link" {
		p.adminIDPLink(w, r)
		return
	}
	alias := strings.TrimPrefix(strings.TrimPrefix(path, "/identity-provider/instances"), "/")
	if name, ok := strings.CutSuffix(alias, "/mappers"); ok && r.Method == "GET" {
		p.adminProviderMappers(w, name)
		return
	}
	incoming, ok := decodeProviderRequest(w, r)
	if !ok {
		return
	}
	p.adminProvider(w, r, alias, incoming)
}

func (p *testIdentity) adminIDPLink(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		reply(w, 200, map[string]any{"alias": "idp_link", "name": "Linking Identity Provider", "enabled": p.idpLink})
	case "PUT":
		var action struct {
			Enabled bool `json:"enabled"`
		}
		if json.NewDecoder(r.Body).Decode(&action) != nil {
			w.WriteHeader(400)
			return
		}
		p.idpLink = action.Enabled
		w.WriteHeader(204)
	default:
		http.NotFound(w, r)
	}
}

func (p *testIdentity) adminProviderMappers(w http.ResponseWriter, name string) {
	mappers, _ := p.providers[name]["mappers"].([]any)
	reply(w, 200, append([]any{}, mappers...))
}

func decodeProviderRequest(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	if r.Method != "POST" && r.Method != "PUT" {
		return nil, true
	}
	var incoming map[string]any
	if json.NewDecoder(r.Body).Decode(&incoming) != nil {
		w.WriteHeader(400)
		return nil, false
	}
	return incoming, true
}

func (p *testIdentity) adminProvider(w http.ResponseWriter, r *http.Request, alias string, incoming map[string]any) {
	stored, exists := p.providers[alias]
	switch {
	case alias == "" && r.Method == "POST":
		name, _ := incoming["alias"].(string)
		if _, taken := p.providers[name]; taken || name == "" {
			w.WriteHeader(409)
			return
		}
		p.providers[name] = incoming
		w.WriteHeader(201)
	case !exists:
		w.WriteHeader(404)
	case r.Method == "GET":
		raw, _ := json.Marshal(stored)
		var masked map[string]any
		_ = json.Unmarshal(raw, &masked)
		ssoConfig(masked)["clientSecret"] = secretMask
		reply(w, 200, masked)
	case r.Method == "PUT":
		if ssoConfig(incoming)["clientSecret"] == secretMask {
			ssoConfig(incoming)["clientSecret"] = ssoConfig(stored)["clientSecret"]
		}
		p.providers[alias] = incoming
		w.WriteHeader(204)
	case r.Method == "DELETE":
		delete(p.providers, alias)
		w.WriteHeader(204)
	default:
		http.NotFound(w, r)
	}
}

func (p *testIdentity) provider(alias string) map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.providers[alias]
}

type ssoSettingsView struct {
	Editable  bool               `json:"editable"`
	Providers map[string]ssoView `json:"providers"`
}

func (f *identityScenarioFixture) testSSOSettings(t *testing.T) {
	owner := f.owner
	read := func(t *testing.T) ssoSettingsView {
		t.Helper()
		w := owner("GET", "/api/settings/sso", nil)
		requireHTTP(t, w, 200)
		var view ssoSettingsView
		if e := json.Unmarshal(w.Body.Bytes(), &view); e != nil {
			t.Fatal(e)
		}
		if strings.Contains(w.Body.String(), "synthetic-secret") || strings.Contains(w.Body.String(), secretMask) {
			t.Fatal("the settings view carries a client secret", w.Body.String())
		}
		return view
	}
	google := func(overrides map[string]any) map[string]any {
		body := map[string]any{"enabled": true, "client_id": "synthetic.apps.googleusercontent.com", "client_secret": "google-synthetic-secret", "hosted_domain": " Example.TEST "}
		for k, v := range overrides {
			body[k] = v
		}
		return body
	}
	microsoft := func(overrides map[string]any) map[string]any {
		body := map[string]any{"enabled": true, "client_id": "0000000A-0000-0000-0000-00000000000A", "client_secret": "microsoft-synthetic-secret", "tenant_id": "0000000b-0000-0000-0000-00000000000b"}
		for k, v := range overrides {
			body[k] = v
		}
		return body
	}

	view := read(t)
	if !view.Editable || view.Providers["google"].Configured || view.Providers["microsoft"].Configured || view.Providers["google"].RedirectURI != f.a.publicIssuer()+"/broker/google/endpoint" {
		t.Fatalf("unexpected initial view: %+v", view)
	}
	if f.adminRoleCookie != nil {
		requireHTTP(t, f.call("GET", "/api/settings/sso", nil, f.adminRoleCookie, f.adminRoleCSRF), 403)
		requireHTTP(t, f.call("PUT", "/api/settings/sso/google", google(nil), f.adminRoleCookie, f.adminRoleCSRF), 403)
		requireHTTP(t, f.call("DELETE", "/api/settings/sso/google", nil, f.adminRoleCookie, f.adminRoleCSRF), 403)
	}
	// A provider decides who signs in to every organization: a recent second factor first.
	f.checkSSOInvalidSettings(t, google, microsoft)

	f.checkSSOGoogleSettings(t, google)

	f.checkSSOMicrosoftSettings(t, google, microsoft, read)

	f.checkSSORevocation(t, google, read)
}

func (f *identityScenarioFixture) checkSSOInvalidSettings(t *testing.T, google, microsoft func(map[string]any) map[string]any) {
	owner, p, db, ctx := f.owner, f.identity, f.admin, context.Background()
	w := owner("PUT", "/api/settings/sso/google", google(nil))
	requireHTTP(t, w, 403)
	if !strings.Contains(w.Body.String(), "fresh_mfa_required") || p.provider("google") != nil {
		t.Fatal("a save without a fresh second factor was not refused cleanly", w.Body.String())
	}
	if tag, e := db.Exec(ctx, `UPDATE sessions SET mfa=true,mfa_verified_at=clock_timestamp() WHERE token_hash=$1`, hash(f.cookie.Value)); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("fresh MFA fixture missing", e)
	}
	t.Cleanup(func() {
		if _, e := db.Exec(ctx, `UPDATE sessions SET mfa=false WHERE token_hash=$1`, hash(f.cookie.Value)); e != nil {
			t.Errorf("could not restore the owner session MFA flag: %v", e)
		}
	})

	f.proveSSOTestDomains(t, google)
	f.checkSSOInvalidSubmissions(t, google, microsoft)
}

func (f *identityScenarioFixture) proveSSOTestDomains(t *testing.T, google func(map[string]any) map[string]any) {
	owner, p, db, ctx := f.owner, f.identity, f.admin, context.Background()
	if Edition == "commercial" {
		// In Enterprise a provider answers only for a domain its organization proved.
		w := owner("PUT", "/api/settings/sso/google", google(nil))
		requireHTTP(t, w, 409)
		if !strings.Contains(w.Body.String(), "domain_not_verified") || p.provider("google") != nil {
			t.Fatal("an unproven domain was accepted", w.Body.String())
		}
		for _, domain := range []string{"example.test", "contoso.test"} {
			if e := tenantExec(ctx, db, f.org, `INSERT INTO sso_domains(organization_id,domain,challenge,verified_at) VALUES($1,$2,$3,now())`, f.org, domain, strings.Repeat("c", 43)); e != nil {
				t.Fatal(e)
			}
		}
		t.Cleanup(func() {
			if e := tenantExec(ctx, db, f.org, `DELETE FROM sso_domains WHERE organization_id=$1`, f.org); e != nil {
				t.Errorf("proven domains not removed: %v", e)
			}
		})
	}
}

func (f *identityScenarioFixture) checkSSOInvalidSubmissions(t *testing.T, google, microsoft func(map[string]any) map[string]any) {
	owner, p := f.owner, f.identity
	for _, provider := range []string{"github", "Google", "google%2F..", "..%2Fgoogle"} {
		requireHTTP(t, owner("PUT", "/api/settings/sso/"+provider, google(nil)), 404)
	}
	for _, body := range []map[string]any{
		google(map[string]any{"hosted_domain": ""}), google(map[string]any{"hosted_domain": "localhost"}),
		google(map[string]any{"hosted_domain": "https://example.test"}), google(map[string]any{"hosted_domain": "example.test,other.test"}),
		google(map[string]any{"client_id": "a b"}), google(map[string]any{"client_id": ""}),
		google(map[string]any{"client_secret": "line\nbreak"}), google(map[string]any{"client_secret": strings.Repeat("s", 513)}),
		// Keycloak reads these as "keep the stored secret" and as a vault reference.
		google(map[string]any{"client_secret": secretMask}), google(map[string]any{"client_secret": "${vault.other}"}),
		// A save without a secret needs a stored one for the same client.
		google(map[string]any{"client_secret": ""}),
	} {
		requireHTTP(t, owner("PUT", "/api/settings/sso/google", body), 400)
	}
	for _, body := range []map[string]any{
		microsoft(map[string]any{"tenant_id": "common"}), microsoft(map[string]any{"tenant_id": "organizations"}),
		microsoft(map[string]any{"tenant_id": "consumers"}), microsoft(map[string]any{"tenant_id": "0000000b-0000-0000-0000-00000000000b/../x"}),
		microsoft(map[string]any{"tenant_id": ""}), microsoft(map[string]any{"client_id": "synthetic.apps.googleusercontent.com"}),
	} {
		requireHTTP(t, owner("PUT", "/api/settings/sso/microsoft", body), 400)
	}
	if p.provider("google") != nil || p.provider("microsoft") != nil || !p.idpLink {
		t.Fatal("a refused submission reached the identity provider")
	}
}

func (f *identityScenarioFixture) checkSSOGoogleSettings(t *testing.T, google func(map[string]any) map[string]any) {
	owner, p := f.owner, f.identity
	w := owner("PUT", "/api/settings/sso/google", google(nil))
	requireHTTP(t, w, 200)
	if strings.Contains(w.Body.String(), "synthetic-secret") {
		t.Fatal("the save echoed the client secret")
	}
	stored := p.provider("google")
	config := ssoConfig(stored)
	if stored["providerId"] != "google" || stored["trustEmail"] != true || stored["firstBrokerLoginFlowAlias"] != ssoFirstLoginFlow || stored["linkOnly"] != false ||
		config["hostedDomain"] != "example.test" || config["clientSecret"] != "google-synthetic-secret" || config["clientId"] != "synthetic.apps.googleusercontent.com" {
		t.Fatalf("unexpected Google representation: %v", stored)
	}
	p.mu.Lock()
	linking, role, flow := p.idpLink, p.roles[ssoPendingRole], len(p.flows[ssoFirstLoginFlow])
	negated := 0
	for _, c := range p.configs {
		if c["condUserRole"] == ssoPendingRole && c["negate"] == "true" {
			negated++
		}
	}
	p.mu.Unlock()
	if linking {
		t.Fatal("self-service account linking was left on")
	}
	// The first-login flow skips the proof only for the invitation role, negated.
	if !role || flow != 1 || negated != 1 {
		t.Fatalf("first-login flow not built: role=%v top=%d negated=%d", role, flow, negated)
	}
	// Saving again without a secret keeps the stored one; changing the client does not.
	requireHTTP(t, owner("PUT", "/api/settings/sso/google", google(map[string]any{"client_secret": "", "enabled": false})), 200)
	if config := ssoConfig(p.provider("google")); config["clientSecret"] != "google-synthetic-secret" || p.provider("google")["enabled"] != false {
		t.Fatalf("masked save did not keep the secret: %v", config)
	}
	requireHTTP(t, owner("PUT", "/api/settings/sso/google", google(map[string]any{"client_secret": "", "client_id": "other.apps.googleusercontent.com"})), 400)
}

func (f *identityScenarioFixture) checkSSOMicrosoftSettings(t *testing.T, google, microsoft func(map[string]any) map[string]any, read func(*testing.T) ssoSettingsView) {
	owner, p, db, ctx := f.owner, f.identity, f.admin, context.Background()
	requireHTTP(t, owner("PUT", "/api/settings/sso/microsoft", microsoft(map[string]any{"invitation_domain": "https://contoso.test"})), 400)
	requireHTTP(t, owner("PUT", "/api/settings/sso/microsoft", microsoft(map[string]any{"invitation_domain": " Contoso.TEST "})), 200)
	stored := p.provider("microsoft")
	config := ssoConfig(stored)
	if stored["firstBrokerLoginFlowAlias"] != ssoFirstLoginFlow || config[ssoInvitationDomain] != "contoso.test" {
		t.Fatalf("unexpected Microsoft invitation settings: %v", stored)
	}
	tenant := microsoftLogin + "0000000b-0000-0000-0000-00000000000b"
	if stored["providerId"] != "oidc" || stored["trustEmail"] != false || config["issuer"] != tenant+"/v2.0" || config["tokenUrl"] != tenant+"/oauth2/v2.0/token" ||
		config["jwksUrl"] != tenant+"/discovery/v2.0/keys" || config["validateSignature"] != "true" || config["clientId"] != "0000000a-0000-0000-0000-00000000000a" {
		t.Fatalf("unexpected Microsoft representation: %v", stored)
	}
	view := read(t)
	if g, m := view.Providers["google"], view.Providers["microsoft"]; !g.Configured || g.Enabled || g.HostedDomain != "example.test" || !m.Configured || !m.Enabled || m.TenantID != "0000000b-0000-0000-0000-00000000000b" || m.InvitationDomain != "contoso.test" {
		t.Fatalf("unexpected configured view: %+v", view)
	}
	f.testSSOInvitations(t, google)
	var audits int
	if e := db.QueryRow(ctx, `SELECT count(*) FROM audit WHERE action='sso.update' AND target IN ('google','microsoft')`).Scan(&audits); e != nil || audits != 4 {
		t.Fatal("sso.update not audited once per save", audits, e)
	}
}

func (f *identityScenarioFixture) checkSSORevocation(t *testing.T, google func(map[string]any) map[string]any, read func(*testing.T) ssoSettingsView) {
	owner, p, db, ctx := f.owner, f.identity, f.admin, context.Background()
	if tag, e := db.Exec(ctx, `UPDATE sessions SET mfa_verified_at=clock_timestamp()-interval '6 minutes' WHERE token_hash=$1`, hash(f.cookie.Value)); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("stale MFA fixture missing", e)
	}
	requireHTTP(t, owner("DELETE", "/api/settings/sso/google", nil), 403)
	if _, e := db.Exec(ctx, `UPDATE sessions SET mfa_verified_at=clock_timestamp() WHERE token_hash=$1`, hash(f.cookie.Value)); e != nil {
		t.Fatal(e)
	}
	requireHTTP(t, owner("DELETE", "/api/settings/sso/google", nil), 200)
	requireHTTP(t, owner("DELETE", "/api/settings/sso/microsoft", nil), 200)
	if p.provider("google") != nil || p.provider("microsoft") != nil {
		t.Fatal("providers were not removed")
	}
	if view := read(t); view.Providers["google"].Configured || view.Providers["microsoft"].Configured {
		t.Fatalf("providers still reported after removal: %+v", view)
	}

	// A provider written outside the console under the same alias is not taken over:
	// its type, post-login flow or mappers would outlive the save.
	for _, foreign := range []map[string]any{
		{"alias": "google", "providerId": "oidc", "config": map[string]any{"clientId": "synthetic.apps.googleusercontent.com"}},
		{"alias": "google", "providerId": "google", "postBrokerLoginFlowAlias": "synthetic-flow", "config": map[string]any{"clientId": "synthetic.apps.googleusercontent.com"}},
		{"alias": "google", "providerId": "google", "mappers": []any{map[string]any{"identityProviderMapper": "oidc-hardcoded-role-idp-mapper"}}, "config": map[string]any{"clientId": "synthetic.apps.googleusercontent.com"}},
	} {
		p.mu.Lock()
		p.providers["google"] = foreign
		p.mu.Unlock()
		w := owner("PUT", "/api/settings/sso/google", google(nil))
		requireHTTP(t, w, 409)
		if stored := p.provider("google"); ssoConfig(stored)["clientSecret"] != nil || stored["firstBrokerLoginFlowAlias"] != nil {
			t.Fatal("a foreign provider was modified", stored)
		}
		requireHTTP(t, owner("DELETE", "/api/settings/sso/google", nil), 200)
	}
}

// The fresh-MFA window starts at the identity provider's auth_time, never when the
// callback is processed: an old authentication completed now stays old.
func TestLoginVerifiedAtUsesAuthTime(t *testing.T) {
	old := time.Now().Add(-time.Hour).Unix()
	if v := loginVerifiedAt(true, old); v == nil || v.Unix() != old {
		t.Fatal("verification time is not the token auth_time", v)
	}
	if loginVerifiedAt(false, old) != nil || loginVerifiedAt(true, 0) != nil || loginVerifiedAt(true, time.Now().Add(time.Hour).Unix()) != nil {
		t.Fatal("a login without MFA, without auth_time or from the future got a verification time")
	}
}

// testSSOInvitations: with both providers offered, an invitation to their domain signs
// in directly (role granted, no password to choose); any other address keeps the
// password invitation; the role goes at the first sign-in; a tampered flow is refused.
func (f *identityScenarioFixture) testSSOInvitations(t *testing.T, google func(map[string]any) map[string]any) {
	owner, p := f.owner, f.identity
	requireHTTP(t, owner("PUT", "/api/settings/sso/google", google(map[string]any{"client_secret": ""})), 200)
	p.mu.Lock()
	p.mailsSucceed = true
	p.mu.Unlock()
	t.Cleanup(func() { p.mu.Lock(); p.mailsSucceed = false; p.mu.Unlock() })
	invite := func(email string) (string, []string, bool) {
		return f.inviteSSOUser(t, email)
	}
	for _, email := range []string{"direct@Example.test", "someone@contoso.test"} {
		if _, actions, pending := invite(email); !pending || strings.Join(actions, ",") != "VERIFY_EMAIL" {
			t.Fatalf("%s: direct sign-in invitation expected, got actions=%v pending=%v", email, actions, pending)
		}
	}
	id, actions, pending := invite("outsider@elsewhere.test")
	if pending || strings.Join(actions, ",") != "VERIFY_EMAIL,UPDATE_PASSWORD" {
		t.Fatalf("an outside address got a direct sign-in: actions=%v pending=%v", actions, pending)
	}
	direct, _, _ := invite("second@example.test")
	admin, e := f.a.identityAdmin(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if e = clearPendingInvitation(context.Background(), admin, direct); e != nil {
		t.Fatal(e)
	}
	if e = clearPendingInvitation(context.Background(), admin, id); e != nil {
		t.Fatal("clearing an account without the role failed", e)
	}
	p.mu.Lock()
	cleared := !p.userRoles[direct][ssoPendingRole]
	var condition string
	for key, c := range p.configs {
		if c["condUserRole"] == ssoPendingRole {
			condition = key
			c["negate"] = "false"
		}
	}
	p.mu.Unlock()
	if !cleared {
		t.Fatal("the first sign-in did not clear the invitation role")
	}
	// A flow changed in Keycloak would link any existing account: it is refused.
	w := owner("PUT", "/api/settings/sso/google", google(map[string]any{"client_secret": ""}))
	requireHTTP(t, w, 409)
	if !strings.Contains(w.Body.String(), "sso_flow_foreign") {
		t.Fatal("tampered flow not reported", w.Body.String())
	}
	p.mu.Lock()
	p.configs[condition]["negate"] = "true"
	p.mu.Unlock()
}

func (f *identityScenarioFixture) inviteSSOUser(t *testing.T, email string) (string, []string, bool) {
	t.Helper()
	requireHTTP(t, f.owner("POST", "/api/members/invitations", map[string]string{"email": email, "role": "viewer"}), 201)
	p := f.identity
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, u := range p.users {
		if strings.EqualFold(u.Email, email) {
			return id, p.mailActions, p.userRoles[id][ssoPendingRole]
		}
	}
	t.Fatal("invited account not created", email)
	return "", nil, false
}

// fakeExecution is one entry of a fake authentication flow; a subflow names its own.
type fakeExecution struct {
	ID, Provider, Subflow, Requirement, Config string
}

// adminFlows serves realm roles and authentication flows the way Keycloak's admin API
// does, including the depth-first flattened execution listing. p.mu is held by admin().
func (p *testIdentity) adminFlows(w http.ResponseWriter, r *http.Request, path string) {
	switch {
	case path == "/authentication/required-actions" && r.Method == "GET":
		reply(w, 200, []map[string]any{{"alias": "idp_link", "enabled": p.idpLink, "defaultAction": false}})
	case path == "/roles" && r.Method == "POST":
		var role struct{ Name string }
		_ = json.NewDecoder(r.Body).Decode(&role)
		p.roles[role.Name] = true
		w.WriteHeader(201)
	case strings.HasPrefix(path, "/roles/") && r.Method == "GET":
		if name := strings.TrimPrefix(path, "/roles/"); p.roles[name] {
			reply(w, 200, map[string]any{"id": "role-" + name, "name": name})
			return
		}
		w.WriteHeader(404)
	case path == "/authentication/flows" && r.Method == "POST":
		var flow struct{ Alias string }
		_ = json.NewDecoder(r.Body).Decode(&flow)
		p.flows[flow.Alias] = []*fakeExecution{}
		w.WriteHeader(201)
	case strings.HasPrefix(path, "/authentication/config/") && r.Method == "GET":
		reply(w, 200, map[string]any{"config": p.configs[strings.TrimPrefix(path, "/authentication/config/")]})
	case strings.HasPrefix(path, "/authentication/executions/") && strings.HasSuffix(path, "/config") && r.Method == "POST":
		p.addFlowConfig(r, path)
		w.WriteHeader(201)
	case strings.HasPrefix(path, "/authentication/flows/"):
		p.flowExecutions(w, r, path)
	default:
		http.NotFound(w, r)
	}
}

func (p *testIdentity) addFlowConfig(r *http.Request, path string) {
	id := strings.TrimSuffix(strings.TrimPrefix(path, "/authentication/executions/"), "/config")
	var config struct{ Config map[string]string }
	_ = json.NewDecoder(r.Body).Decode(&config)
	p.configs["config-"+id] = config.Config
	for _, list := range p.flows {
		for _, x := range list {
			if x.ID == id {
				x.Config = "config-" + id
			}
		}
	}
}

func (p *testIdentity) flowExecutionList(alias string) []map[string]any {
	out := []map[string]any{}
	var walk func(string, int)
	walk = func(flow string, level int) {
		for _, x := range p.flows[flow] {
			entry := map[string]any{"id": x.ID, "level": level, "requirement": x.Requirement}
			if x.Subflow != "" {
				entry["authenticationFlow"], entry["displayName"] = true, x.Subflow
			} else {
				entry["providerId"] = x.Provider
			}
			if x.Config != "" {
				entry["authenticationConfig"] = x.Config
			}
			out = append(out, entry)
			if x.Subflow != "" {
				walk(x.Subflow, level+1)
			}
		}
	}
	walk(alias, 0)
	return out
}

func (p *testIdentity) updateFlowExecution(r *http.Request, list []*fakeExecution) {
	var update struct{ ID, Requirement string }
	_ = json.NewDecoder(r.Body).Decode(&update)
	for _, x := range list {
		if x.ID == update.ID {
			x.Requirement = update.Requirement
		}
	}
}

func (p *testIdentity) createFlowExecution(r *http.Request, alias, action string, list []*fakeExecution) {
	var added struct{ Alias, Provider string }
	_ = json.NewDecoder(r.Body).Decode(&added)
	count := 0
	for _, l := range p.flows {
		count += len(l)
	}
	x := &fakeExecution{ID: "execution-" + strconv.Itoa(count), Requirement: "DISABLED"}
	if action == "/flow" {
		x.Subflow = added.Alias
		p.flows[added.Alias] = []*fakeExecution{}
	} else {
		x.Provider = added.Provider
	}
	p.flows[alias] = append(list, x)
}

func (p *testIdentity) flowExecutions(w http.ResponseWriter, r *http.Request, path string) {
	rest := strings.TrimPrefix(path, "/authentication/flows/")
	alias, action, _ := strings.Cut(rest, "/executions")
	list, ok := p.flows[alias]
	if !ok {
		w.WriteHeader(404)
		return
	}
	switch {
	case action == "" && r.Method == "GET":
		reply(w, 200, p.flowExecutionList(alias))
	case action == "" && r.Method == "PUT":
		p.updateFlowExecution(r, list)
		w.WriteHeader(204)
	case (action == "/flow" || action == "/execution") && r.Method == "POST":
		p.createFlowExecution(r, alias, action, list)
		w.WriteHeader(201)
	default:
		http.NotFound(w, r)
	}
}

func (p *testIdentity) roleMappings(w http.ResponseWriter, r *http.Request, user string) {
	if p.roleFail {
		w.WriteHeader(500)
		return
	}
	var roles []struct{ Name string }
	if r.Method != "GET" && json.NewDecoder(r.Body).Decode(&roles) != nil {
		w.WriteHeader(400)
		return
	}
	if p.userRoles[user] == nil {
		p.userRoles[user] = map[string]bool{}
	}
	switch r.Method {
	case "GET":
		out := []map[string]any{}
		for name := range p.userRoles[user] {
			out = append(out, map[string]any{"id": "role-" + name, "name": name})
		}
		reply(w, 200, out)
	case "POST", "DELETE":
		for _, role := range roles {
			if !p.roles[role.Name] {
				w.WriteHeader(404)
				return
			}
			p.userRoles[user][role.Name] = r.Method == "POST"
			if r.Method == "DELETE" {
				delete(p.userRoles[user], role.Name)
			}
		}
		w.WriteHeader(204)
	}
}
