package app

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// adminProviders serves Keycloak's brokered identity providers and the idp_link
// required action. Like Keycloak, it never returns a client secret and keeps the
// stored one when an update carries the mask. p.mu is held by admin().
func (p *testIdentity) adminProviders(w http.ResponseWriter, r *http.Request, path string) {
	if path == "/authentication/required-actions/idp_link" {
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
		return
	}
	alias := strings.TrimPrefix(strings.TrimPrefix(path, "/identity-provider/instances"), "/")
	if name, ok := strings.CutSuffix(alias, "/mappers"); ok && r.Method == "GET" {
		mappers, _ := p.providers[name]["mappers"].([]any)
		reply(w, 200, append([]any{}, mappers...))
		return
	}
	var incoming map[string]any
	if r.Method == "POST" || r.Method == "PUT" {
		if json.NewDecoder(r.Body).Decode(&incoming) != nil {
			w.WriteHeader(400)
			return
		}
	}
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
	owner, p, db, ctx := f.owner, f.identity, f.admin, context.Background()
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

	w = owner("PUT", "/api/settings/sso/google", google(nil))
	requireHTTP(t, w, 200)
	if strings.Contains(w.Body.String(), "synthetic-secret") {
		t.Fatal("the save echoed the client secret")
	}
	stored := p.provider("google")
	config := ssoConfig(stored)
	if stored["providerId"] != "google" || stored["trustEmail"] != true || stored["firstBrokerLoginFlowAlias"] != ssoBrokerLoginFlow || stored["linkOnly"] != false ||
		config["hostedDomain"] != "example.test" || config["clientSecret"] != "google-synthetic-secret" || config["clientId"] != "synthetic.apps.googleusercontent.com" {
		t.Fatalf("unexpected Google representation: %v", stored)
	}
	p.mu.Lock()
	linking := p.idpLink
	p.mu.Unlock()
	if linking {
		t.Fatal("self-service account linking was left on")
	}
	// Saving again without a secret keeps the stored one; changing the client does not.
	requireHTTP(t, owner("PUT", "/api/settings/sso/google", google(map[string]any{"client_secret": "", "enabled": false})), 200)
	if config := ssoConfig(p.provider("google")); config["clientSecret"] != "google-synthetic-secret" || p.provider("google")["enabled"] != false {
		t.Fatalf("masked save did not keep the secret: %v", config)
	}
	requireHTTP(t, owner("PUT", "/api/settings/sso/google", google(map[string]any{"client_secret": "", "client_id": "other.apps.googleusercontent.com"})), 400)

	requireHTTP(t, owner("PUT", "/api/settings/sso/microsoft", microsoft(nil)), 200)
	stored = p.provider("microsoft")
	config = ssoConfig(stored)
	tenant := microsoftLogin + "0000000b-0000-0000-0000-00000000000b"
	if stored["providerId"] != "oidc" || stored["trustEmail"] != false || config["issuer"] != tenant+"/v2.0" || config["tokenUrl"] != tenant+"/oauth2/v2.0/token" ||
		config["jwksUrl"] != tenant+"/discovery/v2.0/keys" || config["validateSignature"] != "true" || config["clientId"] != "0000000a-0000-0000-0000-00000000000a" {
		t.Fatalf("unexpected Microsoft representation: %v", stored)
	}
	view = read(t)
	if g, m := view.Providers["google"], view.Providers["microsoft"]; !g.Configured || g.Enabled || g.HostedDomain != "example.test" || !m.Configured || !m.Enabled || m.TenantID != "0000000b-0000-0000-0000-00000000000b" {
		t.Fatalf("unexpected configured view: %+v", view)
	}
	var audits int
	if e := db.QueryRow(ctx, `SELECT count(*) FROM audit WHERE action='sso.update' AND target IN ('google','microsoft')`).Scan(&audits); e != nil || audits != 3 {
		t.Fatal("sso.update not audited once per save", audits, e)
	}

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
	if view = read(t); view.Providers["google"].Configured || view.Providers["microsoft"].Configured {
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
		w = owner("PUT", "/api/settings/sso/google", google(nil))
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
