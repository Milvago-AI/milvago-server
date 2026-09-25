package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// admin serves every "/admin/realms/test/..." request issued by the product's
// identityAdmin client, against the in-memory fixtures held on testIdentity.
// It is deliberately permissive: the caller is the product code under test,
// not an adversary.
func (p *testIdentity) admin(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/admin/realms/test")
	switch {
	case strings.HasPrefix(path, "/users"):
		p.adminUsers(w, r, path)
	case path == "/client-scopes" || strings.HasPrefix(path, "/default-") || strings.HasPrefix(path, "/clients"):
		p.adminClientScopes(w, r, path)
	case strings.HasPrefix(path, "/components"):
		p.adminComponents(w, r, path)
	case path == "/testLDAPConnection" && r.Method == "POST":
		if p.ldapFail {
			reply(w, 400, map[string]string{"errorMessage": "connection refused"})
			return
		}
		w.WriteHeader(204)
	default:
		http.NotFound(w, r)
	}
}

func (p *testIdentity) adminUsers(w http.ResponseWriter, r *http.Request, path string) {
	switch {
	case path == "/users" && r.Method == "GET":
		p.listUsers(w, r)
	case path == "/users" && r.Method == "POST":
		p.createUser(w, r)
	case strings.HasSuffix(path, "/federated-identity") && r.Method == "GET":
		p.federatedIdentity(w, strings.TrimSuffix(strings.TrimPrefix(path, "/users/"), "/federated-identity"))
	case strings.HasSuffix(path, "/credentials") && r.Method == "GET":
		p.credentials(w, strings.TrimSuffix(strings.TrimPrefix(path, "/users/"), "/credentials"))
	case strings.HasSuffix(path, "/execute-actions-email") && r.Method == "PUT":
		p.mails++
		reply(w, 500, map[string]string{"error": "smtp_unavailable"})
	case strings.HasPrefix(path, "/users/") && r.Method == "GET":
		p.getUser(w, strings.TrimPrefix(path, "/users/"))
	case strings.HasPrefix(path, "/users/") && r.Method == "DELETE":
		p.deleteUser(w, strings.TrimPrefix(path, "/users/"))
	default:
		http.NotFound(w, r)
	}
}

func (p *testIdentity) deleteUser(w http.ResponseWriter, id string) {
	if _, ok := p.users[id]; !ok {
		w.WriteHeader(404)
		return
	}
	delete(p.users, id)
	w.WriteHeader(204)
}

func (p *testIdentity) adminClientScopes(w http.ResponseWriter, r *http.Request, path string) {
	switch {
	case path == "/client-scopes" && r.Method == "GET":
		reply(w, 200, []map[string]string{
			{"id": "scope-mcp", "name": "milvago:mcp"},
			{"id": "scope-content", "name": "milvago:content"},
			{"id": "scope-basic", "name": "basic"},
		})
	case strings.HasPrefix(path, "/default-default-client-scopes/") && (r.Method == "PUT" || r.Method == "DELETE"),
		strings.HasPrefix(path, "/default-optional-client-scopes/") && r.Method == "PUT":
		p.realmScopes = append(p.realmScopes, r.Method+" "+strings.TrimPrefix(path, "/"))
		w.WriteHeader(204)
	case path == "/clients" && r.Method == "GET":
		p.listClients(w, r)
	case strings.HasPrefix(path, "/clients/") && strings.Contains(path, "-client-scopes/") && (r.Method == "PUT" || r.Method == "DELETE"):
		p.moveClientScope(w, r, strings.TrimPrefix(path, "/clients/"))
	default:
		http.NotFound(w, r)
	}
}

func (p *testIdentity) adminComponents(w http.ResponseWriter, r *http.Request, path string) {
	switch {
	case path == "/components" && r.Method == "GET":
		p.listComponents(w, r)
	case path == "/components" && r.Method == "POST":
		p.createComponent(w, r)
	case strings.HasPrefix(path, "/components/") && r.Method == "GET":
		p.getComponent(w, strings.TrimPrefix(path, "/components/"))
	case strings.HasPrefix(path, "/components/") && r.Method == "PUT":
		p.putComponent(w, r, strings.TrimPrefix(path, "/components/"))
	case strings.HasPrefix(path, "/components/") && r.Method == "DELETE":
		p.deleteComponent(w, strings.TrimPrefix(path, "/components/"))
	default:
		http.NotFound(w, r)
	}
}

// The following helpers assume p.mu is already held by admin() above.

// listClients pages the fake clients by id, the way Keycloak pages by first/max.
func (p *testIdentity) listClients(w http.ResponseWriter, r *http.Request) {
	ids := make([]string, 0, len(p.clients))
	for id := range p.clients {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	// A clientId search answers the exact match, as Keycloak does with search off.
	if wanted := r.URL.Query().Get("clientId"); wanted != "" {
		out := []map[string]any{}
		for _, id := range ids {
			if c := p.clients[id]; c.ClientID == wanted {
				out = append(out, map[string]any{"id": id, "clientId": c.ClientID, "consentRequired": c.Consent, "enabled": true, "standardFlowEnabled": true, "protocolMappers": c.Mappers, "attributes": c.Attributes})
			}
		}
		reply(w, 200, out)
		return
	}
	first, _ := strconv.Atoi(r.URL.Query().Get("first"))
	maximum, _ := strconv.Atoi(r.URL.Query().Get("max"))
	out := []map[string]any{}
	for i := first; i < len(ids) && len(out) < maximum; i++ {
		c := p.clients[ids[i]]
		out = append(out, map[string]any{"id": ids[i], "clientId": c.ClientID, "defaultClientScopes": c.Default, "optionalClientScopes": c.Optional})
	}
	reply(w, 200, out)
}

// moveClientScope applies PUT/DELETE on /clients/{id}/{default|optional}-client-scopes/{scope}.
func (p *testIdentity) moveClientScope(w http.ResponseWriter, r *http.Request, rest string) {
	id, rest, _ := strings.Cut(rest, "/")
	kind, scope, _ := strings.Cut(rest, "-client-scopes/")
	names := map[string]string{"scope-mcp": "milvago:mcp", "scope-content": "milvago:content", "scope-basic": "basic"}
	c, ok := p.clients[id]
	if !ok || names[scope] == "" {
		w.WriteHeader(404)
		return
	}
	list := &c.Default
	if kind == "optional" {
		list = &c.Optional
	}
	name := names[scope]
	if r.Method == "DELETE" {
		*list = slices.DeleteFunc(*list, func(s string) bool { return s == name })
	} else if !slices.Contains(*list, name) {
		*list = append(*list, name)
	}
	w.WriteHeader(204)
}

func (p *testIdentity) listUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	out := p.matchUsers(q)
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	first, _ := strconv.Atoi(q.Get("first"))
	maximum, err := strconv.Atoi(q.Get("max"))
	if first < 0 {
		first = 0
	}
	if first > len(out) {
		first = len(out)
	}
	out = out[first:]
	if err == nil && maximum >= 0 && maximum < len(out) {
		out = out[:maximum]
	}
	reply(w, 200, out)
}
func (p *testIdentity) matchUsers(q url.Values) []identityUser {
	out := []identityUser{}
	if email := q.Get("email"); email != "" {
		for _, u := range p.users {
			if strings.EqualFold(u.Email, email) {
				out = append(out, u.representation())
			}
		}
	} else if search := strings.ToLower(q.Get("search")); search != "" {
		for _, u := range p.users {
			if strings.Contains(strings.ToLower(u.Username), search) || strings.Contains(strings.ToLower(u.Email), search) || strings.Contains(strings.ToLower(u.FirstName), search) || strings.Contains(strings.ToLower(u.LastName), search) {
				out = append(out, u.representation())
			}
		}
	}
	return out
}

func (p *testIdentity) createUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username, Email, FirstName, LastName string
		EmailVerified                        bool
		RequiredActions                      []string
		Credentials                          []struct{ Type, Value string }
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		w.WriteHeader(400)
		return
	}
	// A realm password policy of length(14), stricter than the server's own floor,
	// so a test can reach the identity provider's refusal.
	password := ""
	for _, c := range body.Credentials {
		if c.Type == "password" {
			password = c.Value
		}
	}
	if len(body.Credentials) != 0 && len(password) < 14 {
		reply(w, 400, map[string]string{"error": "invalidPasswordMinLengthMessage", "error_description": "Invalid password: minimum length 14."})
		return
	}
	for _, u := range p.users {
		if strings.EqualFold(u.Email, body.Email) {
			w.WriteHeader(409)
			return
		}
	}
	id := fmt.Sprintf("created-%d", len(p.users)+1)
	p.users[id] = &fakeUser{ID: id, Username: body.Username, Email: body.Email, FirstName: body.FirstName, LastName: body.LastName, Password: password, EmailVerified: body.EmailVerified, RequiredActions: body.RequiredActions}
	w.Header().Set("Location", p.server.URL+"/admin/realms/test/users/"+id)
	w.WriteHeader(201)
}
func (p *testIdentity) getUser(w http.ResponseWriter, id string) {
	u, ok := p.users[id]
	if !ok {
		w.WriteHeader(404)
		return
	}
	reply(w, 200, u.representation())
}
func (p *testIdentity) federatedIdentity(w http.ResponseWriter, id string) {
	u, ok := p.users[id]
	if !ok || !u.Federated {
		reply(w, 200, []any{})
		return
	}
	reply(w, 200, []map[string]string{{"identityProvider": "test-broker", "userId": u.ID, "userName": u.Username}})
}
func (p *testIdentity) credentials(w http.ResponseWriter, id string) {
	u, ok := p.users[id]
	if !ok || !u.OTP {
		reply(w, 200, []any{})
		return
	}
	reply(w, 200, []map[string]string{{"type": "otp"}})
}
func (p *testIdentity) createComponent(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		w.WriteHeader(400)
		return
	}
	// One identifier per kind. The directory tests depend on the LDAP one being
	// exactly this, and a client-registration policy must not land on top of it.
	id := "ldap-component-1"
	// The literal rather than the Enterprise constant: this fake is compiled in both
	// editions, and Community has no client-registration surface to name.
	if provider, ok := body["providerId"].(string); ok && body["providerType"] == "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy" {
		id = "policy-" + provider
	}
	body["id"] = id
	p.components[id] = body
	w.Header().Set("Location", p.server.URL+"/admin/realms/test/components/"+id)
	w.WriteHeader(201)
}

// listComponents answers the collection read, filtered by provider type the way
// Keycloak does. Without the filter the registration screen would be handed the
// directory components as well.
func (p *testIdentity) listComponents(w http.ResponseWriter, r *http.Request) {
	wanted := r.URL.Query().Get("type")
	out := []map[string]any{}
	for id, component := range p.components {
		if wanted != "" && component["providerType"] != wanted {
			continue
		}
		copied := map[string]any{}
		for k, v := range component {
			copied[k] = v
		}
		copied["id"] = id
		out = append(out, copied)
	}
	reply(w, 200, out)
}
func (p *testIdentity) getComponent(w http.ResponseWriter, id string) {
	c, ok := p.components[id]
	if !ok {
		w.WriteHeader(404)
		return
	}
	reply(w, 200, c)
}
func (p *testIdentity) putComponent(w http.ResponseWriter, r *http.Request, id string) {
	if _, ok := p.components[id]; !ok {
		w.WriteHeader(404)
		return
	}
	var body map[string]any
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		w.WriteHeader(400)
		return
	}
	body["id"] = id
	p.components[id] = body
	w.WriteHeader(204)
}
func (p *testIdentity) deleteComponent(w http.ResponseWriter, id string) {
	if _, ok := p.components[id]; !ok {
		w.WriteHeader(404)
		return
	}
	delete(p.components, id)
	w.WriteHeader(204)
}

// Test-goroutine accessors: lock independently of the request-handling
// goroutine, since the fixtures are read and seeded directly by the tests.
func (p *testIdentity) seedUser(u *fakeUser) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.users[u.ID] = u
}
func (p *testIdentity) mailCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.mails
}
func (p *testIdentity) setLDAPFail(v bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ldapFail = v
}
func (p *testIdentity) hasComponent(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.components[id]
	return ok
}
func (p *testIdentity) componentConfig(id string) map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, ok := p.components[id]
	if !ok {
		return nil
	}
	cfg, _ := c["config"].(map[string]any)
	return cfg
}

// configHas reports whether the Keycloak component config key holds value as
// its first (and, for every setting this test sends, only) entry.
func configHas(cfg map[string]any, key, value string) bool {
	arr, ok := cfg[key].([]any)
	if !ok || len(arr) == 0 {
		return false
	}
	s, ok := arr[0].(string)
	return ok && s == value
}

// testIdentitySubsystem exercises identity-type tracking (local/sso/ldap),
// self-service profile actions gated by identity type, MFA step-up during
// login, and the organization's LDAP directory (settings, import, tenant
// isolation). It runs after testShadowSubsystem, reusing the same fake
// OIDC/administration server and owner session.
func testIdentitySubsystem(t *testing.T, f subsystemFixture) {
	t.Helper()
	a, ownerCookie, ownerCSRF, p := f.a, f.cookie, f.csrf, f.identity

	call := func(method, path string, body any, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Origin", a.config.AppURL)
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		return w
	}
	owner := func(method, path string, body any) *httptest.ResponseRecorder {
		return call(method, path, body, ownerCookie, ownerCSRF)
	}
	beginLogin := func(t *testing.T, path string) (*http.Cookie, string, *url.URL) {
		t.Helper()
		w := call("GET", path, nil, nil, "")
		requireHTTP(t, w, 302)
		location, e := url.Parse(w.Header().Get("Location"))
		if e != nil {
			t.Fatal(e)
		}
		p.nonce = location.Query().Get("nonce")
		p.challenge = location.Query().Get("code_challenge")
		return w.Result().Cookies()[0], location.Query().Get("state"), location
	}
	finishLogin := func(cookie *http.Cookie, state, extra string) *httptest.ResponseRecorder {
		return call("GET", "/auth/callback?code=test-code&state="+url.QueryEscape(state)+extra, nil, cookie, "")
	}
	sessionCSRF := func(t *testing.T, cookie *http.Cookie) string {
		t.Helper()
		w := call("GET", "/api/session", nil, cookie, "")
		requireHTTP(t, w, 200)
		var out struct {
			CSRF string `json:"csrf_token"`
		}
		if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
			t.Fatal(e)
		}
		return out.CSRF
	}
	// login performs a full OIDC round trip as subject/email and returns the
	// resulting session cookie and its CSRF token. p.subject/p.email are
	// restored to their previous values immediately after the exchange.
	login := func(t *testing.T, subject, email string) (*http.Cookie, string) {
		t.Helper()
		oldSubject, oldEmail := p.subject, p.email
		p.subject, p.email = subject, email
		cookie, state, _ := beginLogin(t, "/auth/login")
		w := finishLogin(cookie, state, "")
		requireHTTP(t, w, 302)
		p.subject, p.email = oldSubject, oldEmail
		var session *http.Cookie
		for _, c := range w.Result().Cookies() {
			if c.Name == cookieName("session") {
				session = c
			}
		}
		if session == nil {
			t.Fatalf("login for %s did not set a session cookie", subject)
		}
		return session, sessionCSRF(t, session)
	}
	directoryPayload := func(overrides map[string]any) map[string]any {
		base := map[string]any{
			"name": "Synthetic directory", "vendor": "other", "connection_url": "ldap://ldap-test:389",
			"bind_dn": "cn=svc,dc=example,dc=test", "bind_credential": "synthetic-secret",
			"users_dn": "ou=people,dc=example,dc=test", "username_attribute": "uid", "rdn_attribute": "uid",
			"uuid_attribute": "entryUUID", "user_object_classes": "inetOrgPerson", "custom_filter": "",
			"search_scope": 2, "auth_type": "simple", "start_tls": true, "use_truststore": "always",
			"connection_timeout_ms": 5000, "read_timeout_ms": 10000, "pagination": true,
		}
		for k, v := range overrides {
			base[k] = v
		}
		return base
	}

	oldAdminID, oldAdminSecret, oldIssuer := a.config.AdminClientID, a.config.AdminClientSecret, a.config.Issuer
	a.config.AdminClientID, a.config.AdminClientSecret, a.config.Issuer = "test-management", "test-secret", p.server.URL+"/realms/test"
	defer func() {
		a.config.AdminClientID, a.config.AdminClientSecret, a.config.Issuer = oldAdminID, oldAdminSecret, oldIssuer
		p.subject, p.email = "test-owner", "admin@example.test"
	}()

	scenario := &identityScenarioFixture{subsystemFixture: f, call: call, owner: owner, beginLogin: beginLogin, finishLogin: finishLogin, login: login, directoryPayload: directoryPayload}

	t.Run("settings no longer expose require_mfa", scenario.testIdentitySettings)

	t.Run("invite external identities", scenario.testInviteExternalIdentities)

	t.Run("session actions and profile lock", scenario.testIdentityProfileActions)

	t.Run("uninvited stranger", scenario.testUninvitedIdentity)

	t.Run("identity administration unavailable", scenario.testIdentityAdminUnavailable)

	t.Run("ldap directory settings", scenario.testLDAPDirectorySettings)

	t.Run("directory import", scenario.testDirectoryImport)

	t.Run("organization creation requires prior mfa", scenario.testOrganizationCreationMFA)

	t.Run("organization mfa gate on login", scenario.testOrganizationLoginMFA)
}

type identityProfileView struct {
	IdentityType  string `json:"identity_type"`
	MFAConfigured *bool  `json:"mfa_configured"`
	Editable      struct {
		Profile  bool `json:"profile"`
		Email    bool `json:"email"`
		Password bool `json:"password"`
		MFA      bool `json:"mfa"`
	} `json:"editable"`
}

type identityScenarioFixture struct {
	subsystemFixture
	call             func(string, string, any, *http.Cookie, string) *httptest.ResponseRecorder
	owner            func(string, string, any) *httptest.ResponseRecorder
	beginLogin       func(*testing.T, string) (*http.Cookie, string, *url.URL)
	finishLogin      func(*http.Cookie, string, string) *httptest.ResponseRecorder
	login            func(*testing.T, string, string) (*http.Cookie, string)
	directoryPayload func(map[string]any) map[string]any
	adminRoleCookie  *http.Cookie
	adminRoleCSRF    string
}

func (f *identityScenarioFixture) testIdentitySettings(t *testing.T) {
	owner := f.owner

	w := owner("GET", "/api/settings", nil)
	requireHTTP(t, w, 200)
	var raw map[string]any
	if e := json.Unmarshal(w.Body.Bytes(), &raw); e != nil {
		t.Fatal(e)
	}
	if _, present := raw["require_mfa"]; present {
		t.Fatal("organization settings still expose require_mfa")
	}
}

func (f *identityScenarioFixture) testInviteExternalIdentities(t *testing.T) {
	owner := f.owner
	admin := f.admin
	p := f.identity
	ctx := context.Background()

	p.seedUser(&fakeUser{ID: "sso-subject", Username: "ssouser", Email: "sso@example.test", Federated: true})
	before := p.mailCount()
	w := owner("POST", "/api/members/invitations", map[string]string{"email": "sso@example.test", "role": "viewer"})
	requireHTTP(t, w, 201)
	var invited struct {
		IdentityType string `json:"identity_type"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &invited); e != nil {
		t.Fatal(e)
	}
	if invited.IdentityType != "sso" {
		t.Fatalf("expected sso identity type: %s", w.Body.String())
	}
	if p.mailCount() != before {
		t.Fatal("inviting a brokered account sent an activation e-mail")
	}
	var stored string
	if e := admin.QueryRow(ctx, `SELECT identity_type FROM users WHERE subject='sso-subject'`).Scan(&stored); e != nil || stored != "sso" {
		t.Fatal("invited sso member not stored correctly", e)
	}
	requireHTTP(t, owner("POST", "/api/members/invitations", map[string]string{"email": "sso@example.test", "role": "viewer"}), 409)

	p.seedUser(&fakeUser{ID: "ldap-foreign", Username: "ldapforeign", Email: "foreign@example.test", FederationLink: "some-other-directory"})
	w = owner("POST", "/api/members/invitations", map[string]string{"email": "foreign@example.test", "role": "viewer"})
	requireHTTP(t, w, 409)
	var mismatch struct {
		Error string `json:"error"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &mismatch); e != nil {
		t.Fatal(e)
	}
	if mismatch.Error != "directory_mismatch" {
		t.Fatalf("expected directory_mismatch: %s", w.Body.String())
	}
}

func (f *identityScenarioFixture) testIdentityProfileActions(t *testing.T) {
	ssoCookie := f.testIdentityProfileReadOnly(t)
	f.testIdentityProfileLinks(t, ssoCookie)
	f.testIdentityStepUp(t)
}

func (f *identityScenarioFixture) testIdentityProfileReadOnly(t *testing.T) *http.Cookie {
	login := f.login
	call := f.call
	ssoCookie, _ := login(t, "sso-subject", "sso@example.test")
	w := call("GET", "/api/profile", nil, ssoCookie, "")
	requireHTTP(t, w, 200)
	var profile identityProfileView
	if e := json.Unmarshal(w.Body.Bytes(), &profile); e != nil {
		t.Fatal(e)
	}
	if profile.IdentityType != "sso" {
		t.Fatalf("expected sso identity type: %s", w.Body.String())
	}
	if profile.Editable.Profile || profile.Editable.Email || profile.Editable.Password || profile.Editable.MFA {
		t.Fatalf("an sso account must not be editable locally: %s", w.Body.String())
	}
	if profile.MFAConfigured == nil || *profile.MFAConfigured {
		t.Fatalf("expected mfa_configured false, got %s", w.Body.String())
	}

	requireHTTP(t, call("GET", "/auth/login?action=update_password", nil, ssoCookie, ""), 403)

	return ssoCookie
}

func (f *identityScenarioFixture) testIdentityProfileLinks(t *testing.T, ssoCookie *http.Cookie) {
	owner := f.owner
	call := f.call
	a := f.a
	w := owner("GET", "/auth/login?action=configure_totp", nil)
	requireHTTP(t, w, 302)
	if !strings.Contains(w.Header().Get("Location"), "kc_action=CONFIGURE_TOTP") {
		t.Fatal("owner could not trigger configure_totp")
	}

	w = call("GET", "/auth/login?action=configure_totp", nil, nil, "")
	requireHTTP(t, w, 302)
	if strings.Contains(w.Header().Get("Location"), "kc_action") {
		t.Fatal("an anonymous login request must not carry a profile action")
	}

	requireHTTP(t, call("GET", "/auth/login?action=manage_mfa", nil, ssoCookie, ""), 403)
	for _, language := range []string{"fr", "en", "es", "pt-BR"} {
		w = owner("GET", "/auth/login?action=manage_mfa&lang="+language+"&redirect_uri=https://untrusted.example", nil)
		requireHTTP(t, w, 302)
		want := a.config.Issuer + "/account/account-security/signing-in?kc_locale=" + language
		if w.Header().Get("Location") != want || len(w.Result().Cookies()) != 0 {
			t.Fatal("management must open the configured account console without starting an enrollment")
		}
	}
	w = owner("GET", "/auth/login?action=manage_mfa&lang=invalid", nil)
	requireHTTP(t, w, 302)
	if w.Header().Get("Location") != a.config.Issuer+"/account/account-security/signing-in" {
		t.Fatal("unsupported account locale was forwarded")
	}
	for _, cookie := range []*http.Cookie{nil, {Name: cookieName("session"), Value: "invalid-session"}} {
		w = call("GET", "/auth/login?action=manage_mfa", nil, cookie, "")
		requireHTTP(t, w, 302)
		if strings.Contains(w.Header().Get("Location"), "/account/") || strings.Contains(w.Header().Get("Location"), "kc_action") {
			t.Fatal("management must require a valid Milvago session")
		}
	}
	t.Run("demo refuses second-factor actions", func(t *testing.T) {
		previous := a.config.DemoReadOnly
		a.config.DemoReadOnly = true
		t.Cleanup(func() { a.config.DemoReadOnly = previous })
		for _, action := range []string{"configure_totp", "manage_mfa"} {
			requireHTTP(t, owner("GET", "/auth/login?action="+action, nil), 403)
		}
	})

}

func (f *identityScenarioFixture) testIdentityStepUp(t *testing.T) {
	beginLogin := f.beginLogin
	finishLogin := f.finishLogin
	admin := f.admin
	ctx := context.Background()
	_, state, location := beginLogin(t, "/auth/login?mfa=1")
	if location.Query().Get("acr_values") != "2" || location.Query().Get("prompt") != "login" || location.Query().Get("max_age") != "0" {
		t.Fatalf("step-up login must require a fresh authentication at acr_values=2: %s", location.RawQuery)
	}
	var stepUp bool
	if e := admin.QueryRow(ctx, `SELECT step_up FROM login_attempts WHERE state_hash=$1`, hash(state)).Scan(&stepUp); e != nil || !stepUp {
		t.Fatal("step-up login attempt not recorded", e)
	}

	finalCookie, finalState, _ := beginLogin(t, "/auth/login")
	w := finishLogin(finalCookie, finalState, "&kc_action_status=success")
	requireHTTP(t, w, 302)
	if w.Header().Get("Location") != "/#profile" {
		t.Fatalf("expected return to the profile screen, got %s", w.Header().Get("Location"))
	}
}

func (f *identityScenarioFixture) testUninvitedIdentity(t *testing.T) {
	beginLogin := f.beginLogin
	finishLogin := f.finishLogin
	admin := f.admin
	p := f.identity
	ctx := context.Background()

	oldSubject, oldEmail := p.subject, p.email
	p.subject, p.email = "stranger", "stranger@example.test"
	cookie, state, _ := beginLogin(t, "/auth/login")
	requireHTTP(t, finishLogin(cookie, state, ""), 403)
	p.subject, p.email = oldSubject, oldEmail
	var count int
	if e := admin.QueryRow(ctx, `SELECT count(*) FROM users WHERE subject='stranger'`).Scan(&count); e != nil || count != 0 {
		t.Fatal("uninvited login left a users row", e)
	}
}

func (f *identityScenarioFixture) testIdentityAdminUnavailable(t *testing.T) {
	beginLogin := f.beginLogin
	finishLogin := f.finishLogin
	a := f.a
	admin := f.admin
	ctx := context.Background()

	savedID, savedSecret := a.config.AdminClientID, a.config.AdminClientSecret
	a.config.AdminClientID, a.config.AdminClientSecret = "", ""
	defer func() { a.config.AdminClientID, a.config.AdminClientSecret = savedID, savedSecret }()
	cookie, state, _ := beginLogin(t, "/auth/login")
	requireHTTP(t, finishLogin(cookie, state, ""), 302)
	var stored string
	if e := admin.QueryRow(ctx, `SELECT identity_type FROM users WHERE subject='test-owner'`).Scan(&stored); e != nil || stored != "local" {
		t.Fatal("identity type changed despite administration being unavailable", e)
	}
}

func (f *identityScenarioFixture) testLDAPDirectorySettings(t *testing.T) {
	adminMember := f.setupLDAPDirectory(t)
	f.testLDAPEnterpriseIsolation(t, adminMember)
	f.testLDAPURLAndSecret(t)
	f.testLDAPConnection(t)
	f.testLDAPFreshMFAAndDelete(t)
}

func (f *identityScenarioFixture) setupLDAPDirectory(t *testing.T) string {
	call := f.call
	owner := f.owner
	login := f.login
	directoryPayload := f.directoryPayload
	admin := f.admin
	p := f.identity
	ctx := context.Background()
	ownerCookie := f.cookie
	org := f.org
	var adminMember string
	if e := admin.QueryRow(ctx, `INSERT INTO users(subject,email,display_name,identity_type) VALUES('identity-admin-role','admin-role@example.test','Synthetic admin role','local') RETURNING id`).Scan(&adminMember); e != nil {
		t.Fatal(e)
	}
	if _, e := admin.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'admin')`, org, adminMember); e != nil {
		t.Fatal(e)
	}
	f.adminRoleCookie, f.adminRoleCSRF = login(t, "identity-admin-role", "admin-role@example.test")
	requireHTTP(t, call("PUT", "/api/settings/ldap", directoryPayload(nil), f.adminRoleCookie, f.adminRoleCSRF), 403)

	// Saving or testing the directory spends the stored bind credential, so
	// both routes require a recent second factor. The owner session gets one
	// here, and gives it back when the subtest ends so later MFA assertions
	// still start from a non-MFA session.
	if tag, e := admin.Exec(ctx, `UPDATE sessions SET mfa=true,mfa_verified_at=clock_timestamp() WHERE token_hash=$1`, hash(ownerCookie.Value)); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("fresh MFA fixture missing", e)
	}
	t.Cleanup(func() {
		if _, e := admin.Exec(ctx, `UPDATE sessions SET mfa=false WHERE token_hash=$1`, hash(ownerCookie.Value)); e != nil {
			t.Errorf("could not restore the owner session MFA flag: %v", e)
		}
	})

	w := owner("PUT", "/api/settings/ldap", directoryPayload(nil))
	requireHTTP(t, w, 200)
	var view directoryView
	if e := json.Unmarshal(w.Body.Bytes(), &view); e != nil {
		t.Fatal(e)
	}
	if !view.Configured || view.ConnectionURL != "ldap://ldap-test:389" {
		t.Fatalf("unexpected directory view: %s", w.Body.String())
	}
	cfg := p.componentConfig("ldap-component-1")
	if cfg == nil || !configHas(cfg, "editMode", "READ_ONLY") || !configHas(cfg, "trustEmail", "true") || !configHas(cfg, "importEnabled", "true") || !configHas(cfg, "bindCredential", "synthetic-secret") {
		t.Fatalf("directory component config incorrect: %v", cfg)
	}
	if _, e := admin.Exec(ctx, `SELECT bind_credential FROM ldap_directories`); e == nil {
		t.Fatal("ldap_directories table stores a bind credential column")
	}

	return adminMember
}

func (f *identityScenarioFixture) testLDAPEnterpriseIsolation(t *testing.T, adminMember string) {
	if Edition != "commercial" {
		return
	}
	otherOrg := f.createLDAPIsolationOrg(t)
	childOwner, rootOwner := f.seedLDAPChildAuthority(t, otherOrg)
	f.assertLDAPChildAuthority(t, otherOrg, childOwner, rootOwner, adminMember)
	f.removeLDAPIsolationOrg(t, otherOrg, childOwner)
}

func (f *identityScenarioFixture) createLDAPIsolationOrg(t *testing.T) string {
	a := f.a
	admin := f.admin
	ctx := context.Background()
	org := f.org
	var otherOrg string
	if e := admin.QueryRow(ctx, `INSERT INTO organizations(name,parent_id) VALUES('Identity isolation organization',$1) RETURNING id`, org).Scan(&otherOrg); e != nil {
		t.Fatal(e)
	}
	tx, e := tenantTx(ctx, a.db, otherOrg)
	if e != nil {
		t.Fatal(e)
	}
	var count int
	if e := tx.QueryRow(ctx, `SELECT count(*) FROM ldap_directories`).Scan(&count); e != nil || count != 0 {
		t.Fatal("cross-tenant directory row visible", e)
	}
	tx.Rollback(ctx)

	return otherOrg
}

func (f *identityScenarioFixture) seedLDAPChildAuthority(t *testing.T, otherOrg string) (string, string) {
	a := f.a
	admin := f.admin
	ctx := context.Background()
	org := f.org
	// A directory is instance infrastructure in Enterprise: every tenant's
	// sign-in consults every LDAP component of the shared realm. Only an owner
	// of the root organization configures one, even for a child; an owner of
	// the child alone does not, nor does a key (audit of 2026-09-24). The same
	// fixture proves that the child cannot shadow the root owner's inherited
	// access with a direct membership of its own.
	var childOwner, rootOwner string
	if e := admin.QueryRow(ctx, `INSERT INTO users(subject,email,display_name,identity_type) VALUES('identity-child-owner','child-owner@example.test','Synthetic child owner','local') RETURNING id`).Scan(&childOwner); e != nil {
		t.Fatal(e)
	}
	seedTx, e := tenantTx(ctx, a.db, otherOrg)
	if e != nil {
		t.Fatal(e)
	}
	if e = seedBuiltinRoles(ctx, seedTx, otherOrg); e != nil {
		t.Fatal(e)
	}
	if _, e = seedTx.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, otherOrg, childOwner); e != nil {
		t.Fatal(e)
	}
	if e = seedTx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if e := admin.QueryRow(ctx, `SELECT user_id FROM memberships WHERE organization_id=$1 AND role='owner' LIMIT 1`, org).Scan(&rootOwner); e != nil {
		t.Fatal(e)
	}
	return childOwner, rootOwner
}

func (f *identityScenarioFixture) assertLDAPChildAuthority(t *testing.T, otherOrg, childOwner, rootOwner, adminMember string) {
	a := f.a
	ctx := context.Background()
	childTx, e := tenantTx(ctx, a.db, otherOrg)
	if e != nil {
		t.Fatal(e)
	}
	for _, c := range []struct {
		name string
		s    *Session
		want bool
	}{
		{"child owner", &Session{UserID: childOwner, OrganizationID: otherOrg, Role: "owner"}, false},
		{"root owner in the child", &Session{UserID: rootOwner, OrganizationID: otherOrg, Role: "owner"}, true},
		{"root owner's key", &Session{UserID: rootOwner, OrganizationID: otherOrg, Role: "owner", APIKeyID: "synthetic"}, false},
	} {
		if got, e := directoryOperator(ctx, childTx, c.s); e != nil || got != c.want {
			t.Fatalf("%s: directory operator %v, want %v (%v)", c.name, got, c.want, e)
		}
	}
	childSession := &Session{UserID: childOwner, OrganizationID: otherOrg, Role: "owner"}
	if e := guardParentControl(ctx, childTx, childSession, rootOwner); e == nil || !strings.Contains(e.Error(), "parent organization") {
		t.Fatal("a child owner may shadow the root owner's inherited access", e)
	}
	if e := guardParentControl(ctx, childTx, &Session{UserID: rootOwner, OrganizationID: otherOrg, Role: "owner"}, childOwner); e != nil {
		t.Fatal("the root owner may not manage a member of the child", e)
	}
	if guardParentControl(ctx, childTx, childSession, adminMember) == nil {
		t.Fatal("a root admin reached the child through the parent yet the child owner may shadow them")
	}
	childTx.Rollback(ctx)
}

func (f *identityScenarioFixture) removeLDAPIsolationOrg(t *testing.T, otherOrg, childOwner string) {
	admin := f.admin
	ctx := context.Background()

	if _, e := admin.Exec(ctx, `DELETE FROM memberships WHERE user_id=$1`, childOwner); e != nil {
		t.Fatal(e)
	}
	if _, e := admin.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, otherOrg); e != nil {
		t.Fatal(e)
	}
}

func (f *identityScenarioFixture) testLDAPURLAndSecret(t *testing.T) {
	owner := f.owner
	directoryPayload := f.directoryPayload
	p := f.identity
	var view directoryView
	requireHTTP(t, owner("PUT", "/api/settings/ldap", directoryPayload(map[string]any{"bind_credential": ""})), 200)
	cfg := p.componentConfig("ldap-component-1")
	if !configHas(cfg, "bindCredential", secretMask) {
		t.Fatalf("empty bind credential did not reuse the stored secret: %v", cfg)
	}

	for _, u := range []string{"ldap://h/x", "http://h", "ldap://u@h", "ldap://h:99999", "ldap://h:0", "ldap://h;x", "ldap://h_x", "ldap://h?x", "ldap://h#f", "ldap://-h", "ldap://h..x"} {
		requireHTTP(t, owner("PUT", "/api/settings/ldap", directoryPayload(map[string]any{"connection_url": u})), 400)
	}
	requireHTTP(t, owner("PUT", "/api/settings/ldap", directoryPayload(map[string]any{"connection_url": "ldaps://h", "start_tls": true})), 400)
	requireHTTP(t, owner("PUT", "/api/settings/ldap", directoryPayload(map[string]any{"start_tls": false})), 400)
	requireHTTP(t, owner("POST", "/api/settings/ldap/test", directoryPayload(map[string]any{"start_tls": false})), 400)
	requireHTTP(t, owner("PUT", "/api/settings/ldap", directoryPayload(map[string]any{"use_truststore": "never"})), 400)
	// Scheme case and a trailing slash are normalized; IP literals are accepted.
	for raw, canonical := range map[string]string{"LDAP://Ldap-Test:389/": "ldap://Ldap-Test:389", "ldap://[::1]:636": "ldap://[::1]:636", "ldaps://[::1]": "ldaps://[::1]", "ldap://10.0.0.1": "ldap://10.0.0.1"} {
		w := owner("PUT", "/api/settings/ldap", directoryPayload(map[string]any{"connection_url": raw, "start_tls": !strings.HasPrefix(raw, "ldaps:")}))
		requireHTTP(t, w, 200)
		if e := json.Unmarshal(w.Body.Bytes(), &view); e != nil || view.ConnectionURL != canonical {
			t.Fatalf("connection URL %q not stored canonically: %s", raw, w.Body.String())
		}
	}
	// Back to the reference server, password supplied: a URL change is always
	// allowed together with a fresh credential.
	requireHTTP(t, owner("PUT", "/api/settings/ldap", directoryPayload(nil)), 200)
	// Without it, the stored secret may only ever be reused against the very
	// server it was saved for — never spent on a new host, on either route.
	requireHTTP(t, owner("PUT", "/api/settings/ldap", directoryPayload(map[string]any{"connection_url": "ldap://ldap-other:389", "bind_credential": ""})), 400)
	requireHTTP(t, owner("POST", "/api/settings/ldap/test", directoryPayload(map[string]any{"connection_url": "ldap://ldap-other:389", "bind_credential": ""})), 400)
	// URL unchanged, credential empty: the stored secret is reused as before.
	requireHTTP(t, owner("PUT", "/api/settings/ldap", directoryPayload(map[string]any{"bind_credential": ""})), 200)
	requireHTTP(t, owner("POST", "/api/settings/ldap/test", directoryPayload(map[string]any{"bind_credential": ""})), 200)

}

func (f *identityScenarioFixture) testLDAPConnection(t *testing.T) {
	owner := f.owner
	directoryPayload := f.directoryPayload
	p := f.identity
	var view directoryView
	w := owner("GET", "/api/settings/ldap", nil)
	requireHTTP(t, w, 200)
	if e := json.Unmarshal(w.Body.Bytes(), &view); e != nil {
		t.Fatal(e)
	}
	if !view.Configured {
		t.Fatal("directory not reported as configured")
	}

	w = owner("POST", "/api/settings/ldap/test", directoryPayload(map[string]any{"bind_credential": ""}))
	requireHTTP(t, w, 200)
	var result struct {
		OK      bool   `json:"ok"`
		Step    string `json:"step"`
		Message string `json:"message"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	if !result.OK || result.Step != "authentication" {
		t.Fatalf("directory test should have succeeded: %s", w.Body.String())
	}
	p.setLDAPFail(true)
	w = owner("POST", "/api/settings/ldap/test", directoryPayload(map[string]any{"bind_credential": ""}))
	requireHTTP(t, w, 200)
	if e := json.Unmarshal(w.Body.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	if result.OK || result.Step != "connection" {
		t.Fatalf("directory test should have failed at connection: %s", w.Body.String())
	}
	p.setLDAPFail(false)

}

func (f *identityScenarioFixture) testLDAPFreshMFAAndDelete(t *testing.T) {
	owner := f.owner
	directoryPayload := f.directoryPayload
	admin := f.admin
	p := f.identity
	ctx := context.Background()
	ownerCookie := f.cookie
	// A second factor older than five minutes no longer spends the stored
	// credential: both routes refuse with fresh_mfa_required, and a fresh
	// factor restores them.
	if tag, e := admin.Exec(ctx, `UPDATE sessions SET mfa_verified_at=clock_timestamp()-interval '6 minutes' WHERE token_hash=$1`, hash(ownerCookie.Value)); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("stale MFA fixture missing", e)
	}
	w := owner("PUT", "/api/settings/ldap", directoryPayload(nil))
	requireHTTP(t, w, 403)
	if !strings.Contains(w.Body.String(), "fresh_mfa_required") {
		t.Fatal("stale MFA refused the save for an unrelated reason", w.Body.String())
	}
	w = owner("POST", "/api/settings/ldap/test", directoryPayload(nil))
	requireHTTP(t, w, 403)
	if !strings.Contains(w.Body.String(), "fresh_mfa_required") {
		t.Fatal("stale MFA refused the test for an unrelated reason", w.Body.String())
	}
	if tag, e := admin.Exec(ctx, `UPDATE sessions SET mfa_verified_at=clock_timestamp() WHERE token_hash=$1`, hash(ownerCookie.Value)); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("fresh MFA restore missing", e)
	}
	requireHTTP(t, owner("PUT", "/api/settings/ldap", directoryPayload(nil)), 200)

	requireHTTP(t, owner("DELETE", "/api/settings/ldap", nil), 200)
	if p.hasComponent("ldap-component-1") {
		t.Fatal("directory component was not removed")
	}
	w = owner("GET", "/api/settings/ldap", nil)
	requireHTTP(t, w, 200)
	var deleted struct {
		Configured bool `json:"configured"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &deleted); e != nil {
		t.Fatal(e)
	}
	if deleted.Configured {
		t.Fatal("directory still reported as configured after deletion")
	}
}

func (f *identityScenarioFixture) testDirectoryImport(t *testing.T) {
	f.testDirectorySearch(t)
	f.testDirectoryRejectedInputs(t)
	f.testDirectoryMemberImport(t)
}

func (f *identityScenarioFixture) testDirectorySearch(t *testing.T) {
	owner := f.owner
	directoryPayload := f.directoryPayload
	admin := f.admin
	p := f.identity
	ctx := context.Background()
	ownerCookie := f.cookie
	requireHTTP(t, owner("GET", "/api/members/directory?query=ldap", nil), 409)

	// The save route requires a recent second factor (see ldap directory
	// settings); this subtest re-creates the directory the previous one
	// deleted, with the same session-scoped fixture and restore.
	if tag, e := admin.Exec(ctx, `UPDATE sessions SET mfa=true,mfa_verified_at=clock_timestamp() WHERE token_hash=$1`, hash(ownerCookie.Value)); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("fresh MFA fixture missing", e)
	}
	t.Cleanup(func() {
		if _, e := admin.Exec(ctx, `UPDATE sessions SET mfa=false WHERE token_hash=$1`, hash(ownerCookie.Value)); e != nil {
			t.Errorf("could not restore the owner session MFA flag: %v", e)
		}
	})
	requireHTTP(t, owner("PUT", "/api/settings/ldap", directoryPayload(nil)), 200)

	p.seedUser(&fakeUser{ID: "ldap-1", Username: "ldap1", Email: "ldap1@example.test", FederationLink: "ldap-component-1"})
	p.seedUser(&fakeUser{ID: "ldap-other", Username: "ldapother", Email: "ldapother@example.test", FederationLink: "other"})

	// More than one full page of unrelated realm users precedes our match.
	for i := 0; i < 130; i++ {
		p.seedUser(&fakeUser{ID: fmt.Sprintf("search-foreign-%03d", i), Username: fmt.Sprintf("a-ldap-%03d", i), Email: fmt.Sprintf("foreign-%03d@example.test", i), FederationLink: "foreign-directory"})
	}
	w := owner("GET", "/api/members/directory?query=ldap", nil)
	requireHTTP(t, w, 200)
	var found struct {
		Items []struct {
			Subject string `json:"subject"`
		} `json:"items"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &found); e != nil {
		t.Fatal(e)
	}
	if len(found.Items) != 1 || found.Items[0].Subject != "ldap-1" {
		t.Fatalf("directory search must only list this organization's directory: %s", w.Body.String())
	}

}

func (f *identityScenarioFixture) testDirectoryRejectedInputs(t *testing.T) {
	owner := f.owner
	requireHTTP(t, owner("GET", "/api/members/directory?query=a", nil), 400)
	// LDAP filter metacharacters never reach Keycloak's search; wildcards alone are empty.
	for _, q := range []string{"*", "**", "a)(cn=*", "(uid=x)", `a\2a`, "a\x00b", "  x  "} {
		requireHTTP(t, owner("GET", "/api/members/directory?query="+url.QueryEscape(q), nil), 400)
	}
	// A subject can never change the admin API path (dot segments, slashes, escapes).
	for _, s := range []string{"..", ".", "../clients", "..%2fclients", "%2e%2e", "", "a/b", "-x"} {
		requireHTTP(t, owner("POST", "/api/members/directory", map[string]string{"subject": s, "role": "viewer"}), 400)
	}

}

func (f *identityScenarioFixture) testDirectoryMemberImport(t *testing.T) {
	call := f.call
	owner := f.owner
	login := f.login
	a := f.a
	admin := f.admin
	ctx := context.Background()
	requireHTTP(t, owner("POST", "/api/members/directory", map[string]string{"subject": "ldap-other", "role": "viewer"}), 403)
	requireHTTP(t, call("POST", "/api/members/directory", map[string]string{"subject": "ldap-1", "role": "owner"}, f.adminRoleCookie, f.adminRoleCSRF), 403)

	w := owner("POST", "/api/members/directory", map[string]string{"subject": "ldap-1", "role": "viewer"})
	requireHTTP(t, w, 201)
	var identityType string
	if e := admin.QueryRow(ctx, `SELECT identity_type FROM users WHERE subject='ldap-1'`).Scan(&identityType); e != nil || identityType != "ldap" {
		t.Fatal("imported member was not stored as ldap", e)
	}
	var audits int
	if e := admin.QueryRow(ctx, `SELECT count(*) FROM audit WHERE action='member.import'`).Scan(&audits); e != nil || audits == 0 {
		t.Fatal("directory import left no audit trail", e)
	}
	requireHTTP(t, owner("POST", "/api/members/directory", map[string]string{"subject": "ldap-1", "role": "viewer"}), 409)

	ldapCookie, _ := login(t, "ldap-1", "ldap1@example.test")
	w = call("GET", "/api/profile", nil, ldapCookie, "")
	requireHTTP(t, w, 200)
	var profile identityProfileView
	if e := json.Unmarshal(w.Body.Bytes(), &profile); e != nil {
		t.Fatal(e)
	}
	if profile.IdentityType != "ldap" || profile.Editable.Profile || profile.Editable.Email || profile.Editable.Password || !profile.Editable.MFA {
		t.Fatalf("ldap profile editability incorrect: %s", w.Body.String())
	}
	requireHTTP(t, call("GET", "/auth/login?action=update_profile", nil, ldapCookie, ""), 403)
	w = call("GET", "/auth/login?action=configure_totp", nil, ldapCookie, "")
	requireHTTP(t, w, 302)
	if !strings.Contains(w.Header().Get("Location"), "kc_action=CONFIGURE_TOTP") {
		t.Fatal("ldap account could not trigger its own MFA enrollment")
	}
	w = call("GET", "/auth/login?action=manage_mfa", nil, ldapCookie, "")
	requireHTTP(t, w, 302)
	if w.Header().Get("Location") != a.config.Issuer+"/account/account-security/signing-in" {
		t.Fatal("ldap account could not manage its own MFA credentials")
	}
}

func (f *identityScenarioFixture) testOrganizationCreationMFA(t *testing.T) {
	owner := f.owner
	admin := f.admin
	ctx := context.Background()
	ownerCookie := f.cookie
	org := f.org

	if Edition == "community" {
		return
	}
	requireHTTP(t, owner("POST", "/api/organizations", map[string]any{"name": "Synthetic MFA organization", "require_mfa": true}), 409)
	if _, e := admin.Exec(ctx, `UPDATE sessions SET mfa=true WHERE token_hash=$1`, hash(ownerCookie.Value)); e != nil {
		t.Fatal(e)
	}
	w := owner("POST", "/api/organizations", map[string]any{"name": "Synthetic MFA organization", "require_mfa": true})
	requireHTTP(t, w, 201)
	var created Organization
	if e := json.Unmarshal(w.Body.Bytes(), &created); e != nil {
		t.Fatal(e)
	}
	// Give the account back its single organization when this subtest ends.
	// Leaving the affiliation behind means a fresh login picks whichever of the
	// two organizations has the lower UUID (auth.go: ORDER BY id LIMIT 1), and
	// those identifiers are random -- so every later subtest that logs in became
	// a coin toss, which is what made the mfa gate below fail about one run in
	// six. The organization itself stays: it is referenced by append-only audit
	// rows, and deleting it is refused for exactly the right reason.
	t.Cleanup(func() {
		if _, e := admin.Exec(ctx, `SELECT set_config('milvago.organization_id',$1,false)`, created.ID); e != nil {
			t.Errorf("could not reach the organization this subtest created: %v", e)
			return
		}
		if _, e := admin.Exec(ctx, `DELETE FROM memberships WHERE organization_id=$1`, created.ID); e != nil {
			t.Errorf("could not drop the affiliation this subtest created: %v", e)
		}
		if _, e := admin.Exec(ctx, `SELECT set_config('milvago.organization_id',$1,false)`, org); e != nil {
			t.Errorf("could not restore the tenant context: %v", e)
		}
	})
	// settings is FORCE RLS: the admin connection only sees the organization
	// named by its own session-level org context, so point it at the new
	// organization for this read. The restore is registered before the read, not
	// written after it: a failing assertion in between used to leave the context
	// on the wrong organization, and the next subtest's UPDATE then matched no
	// rows and reported success.
	setTenant(t, admin, created.ID)
	var requireMFA bool
	if e := admin.QueryRow(ctx, `SELECT require_mfa FROM settings WHERE organization_id=$1`, created.ID).Scan(&requireMFA); e != nil || !requireMFA {
		t.Fatal("new organization did not persist require_mfa", e)
	}
	if _, e := admin.Exec(ctx, `UPDATE sessions SET mfa=false WHERE token_hash=$1`, hash(ownerCookie.Value)); e != nil {
		t.Fatal(e)
	}
}

func (f *identityScenarioFixture) testOrganizationLoginMFA(t *testing.T) {
	gated := f.requireLandingOrgMFA(t)
	f.testLocalMFAGate(t, gated)
	ssoCookie := f.testLinkedMFAGate(t)
	f.testMFADowngrade(t, ssoCookie)
}

func (f *identityScenarioFixture) requireLandingOrgMFA(t *testing.T) string {
	admin := f.admin
	ctx := context.Background()
	user := f.user
	// settings is FORCE RLS, so this write only reaches a row when the admin
	// connection already points at this organization. Inheriting that context
	// from whatever ran before made the subtest pass or fail with the order:
	// the UPDATE simply matched nothing and reported success, and the login
	// then went through without the step-up this asserts. Set it here, and
	// check that a row was actually written rather than trusting the absence
	// of an error.
	// A fresh login lands in the topmost organization the account can reach, then
	// alphabetically, and earlier subtests leave this account affiliated to more
	// than one. Requiring MFA on `org` and asserting the gate was a coin toss --
	// about one run in three landed elsewhere. Resolve the same organization the
	// login will choose, and require it there.
	//
	// The ordering below is auth.go's, copied deliberately: when the landing rule
	// moved from the smallest identifier to the hierarchy (2026-09-17), this query
	// kept the old one and the subtest went back to failing intermittently, for a
	// reason that has nothing to do with the gate it tests.
	//
	// Note the resolution goes through user_organizations, not a count over
	// memberships: that table is under FORCE row level security, so a direct
	// count from this connection only ever sees the current tenant and would
	// report one affiliation however many exist.
	var gated string
	if e := admin.QueryRow(ctx, `SELECT u.id FROM user_organizations($1) u JOIN organizations o ON o.id=u.id ORDER BY (o.parent_id IS NOT NULL), u.name, u.id LIMIT 1`, user).Scan(&gated); e != nil {
		t.Fatal(e)
	}
	setTenant(t, admin, gated)
	result, e := admin.Exec(ctx, `UPDATE settings SET require_mfa=true WHERE organization_id=$1`, gated)
	if e != nil {
		t.Fatal(e)
	}
	if result.RowsAffected() != 1 {
		t.Fatalf("the mfa requirement reached %d rows, not the organization's", result.RowsAffected())
	}
	t.Cleanup(func() {
		if _, e := admin.Exec(ctx, `UPDATE settings SET require_mfa=false WHERE organization_id=$1`, gated); e != nil {
			t.Errorf("could not restore require_mfa: %v", e)
		}
	})
	return gated
}

func (f *identityScenarioFixture) testLocalMFAGate(t *testing.T, gated string) {
	beginLogin := f.beginLogin
	finishLogin := f.finishLogin
	admin := f.admin
	ctx := context.Background()
	user := f.user
	cookie, state, _ := beginLogin(t, "/auth/login")
	w := finishLogin(cookie, state, "")
	requireHTTP(t, w, 302)
	if !strings.HasPrefix(w.Header().Get("Location"), "/auth/login?mfa=1") {
		// Say which organization the session actually landed in, and whether the
		// bootstrap grant was still unconsumed: those are the two things that
		// decide the branch taken here, and a bare "got /" names neither.
		// Name what the decision actually depended on: which organization the
		// gate was set on, how many the account can land in, and the account's
		// identity type, which never substitutes for verified MFA evidence.
		var affiliations int
		_ = admin.QueryRow(ctx, `SELECT count(*) FROM user_organizations($1)`, user).Scan(&affiliations)
		var kind, stored string
		_ = admin.QueryRow(ctx, `SELECT identity_type FROM users WHERE id=$1`, user).Scan(&kind)
		_ = admin.QueryRow(ctx, `SELECT require_mfa::text FROM settings WHERE organization_id=$1`, gated).Scan(&stored)
		t.Fatalf("an mfa-required organization must redirect to step-up, got %s (gate set on %s, stored require_mfa=%s, the account can land in %d organizations, identity=%s)", w.Header().Get("Location"), gated, stored, affiliations, kind)
	}

	cookie, state, _ = beginLogin(t, "/auth/login?mfa=1")
	requireHTTP(t, finishLogin(cookie, state, ""), 403)

}

func (f *identityScenarioFixture) testLinkedMFAGate(t *testing.T) *http.Cookie {
	call := f.call
	beginLogin := f.beginLogin
	finishLogin := f.finishLogin
	login := f.login
	admin := f.admin
	p := f.identity
	ctx := context.Background()
	// A linked account is not proof of MFA in the current authentication.
	var ssoOrg string
	if e := admin.QueryRow(ctx, "SELECT o.id FROM users u CROSS JOIN LATERAL user_organizations(u.id) o WHERE u.subject='sso-subject' ORDER BY o.id LIMIT 1").Scan(&ssoOrg); e != nil {
		t.Fatal(e)
	}
	setTenant(t, admin, ssoOrg)
	var previous bool
	if e := admin.QueryRow(ctx, "SELECT require_mfa FROM settings WHERE organization_id=$1", ssoOrg).Scan(&previous); e != nil {
		t.Fatal(e)
	}
	if tag, e := admin.Exec(ctx, "UPDATE settings SET require_mfa=true WHERE organization_id=$1", ssoOrg); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("missing MFA fixture", e)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(ctx, "UPDATE settings SET require_mfa=$1 WHERE organization_id=$2", previous, ssoOrg)
	})
	oldSubject, oldEmail, oldACR := p.subject, p.email, p.acr
	t.Cleanup(func() { p.subject, p.email, p.acr = oldSubject, oldEmail, oldACR })
	p.subject, p.email, p.acr = "sso-subject", "sso@example.test", ""
	cookie, state, _ := beginLogin(t, "/auth/login")
	w := finishLogin(cookie, state, "")
	requireHTTP(t, w, 302)
	if !strings.HasPrefix(w.Header().Get("Location"), "/auth/login?mfa=1") {
		t.Fatal("linked account bypassed MFA", w.Body.String())
	}
	cookie, state, _ = beginLogin(t, "/auth/login?mfa=1")
	requireHTTP(t, finishLogin(cookie, state, ""), 403)
	p.acr = "2"
	ssoCookie, _ := login(t, "sso-subject", "sso@example.test")
	requireHTTP(t, call("GET", "/api/profile", nil, ssoCookie, ""), 200)
	var storedMFA bool
	if e := admin.QueryRow(ctx, "SELECT mfa FROM sessions WHERE token_hash=$1", hash(ssoCookie.Value)).Scan(&storedMFA); e != nil || !storedMFA {
		t.Fatal("the signed ACR 2 login did not establish an MFA session", e)
	}
	return ssoCookie
}

func (f *identityScenarioFixture) testMFADowngrade(t *testing.T, ssoCookie *http.Cookie) {
	call := f.call
	admin := f.admin
	p := f.identity
	ctx := context.Background()
	var storedMFA bool
	// Refresh must replace the previous assurance with the new signed claim.
	// Never fabricate this result by writing sessions.mfa in the fixture.
	p.acr = "1"
	beforeRefresh := p.refreshes
	if tag, e := admin.Exec(ctx, "UPDATE sessions SET identity_expires_at=now()-interval '1 second' WHERE token_hash=$1", hash(ssoCookie.Value)); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("the refresh fixture did not expire exactly one linked session", e)
	}
	downgraded := call("GET", "/api/profile", nil, ssoCookie, "")
	requireHTTP(t, downgraded, 403)
	if !strings.Contains(downgraded.Body.String(), "mfa_required") {
		t.Fatal("the downgraded session was refused for an unrelated reason", downgraded.Body.String())
	}
	if p.refreshes != beforeRefresh+1 {
		t.Fatalf("expected one signed identity refresh, got %d", p.refreshes-beforeRefresh)
	}
	if e := admin.QueryRow(ctx, "SELECT mfa FROM sessions WHERE token_hash=$1", hash(ssoCookie.Value)).Scan(&storedMFA); e != nil || storedMFA {
		t.Fatal("the signed ACR 1 refresh did not persist the MFA downgrade", e)
	}
	requireHTTP(t, call("GET", "/api/profile", nil, ssoCookie, ""), 403)
	if p.refreshes != beforeRefresh+1 {
		t.Fatal("the second refusal did not reuse the persisted refreshed session")
	}
}
