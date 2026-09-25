package app

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func validateRules(rules []Rule) error {
	if rules == nil || len(rules) > 200 {
		return bad("Provide between 0 and 200 rules.")
	}
	ids := map[string]bool{}
	domains := map[string]bool{}
	for _, rule := range rules {
		if !uuidPattern.MatchString(rule.ID) || ids[rule.ID] {
			return bad("Rule IDs must be unique UUIDs.")
		}
		if len(rule.Domain) > 253 || !domainPattern.MatchString(rule.Domain) || domains[rule.Domain] {
			return bad("Domains must be unique lowercase DNS names without wildcards.")
		}
		if rule.Action != "observe" && rule.Action != "block" {
			return bad("Rule action must be observe or block.")
		}
		ids[rule.ID] = true
		domains[rule.Domain] = true
	}
	return nil
}

type testIdentity struct {
	refreshes                                  int
	server                                     *httptest.Server
	key                                        *rsa.PrivateKey
	nonce, challenge, email, subject, audience string
	expiry                                     time.Time
	verified                                   bool
	exchanges                                  int
	acr                                        string
	// Fake identity-administration state (Keycloak admin REST API), guarded by mu
	// since it is written both by the test goroutine and read by the server's
	// request-handling goroutine.
	mu         sync.Mutex
	users      map[string]*fakeUser
	mails      int
	components map[string]map[string]any
	ldapFail   bool
	// Which client scopes were pushed into the realm's own default and optional
	// lists, in order, so a test can prove what a newly created client inherits.
	realmScopes []string
	// Clients of the realm by internal id, with their default and optional scope
	// names, so a test can prove what a per-client sweep changed.
	clients map[string]*fakeClient
	// The realm's smtpServer as last written through the admin API.
	smtp map[string]string
}

type fakeClient struct {
	ClientID          string
	Default, Optional []string
	Consent           bool
	Mappers           []map[string]any
	Attributes        map[string]string
}

// fakeUser is a minimal Keycloak UserRepresentation held by the fake identity
// administration API.
type fakeUser struct {
	ID, Username, Email, FirstName, LastName, FederationLink string
	Federated, OTP, Disabled                                 bool
	Password                                                 string
	EmailVerified                                            bool
	RequiredActions                                          []string
}

func (u *fakeUser) representation() identityUser {
	// Keycloak always reports enabled on a user read, so the fake does too --
	// leaving it absent would exercise the unknown path rather than the real one.
	enabled := !u.Disabled
	return identityUser{ID: u.ID, Username: u.Username, Email: u.Email, FirstName: u.FirstName, LastName: u.LastName, FederationLink: u.FederationLink, Enabled: &enabled}
}

// setUserDisabled and removeUser let a test withdraw an account the way an
// administrator would: disabling it, or deleting it outright.
func (p *testIdentity) setUserDisabled(id string, disabled bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if u, ok := p.users[id]; ok {
		u.Disabled = disabled
	}
}
func (p *testIdentity) removeUser(id string) *fakeUser {
	p.mu.Lock()
	defer p.mu.Unlock()
	u := p.users[id]
	delete(p.users, id)
	return u
}

func identityProvider(t *testing.T) *testIdentity {
	t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	p := &testIdentity{key: key, email: "admin@example.test", subject: "test-owner", audience: "test-console", expiry: time.Now().Add(time.Hour), verified: true,
		users:      map[string]*fakeUser{"invited-subject": {ID: "invited-subject", Username: "invitee", Email: "invitee@example.test"}},
		components: map[string]map[string]any{}}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.well-known/openid-configuration":
			reply(w, 200, map[string]any{"issuer": p.server.URL, "authorization_endpoint": p.server.URL + "/authorize", "token_endpoint": p.server.URL + "/token", "end_session_endpoint": p.server.URL + "/logout", "jwks_uri": p.server.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case r.URL.Path == "/keys":
			reply(w, 200, map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
		case r.URL.Path == "/token":
			r.ParseForm()
			if r.Form.Get("grant_type") == "client_credentials" {
				reply(w, 200, map[string]string{"access_token": "test-administration-token"})
				return
			}
			challenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if r.Form.Get("grant_type") == "refresh_token" {
				if r.Form.Get("refresh_token") != "test-refresh-token" {
					reply(w, 400, map[string]string{"error": "invalid_grant"})
					return
				}
				p.refreshes++
				reply(w, 200, map[string]any{"access_token": "refreshed-access-token", "refresh_token": "test-refresh-token", "token_type": "Bearer", "expires_in": 3600, "id_token": p.token(t)})
				return
			}
			if r.Form.Get("code") != "test-code" || base64.RawURLEncoding.EncodeToString(challenge[:]) != p.challenge {
				reply(w, 400, map[string]string{"error": "invalid_grant"})
				return
			}
			p.exchanges++
			reply(w, 200, map[string]any{"access_token": "test-access-token", "refresh_token": "test-refresh-token", "token_type": "Bearer", "expires_in": 3600, "id_token": p.token(t)})
		case r.URL.Path == "/admin/realms/test" && r.Method == "PUT":
			// A partial realm update; the setup wizard only ever sends smtpServer.
			var realm struct {
				SMTPServer map[string]string `json:"smtpServer"`
			}
			if json.NewDecoder(r.Body).Decode(&realm) != nil {
				w.WriteHeader(400)
				return
			}
			p.mu.Lock()
			p.smtp = realm.SMTPServer
			p.mu.Unlock()
			w.WriteHeader(204)
		case r.URL.Path == "/admin/realms/test":
			// The realm representation itself, without a trailing slash, which is where
			// Keycloak publishes the realm's internal identifier. A component needs it
			// as its parent, so this is not decoration.
			reply(w, 200, map[string]string{"id": "realm-test", "realm": "test"})
		case strings.HasPrefix(r.URL.Path, "/admin/realms/test/"):
			p.admin(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(p.server.Close)
	return p
}
func (p *testIdentity) token(t *testing.T) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test-key"})
	claims, _ := json.Marshal(map[string]any{"iss": p.server.URL, "aud": p.audience, "sub": p.subject, "exp": p.expiry.Unix(), "iat": time.Now().Unix(), "nonce": p.nonce, "email": p.email, "email_verified": p.verified, "name": "Test account", "acr": p.acr})
	data := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(data))
	signature, e := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, digest[:])
	if e != nil {
		t.Fatal(e)
	}
	return data + "." + base64.RawURLEncoding.EncodeToString(signature)
}
func TestOIDCVerification(t *testing.T) {
	p := identityProvider(t)
	a := &App{config: Config{Issuer: p.server.URL, ClientID: "test-console", AppURL: "http://localhost"}}
	if e := a.initOIDC(context.Background()); e != nil {
		t.Fatal(e)
	}
	if _, e := a.verifier.Verify(context.Background(), p.token(t)); e != nil {
		t.Fatal(e)
	}
	p.audience = "other-client"
	if _, e := a.verifier.Verify(context.Background(), p.token(t)); e == nil {
		t.Fatal("accepted wrong audience")
	}
	p.audience = "test-console"
	p.expiry = time.Now().Add(-time.Hour)
	if _, e := a.verifier.Verify(context.Background(), p.token(t)); e == nil {
		t.Fatal("accepted expired identity token")
	}
}
func TestMetadataAndPolicyValidation(t *testing.T) {
	event := InputEvent{ID: "11111111-1111-4111-8111-111111111111", OccurredAt: time.Now(), Provider: "example.ai", Action: "observed", Source: "browser", Labels: []string{}}
	if e := validateEvent(event, time.Now()); e != nil {
		t.Fatal(e)
	}
	event.Source = "inventory"
	if validateEvent(event, time.Now()) == nil {
		t.Fatal("inventory accepted as browser event")
	}
	request := httptest.NewRequest("POST", "/", strings.NewReader(`{"events":[],"prompt":"secret"}`))
	request.Header.Set("Content-Type", "application/json")
	var body struct {
		Events []InputEvent `json:"events"`
	}
	if decode(httptest.NewRecorder(), request, &body) == nil {
		t.Fatal("prompt field accepted")
	}
	if hasPermission([]string{"overview.read"}, "members.manage") || hasPermission(nil, "overview.read") {
		t.Fatal("permissions must default deny")
	}
	rules := []Rule{{ID: "11111111-1111-4111-8111-111111111111", Domain: "example.ai", Action: "block", Enabled: true}}
	if e := validateRules(rules); e != nil {
		t.Fatal(e)
	}
	rules[0].Domain = "*.example.ai"
	if validateRules(rules) == nil {
		t.Fatal("wildcard domain accepted")
	}
}

func TestDatabaseSecurityAndHTTP(t *testing.T) {
	runtimeURL, migrationURL := os.Getenv("TEST_DATABASE_URL"), os.Getenv("TEST_MIGRATION_DATABASE_URL")
	if runtimeURL == "" || migrationURL == "" {
		t.Skip("set TEST_DATABASE_URL and TEST_MIGRATION_DATABASE_URL to disposable milvago_test database")
	}
	for _, raw := range []string{runtimeURL, migrationURL} {
		u, e := url.Parse(raw)
		if e != nil || u.Path != "/milvago_test" {
			t.Fatal("integration tests require disposable database named milvago_test")
		}
	}
	ctx := context.Background()
	adminConfig, e := pgxpool.ParseConfig(migrationURL)
	if e != nil {
		t.Fatal(e)
	}
	adminConfig.MaxConns = 1
	admin, e := pgxpool.NewWithConfig(ctx, adminConfig)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Close()
	if _, e = admin.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); e != nil {
		t.Fatal(e)
	}
	p := identityProvider(t)
	block, _ := aes.NewCipher(make([]byte, 32))
	gcm, _ := cipher.NewGCM(block)
	c := Config{DatabaseURL: runtimeURL, MigrationURL: migrationURL, RuntimeRole: "milvago_runtime", OrganizationName: "Test organization", BootstrapEmail: "admin@example.test", AppURL: "http://localhost:4020", Issuer: p.server.URL, ClientID: "test-console", ClientSecret: "test-client-secret", SessionCipher: gcm, ContentKeys: testContentKeys(), ContentVersion: 1, SigningKey: ed25519.NewKeyFromSeed(make([]byte, 32))}
	db, e := OpenDatabase(ctx, c)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	reopened, e := OpenDatabase(ctx, c)
	if e != nil {
		t.Fatalf("idempotent migration restart failed: %v", e)
	}
	reopened.Close()
	unsafeConfig := c
	unsafeConfig.DatabaseURL = migrationURL
	if unsafeDB, e := OpenDatabase(ctx, unsafeConfig); e == nil {
		unsafeDB.Close()
		t.Fatal("accepted owner as runtime role")
	}
	a, e := New(ctx, c, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if e != nil {
		t.Fatal(e)
	}
	call := func(method, path string, body any, cookie *http.Cookie, csrf, origin, bearer string) *httptest.ResponseRecorder {
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
		r.Header.Set("Origin", origin)
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		return w
	}
	beginLogin := func() (*http.Cookie, string) {
		w := call("GET", "/auth/login", nil, nil, "", "", "")
		requireHTTP(t, w, 302)
		location, e := url.Parse(w.Header().Get("Location"))
		if e != nil {
			t.Fatal(e)
		}
		p.nonce = location.Query().Get("nonce")
		p.challenge = location.Query().Get("code_challenge")
		if p.nonce == "" || p.challenge == "" || location.Query().Get("code_challenge_method") != "S256" {
			t.Fatal("nonce and PKCE required")
		}
		return w.Result().Cookies()[0], location.Query().Get("state")
	}
	callback := func(cookie *http.Cookie, state string) *httptest.ResponseRecorder {
		return call("GET", "/auth/callback?code=test-code&state="+url.QueryEscape(state), nil, cookie, "", "", "")
	}
	t.Run("unaffiliated visitor cannot bootstrap", func(t *testing.T) {
		p.email = "visitor@example.test"
		p.subject = "visitor"
		cookie, state := beginLogin()
		requireHTTP(t, callback(cookie, state), 403)
		var consumed bool
		if e := admin.QueryRow(ctx, `SELECT bootstrap_consumed FROM app_config`).Scan(&consumed); e != nil || consumed {
			t.Fatal("visitor consumed bootstrap")
		}
		var count int
		if e := admin.QueryRow(ctx, `SELECT count(*) FROM users WHERE subject='visitor'`).Scan(&count); e != nil || count != 0 {
			t.Fatal("unaffiliated visitor left a users row", e)
		}
	})
	p.email = "admin@example.test"
	p.subject = "test-owner"
	t.Run("unverified email and wrong nonce rejected", func(t *testing.T) {
		p.verified = false
		cookie, state := beginLogin()
		requireHTTP(t, callback(cookie, state), 403)
		p.verified = true
		cookie, state = beginLogin()
		p.nonce = "different-nonce"
		requireHTTP(t, callback(cookie, state), 401)
	})
	t.Run("login is browser bound and one use", func(t *testing.T) {
		cookie, state := beginLogin()
		requireHTTP(t, callback(&http.Cookie{Name: cookie.Name, Value: "wrong-browser"}, state), 400)
		requireHTTP(t, callback(cookie, state), 302)
		requireHTTP(t, callback(cookie, state), 400)
	})
	cookie, state := beginLogin()
	login := callback(cookie, state)
	requireHTTP(t, login, 302)
	var sessionCookie *http.Cookie
	for _, v := range login.Result().Cookies() {
		if v.Name == cookieName("session") {
			sessionCookie = v
		}
	}
	if sessionCookie == nil || !sessionCookie.HttpOnly || sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Fatal("session cookie flags missing")
	}
	var session struct {
		CSRF string `json:"csrf_token"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		Organization Organization `json:"organization"`
	}
	w := call("GET", "/api/session", nil, sessionCookie, "", "", "")
	requireHTTP(t, w, 200)
	if e = json.Unmarshal(w.Body.Bytes(), &session); e != nil {
		t.Fatal(e)
	}
	if _, e = admin.Exec(ctx, `SELECT set_config('milvago.organization_id',$1,false)`, session.Organization.ID); e != nil {
		t.Fatal(e)
	}
	t.Run("session tokens encrypted", func(t *testing.T) {
		var encrypted []byte
		if e := admin.QueryRow(ctx, `SELECT encrypted_tokens FROM sessions WHERE token_hash=$1`, hash(sessionCookie.Value)).Scan(&encrypted); e != nil {
			t.Fatal(e)
		}
		if bytes.Contains(encrypted, []byte("test-access-token")) {
			t.Fatal("plaintext tokens persisted")
		}
		nonce := encrypted[:gcm.NonceSize()]
		plain, e := gcm.Open(nil, nonce, encrypted[gcm.NonceSize():], hash(sessionCookie.Value))
		if e != nil || !bytes.Contains(plain, []byte("test-access-token")) {
			t.Fatal("cannot authenticate stored tokens")
		}
	})
	t.Run("refresh verifies identity and persists encrypted rotation", func(t *testing.T) {
		if _, e := admin.Exec(ctx, `UPDATE sessions SET identity_expires_at=now()-interval '1 second' WHERE token_hash=$1`, hash(sessionCookie.Value)); e != nil {
			t.Fatal(e)
		}
		before := p.refreshes
		requireHTTP(t, call("GET", "/api/session", nil, sessionCookie, "", "", ""), 200)
		requireHTTP(t, call("GET", "/api/session", nil, sessionCookie, "", "", ""), 200)
		if p.refreshes != before+1 {
			t.Fatal("refresh was not committed exactly once")
		}
		var encrypted []byte
		if e := admin.QueryRow(ctx, `SELECT encrypted_tokens FROM sessions WHERE token_hash=$1`, hash(sessionCookie.Value)).Scan(&encrypted); e != nil {
			t.Fatal(e)
		}
		if bytes.Contains(encrypted, []byte("refreshed-access-token")) {
			t.Fatal("refresh token stored plaintext")
		}
		cookie, state := beginLogin()
		w := callback(cookie, state)
		requireHTTP(t, w, 302)
		var second *http.Cookie
		for _, v := range w.Result().Cookies() {
			if v.Name == cookieName("session") {
				second = v
			}
		}
		if _, e := admin.Exec(ctx, `UPDATE sessions SET identity_expires_at=now()-interval '1 second' WHERE token_hash=$1`, hash(second.Value)); e != nil {
			t.Fatal(e)
		}
		p.subject = "different-subject"
		requireHTTP(t, call("GET", "/api/session", nil, second, "", "", ""), 401)
		p.subject = "test-owner"
		requireHTTP(t, call("GET", "/api/session", nil, second, "", "", ""), 401)
	})
	t.Run("CSRF and roles", func(t *testing.T) {
		body := map[string]string{"label": "Test device"}
		requireHTTP(t, call("POST", "/api/enrollments", body, sessionCookie, session.CSRF, "https://attacker.example", ""), 403)
		requireHTTP(t, call("POST", "/api/enrollments", body, sessionCookie, "", c.AppURL, ""), 403)
		// The body is read after the session, before the transaction and the barrier;
		// past the ceiling, the route refuses it as before.
		held := readBytes.Load()
		requireHTTP(t, call("POST", "/api/enrollments", map[string]string{"label": strings.Repeat("a", 1600<<10)}, sessionCookie, session.CSRF, c.AppURL, ""), 400)
		// Every body read ahead returns its reservation once its request ends, decoded or not.
		if leaked := readBytes.Load() - held; leaked != 0 {
			t.Fatalf("body reservations leaked: %d bytes", leaked)
		}
		// A cross-site top-level GET carries the Lax cookie; Fetch Metadata refuses it.
		for site, want := range map[string]int{"cross-site": 403, "same-site": 403, "same-origin": 200, "none": 200} {
			r := httptest.NewRequest("GET", "/api/settings", nil)
			r.AddCookie(sessionCookie)
			r.Header.Set("Sec-Fetch-Site", site)
			w := httptest.NewRecorder()
			a.Handler().ServeHTTP(w, r)
			requireHTTP(t, w, want)
		}
		if _, e := admin.Exec(ctx, `UPDATE memberships SET role='viewer' WHERE user_id=$1`, session.User.ID); e != nil {
			t.Fatal(e)
		}
		requireHTTP(t, call("POST", "/api/enrollments", body, sessionCookie, session.CSRF, c.AppURL, ""), 403)
		if _, e := admin.Exec(ctx, `UPDATE memberships SET role='owner' WHERE user_id=$1`, session.User.ID); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("the exclusive barrier is neither taken before authorization nor awaited forever", func(t *testing.T) {
		holder, e := pgx.Connect(ctx, migrationURL)
		if e != nil {
			t.Fatal(e)
		}
		defer holder.Close(ctx)
		hold := func(org string) {
			if _, e := holder.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(`+barrierKeySQL+`)`, org); e != nil {
				t.Fatal(e)
			}
		}
		if _, e := holder.Exec(ctx, `BEGIN`); e != nil {
			t.Fatal(e)
		}
		// A reader of another organization does not hold this one's barrier.
		hold("00000000-0000-4000-8000-0000000000aa")
		requireHTTP(t, call("DELETE", "/api/members/00000000-0000-4000-8000-000000000001", nil, sessionCookie, session.CSRF, c.AppURL, ""), 404)
		hold(session.Organization.ID)
		defer holder.Exec(ctx, `ROLLBACK`)
		if _, e := admin.Exec(ctx, `UPDATE memberships SET role='viewer' WHERE user_id=$1`, session.User.ID); e != nil {
			t.Fatal(e)
		}
		const nobody = "/api/members/00000000-0000-4000-8000-000000000001"
		started := time.Now()
		requireHTTP(t, call("DELETE", nobody, nil, sessionCookie, session.CSRF, c.AppURL, ""), 403)
		if waited := time.Since(started); waited > 2*time.Second {
			t.Fatalf("a caller without the permission queued on the barrier for %s", waited)
		}
		if _, e := admin.Exec(ctx, `UPDATE memberships SET role='owner' WHERE user_id=$1`, session.User.ID); e != nil {
			t.Fatal(e)
		}
		requireHTTP(t, call("DELETE", nobody, nil, sessionCookie, session.CSRF, c.AppURL, ""), 503)
	})
	t.Run("MFA and invitation failure never report success", func(t *testing.T) {
		requireHTTP(t, call("PUT", "/api/settings", map[string]any{"name": "Test organization", "event_retention_days": 30, "require_mfa": true}, sessionCookie, session.CSRF, c.AppURL, ""), 400)
		body := map[string]string{"email": "invitee@example.test", "role": "viewer"}
		requireHTTP(t, call("POST", "/api/members/invitations", body, sessionCookie, session.CSRF, c.AppURL, ""), 503)
		a.config.AdminClientID = "test-management"
		a.config.AdminClientSecret = "test-secret"
		a.config.Issuer = p.server.URL + "/realms/test"
		requireHTTP(t, call("POST", "/api/members/invitations", body, sessionCookie, session.CSRF, c.AppURL, ""), 502)
		a.config.Issuer = c.Issuer
		a.config.AdminClientID = ""
		a.config.AdminClientSecret = ""
		var count int
		if e := admin.QueryRow(ctx, `SELECT count(*) FROM users WHERE subject='invited-subject'`).Scan(&count); e != nil || count != 0 {
			t.Fatal("failed SMTP created a local member")
		}
	})
	t.Run("member permissions last owner and session invalidation", func(t *testing.T) {
		// Acting on one's own membership is refused by the self lock, which is
		// deliberately absolute and ordered before the last-owner count (see
		// mutateMember): a user never demotes or removes themselves, whether or not
		// they happen to be the last owner. These two expectations said 409 from
		// the era before that guard existed; the documented and security-reviewed
		// behaviour is 403 self_forbidden. The 409 last_owner path is still covered
		// below, through a second owner acting on the first.
		requireHTTP(t, call("PUT", "/api/members/"+session.User.ID+"/role", map[string]string{"role": "admin"}, sessionCookie, session.CSRF, c.AppURL, ""), 403)
		requireHTTP(t, call("DELETE", "/api/members/"+session.User.ID, nil, sessionCookie, session.CSRF, c.AppURL, ""), 403)
		var member string
		if e := admin.QueryRow(ctx, `INSERT INTO users(subject,email,display_name) VALUES('test-admin','team@example.test','Test administrator') RETURNING id`).Scan(&member); e != nil {
			t.Fatal(e)
		}
		if _, e := admin.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'admin')`, session.Organization.ID, member); e != nil {
			t.Fatal(e)
		}
		p.subject = "test-admin"
		p.email = "team@example.test"
		cookie, state := beginLogin()
		w := callback(cookie, state)
		requireHTTP(t, w, 302)
		var memberCookie *http.Cookie
		for _, v := range w.Result().Cookies() {
			if v.Name == cookieName("session") {
				memberCookie = v
			}
		}
		w = call("GET", "/api/session", nil, memberCookie, "", "", "")
		requireHTTP(t, w, 200)
		var memberSession struct {
			CSRF string `json:"csrf_token"`
		}
		json.Unmarshal(w.Body.Bytes(), &memberSession)
		requireHTTP(t, call("PUT", "/api/members/"+session.User.ID+"/role", map[string]string{"role": "viewer"}, memberCookie, memberSession.CSRF, c.AppURL, ""), 403)
		requireHTTP(t, call("PUT", "/api/members/"+member+"/role", map[string]string{"role": "owner"}, memberCookie, memberSession.CSRF, c.AppURL, ""), 403)
		requireHTTP(t, call("PUT", "/api/members/"+member+"/role", map[string]string{"role": "viewer"}, sessionCookie, session.CSRF, c.AppURL, ""), 200)
		requireHTTP(t, call("GET", "/api/session", nil, memberCookie, "", "", ""), 401)
		requireHTTP(t, call("DELETE", "/api/members/"+member, nil, sessionCookie, session.CSRF, c.AppURL, ""), 200)
		p.subject = "test-owner"
		p.email = "admin@example.test"
	})
	t.Run("tenant isolation and append-only audit", func(t *testing.T) {
		var unforced int
		if e := admin.QueryRow(ctx, `SELECT count(*) FROM pg_class WHERE relname IN ('memberships','settings','policies','enrollments','devices','events','audit','tool_observations','ldap_directories','api_keys') AND NOT(relrowsecurity AND relforcerowsecurity)`).Scan(&unforced); e != nil || unforced != 0 {
			t.Fatal("tenant tables require ENABLE and FORCE RLS")
		}
		if _, e := db.Exec(ctx, `SET ROLE milvago_lookup`); e == nil {
			t.Fatal("runtime can assume lookup role")
		}
		if _, e = admin.Exec(ctx, `SELECT set_config('milvago.organization_id','',false)`); e != nil {
			t.Fatal(e)
		}
		var hidden int
		if e := admin.QueryRow(ctx, `SELECT count(*) FROM memberships`).Scan(&hidden); e != nil || hidden != 0 {
			t.Fatal("table owner bypassed FORCE RLS")
		}
		if _, e = admin.Exec(ctx, `SELECT set_config('milvago.organization_id',$1,false)`, session.Organization.ID); e != nil {
			t.Fatal(e)
		}
		var other string
		if e := admin.QueryRow(ctx, `INSERT INTO organizations(name,parent_id) VALUES('Other test organization',$1) RETURNING id`, session.Organization.ID).Scan(&other); e != nil {
			t.Fatal(e)
		}
		if _, e = admin.Exec(ctx, `SELECT set_config('milvago.organization_id',$1,false)`, other); e != nil {
			t.Fatal(e)
		}
		if _, e := admin.Exec(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version) VALUES($1,$2,'Other device','test','0')`, other, hash("other-device")); e != nil {
			t.Fatal(e)
		}
		if _, e = admin.Exec(ctx, `SELECT set_config('milvago.organization_id',$1,false)`, session.Organization.ID); e != nil {
			t.Fatal(e)
		}
		var count int
		if e := db.QueryRow(ctx, `SELECT count(*) FROM devices`).Scan(&count); e != nil || count != 0 {
			t.Fatalf("unscoped runtime sees tenant data: %d %v", count, e)
		}
		tx, e := tenantTx(ctx, db, session.Organization.ID)
		if e != nil {
			t.Fatal(e)
		}
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM devices WHERE organization_id=$1`, other).Scan(&count); e != nil || count != 0 {
			t.Fatal("cross-tenant read succeeded")
		}
		tx.Rollback(ctx)
		tx, e = tenantTx(ctx, db, session.Organization.ID)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = tx.Exec(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version) VALUES($1,$2,'Injected','test','0')`, other, hash("injected")); e == nil {
			t.Fatal("cross-tenant insert succeeded")
		}
		tx.Rollback(ctx)
		tx, e = tenantTx(ctx, db, session.Organization.ID)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = tx.Exec(ctx, `DELETE FROM audit`); e == nil {
			t.Fatal("runtime audit deletion succeeded")
		}
		tx.Rollback(ctx)
		if _, e = admin.Exec(ctx, `UPDATE audit SET actor='changed'`); e == nil {
			t.Fatal("audit trigger allowed mutation")
		}
		// Remove only this test fixture. Audit never references this isolated tenant.
		if _, e = admin.Exec(ctx, `SELECT set_config('milvago.organization_id',$1,false)`, other); e != nil {
			t.Fatal(e)
		}
		if _, e = admin.Exec(ctx, `DELETE FROM devices WHERE organization_id=$1`, other); e != nil {
			t.Fatal(e)
		}
		if _, e = admin.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, other); e != nil {
			t.Fatal(e)
		}
		if _, e = admin.Exec(ctx, `SELECT set_config('milvago.organization_id',$1,false)`, session.Organization.ID); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("enrollment approval signatures ingestion revocation", func(t *testing.T) {
		w := call("POST", "/api/enrollments", map[string]string{"label": "Browser test"}, sessionCookie, session.CSRF, c.AppURL, "")
		requireHTTP(t, w, 201)
		var enrollment struct {
			Token     string `json:"token"`
			PublicKey string `json:"policy_public_key"`
		}
		json.Unmarshal(w.Body.Bytes(), &enrollment)
		body := map[string]string{"token": enrollment.Token, "hostname": "test-workstation", "platform": "test", "version": "0.1.0"}
		w = call("POST", "/v1/enroll", body, nil, "", "", "")
		requireHTTP(t, w, 201)
		var device struct {
			ID         string `json:"device_id"`
			Credential string `json:"credential"`
		}
		json.Unmarshal(w.Body.Bytes(), &device)
		requireHTTP(t, call("POST", "/v1/enroll", body, nil, "", "", ""), 401)
		requireHTTP(t, call("GET", "/v1/policy", nil, nil, "", "", device.Credential), 401)
		requireHTTP(t, call("POST", "/api/devices/"+device.ID+"/approve", nil, sessionCookie, session.CSRF, c.AppURL, ""), 200)
		w = call("GET", "/v1/policy", nil, nil, "", "", device.Credential)
		requireHTTP(t, w, 200)
		var envelope struct{ Payload, Signature string }
		json.Unmarshal(w.Body.Bytes(), &envelope)
		payload, _ := base64.StdEncoding.DecodeString(envelope.Payload)
		signature, _ := base64.StdEncoding.DecodeString(envelope.Signature)
		pin, _ := base64.StdEncoding.DecodeString(enrollment.PublicKey)
		if !ed25519.Verify(ed25519.PublicKey(pin), payload, signature) {
			t.Fatal("invalid policy signature")
		}
		if ed25519.Verify(a.policyKey("99999999-9999-4999-8999-999999999999").Public().(ed25519.PublicKey), payload, signature) {
			t.Fatal("another organization's pin accepted policy")
		}
		payload[0] ^= 1
		if ed25519.Verify(a.policyKey(session.Organization.ID).Public().(ed25519.PublicKey), payload, signature) {
			t.Fatal("tampered policy accepted")
		}
		event := InputEvent{ID: "11111111-1111-4111-8111-111111111111", OccurredAt: time.Now().UTC(), Provider: "example.ai", Action: "observed", Source: "browser", Characters: 10, Labels: []string{}}
		events := map[string]any{"events": []InputEvent{event}}
		requireHTTP(t, call("POST", "/v1/events", events, nil, "", "", device.Credential), 200)
		requireHTTP(t, call("POST", "/v1/events", events, nil, "", "", device.Credential), 200)
		var count int
		if e := admin.QueryRow(ctx, `SELECT count(*) FROM events WHERE device_id=$1`, device.ID).Scan(&count); e != nil || count != 1 {
			t.Fatal("event replay was not idempotent")
		}
		requireHTTP(t, call("GET", "/api/overview", nil, sessionCookie, "", "", ""), 200)
		requireHTTP(t, call("GET", "/api/events?limit=1", nil, sessionCookie, "", "", ""), 200)
		requireHTTP(t, call("GET", "/api/devices?group_id=invalid", nil, sessionCookie, "", "", ""), 400)
		requireHTTP(t, call("GET", "/api/devices?group_id=11111111-1111-4111-8111-111111111111&exclude_group_id=22222222-2222-4222-8222-222222222222", nil, sessionCookie, "", "", ""), 400)
		if Edition == "commercial" {
			inventory := map[string]any{"observations": []any{map[string]any{"tool": "ollama", "kind": "executable", "observed_at": time.Now().UTC()}}}
			requireHTTP(t, call("POST", "/v1/inventory", inventory, nil, "", "", device.Credential), 200)
			requireHTTP(t, call("POST", "/v1/inventory", inventory, nil, "", "", device.Credential), 200)
			if e := admin.QueryRow(ctx, `SELECT count(*) FROM tool_observations WHERE device_id=$1`, device.ID).Scan(&count); e != nil || count != 1 {
				t.Fatal("inventory snapshot is not idempotent")
			}
			if e := admin.QueryRow(ctx, `SELECT count(*) FROM events WHERE device_id=$1`, device.ID).Scan(&count); e != nil || count != 1 {
				t.Fatal("inventory produced a browser event")
			}
			requireHTTP(t, call("GET", "/api/tools", nil, sessionCookie, "", "", ""), 200)
			w = call("GET", "/api/tools?device_id="+device.ID, nil, sessionCookie, "", "", "")
			requireHTTP(t, w, 200)
			if !strings.Contains(w.Body.String(), "ollama") {
				t.Fatalf("device-scoped tools missing observation: %s", w.Body.String())
			}
			requireHTTP(t, call("GET", "/api/tools?device_id=abc", nil, sessionCookie, "", "", ""), 400)
			w = call("GET", "/api/tools?device_id=99999999-9999-4999-8999-999999999999", nil, sessionCookie, "", "", "")
			requireHTTP(t, w, 200)
			if !strings.Contains(w.Body.String(), `"items": []`) && !strings.Contains(w.Body.String(), `"items":[]`) {
				t.Fatalf("foreign device id leaked tools: %s", w.Body.String())
			}
		}
		requireHTTP(t, call("POST", "/api/devices/"+device.ID+"/revoke", nil, sessionCookie, session.CSRF, c.AppURL, ""), 200)
		requireHTTP(t, call("POST", "/v1/events", events, nil, "", "", device.Credential), 401)
		requireHTTP(t, call("GET", "/v1/policy", nil, nil, "", "", device.Credential), 401)
		if Edition == "commercial" {
			requireHTTP(t, call("POST", "/v1/inventory", map[string]any{"observations": []any{}}, nil, "", "", device.Credential), 401)
		}
		requireHTTP(t, call("POST", "/api/devices/"+device.ID+"/approve", nil, sessionCookie, session.CSRF, c.AppURL, ""), 409)
	})
	// Ordered first of the three: these helpers fail the parent test, so a failure
	// Each subsystem runs as its own subtest. They share this test's application,
	// schema and admin pool -- which is deliberate, and cheap -- but they must not
	// share its verdict: every one of these helpers ends an assertion with
	// t.Fatalf, and calling that on a parent aborts everything declared after it.
	// That is what made the suite report a different first failure on every run,
	// and what hid a real 204 in the update path behind an unrelated stale
	// expectation. Their order is now irrelevant, so none is documented.
	t.Run("api keys", func(t *testing.T) {
		testAPIKeySubsystem(t, a, admin, sessionCookie, session.CSRF, session.Organization.ID, session.User.ID, p)
	})
	// No-op in Community, where the MCP endpoint is not compiled.
	t.Run("mcp", func(t *testing.T) {
		testMCPSubsystem(t, a, admin, sessionCookie, session.CSRF, session.Organization.ID, session.User.ID, p)
	})
	t.Run("shadow", func(t *testing.T) {
		testShadowSubsystem(t, a, admin, sessionCookie, session.CSRF, session.Organization.ID, session.User.ID, p)
	})
	t.Run("identity", func(t *testing.T) {
		testIdentitySubsystem(t, a, admin, sessionCookie, session.CSRF, session.Organization.ID, session.User.ID, p)
	})
	t.Run("edition routes", func(t *testing.T) {
		if Edition == "community" {
			requireHTTP(t, call("POST", "/api/organizations", map[string]string{"name": "Forbidden"}, sessionCookie, session.CSRF, c.AppURL, ""), 404)
			requireHTTP(t, call("POST", "/v1/inventory", map[string]any{"observations": []any{}}, nil, "", "", ""), 404)
			// The MCP endpoint is an Enterprise module: the path is never
			// registered here, so it is not merely unauthorized, it does not exist.
			requireHTTP(t, call("POST", mcpPath, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "server/discover"}, nil, "", "", ""), 404)
			requireHTTP(t, call("POST", mcpPath, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, sessionCookie, session.CSRF, c.AppURL, ""), 404)
		} else {
			w := call("POST", "/api/organizations", map[string]string{"name": "Second organization"}, sessionCookie, session.CSRF, c.AppURL, "")
			requireHTTP(t, w, 201)
			var org Organization
			json.Unmarshal(w.Body.Bytes(), &org)
			var parent string
			var rootCount int
			if e := admin.QueryRow(ctx, `SELECT parent_id FROM organizations WHERE id=$1`, org.ID).Scan(&parent); e != nil || parent != session.Organization.ID {
				t.Fatal("default creation did not attach to the bootstrap root", e)
			}
			if e := admin.QueryRow(ctx, `SELECT count(*) FROM organizations WHERE is_root AND parent_id IS NULL`).Scan(&rootCount); e != nil || rootCount != 1 {
				t.Fatal("Enterprise must have one root", e)
			}
			for _, statement := range []string{
				`INSERT INTO organizations(name) VALUES('Forbidden disconnected organization')`,
				`INSERT INTO organizations(name,is_root) VALUES('Forbidden second root',true)`,
				`UPDATE organizations SET parent_id=id WHERE is_root`,
				`UPDATE organizations SET is_root=false WHERE is_root`,
				`DELETE FROM organizations WHERE is_root`,
				`INSERT INTO organizations(id,name,parent_id) VALUES('aaaaaaaa-0000-4000-8000-000000000001','Cycle A','aaaaaaaa-0000-4000-8000-000000000002'),('aaaaaaaa-0000-4000-8000-000000000002','Cycle B','aaaaaaaa-0000-4000-8000-000000000001')`,
			} {
				if _, e := admin.Exec(ctx, statement); e == nil {
					t.Fatal("invalid hierarchy mutation accepted")
				}
			}
			w = call("GET", "/api/organizations", nil, sessionCookie, "", "", "")
			requireHTTP(t, w, 200)
			var listed struct {
				Items []struct {
					ID       string  `json:"id"`
					ParentID *string `json:"parent_id"`
					IsRoot   bool    `json:"is_root"`
				}
			}
			if e := json.Unmarshal(w.Body.Bytes(), &listed); e != nil {
				t.Fatal(e)
			}
			var foundRoot, foundChild bool
			for _, item := range listed.Items {
				if item.ID == session.Organization.ID {
					foundRoot = item.IsRoot && item.ParentID == nil
				}
				if item.ID == org.ID {
					foundChild = !item.IsRoot && item.ParentID != nil && *item.ParentID == session.Organization.ID
				}
			}
			if !foundRoot || !foundChild {
				t.Fatal("organization API omitted the root/child relationship")
			}
			requireHTTP(t, call("POST", "/api/session/organization", map[string]string{"organization_id": org.ID}, sessionCookie, session.CSRF, c.AppURL, ""), 200)
			w = call("GET", "/api/devices", nil, sessionCookie, "", "", "")
			requireHTTP(t, w, 200)
			if !strings.Contains(w.Body.String(), `"items": []`) && !strings.Contains(w.Body.String(), `"items":[]`) {
				t.Fatalf("second organization leaked devices: %s", w.Body.String())
			}
			requireHTTP(t, call("POST", "/api/session/organization", map[string]string{"organization_id": "99999999-9999-4999-8999-999999999999"}, sessionCookie, session.CSRF, c.AppURL, ""), 403)
			var child string
			if e := admin.QueryRow(ctx, `INSERT INTO organizations(name,parent_id) VALUES('Unassigned child',$1) RETURNING id`, org.ID).Scan(&child); e != nil {
				t.Fatal(e)
			}
			requireHTTP(t, call("POST", "/api/session/organization", map[string]string{"organization_id": child}, sessionCookie, session.CSRF, c.AppURL, ""), 403)
			// Creating under a descendant of an organization one owns is allowed, and
			// that is the model rather than a leak: a parent membership grants its
			// role down the tree (a parent member inherits their role on the
			// descendants), and effective_access() walks
			// parent_id to the nearest ancestor membership precisely to grant it.
			// This expectation asserted 403 and was stale -- the third stale
			// expectation found in this suite, after the self-lock and the model
			// policy ones. Decision confirmed by the user on 2026-09-10.
			//
			// Note the asymmetry with the line above, which stays 403: switching the
			// session into `child` is refused while creating under it is allowed.
			// `user_organizations()` does walk descendants, so the refusal is
			// observed and not explained -- `child` is inserted raw here, with no
			// settings, policies or seeded roles, unlike an organization created
			// through the API. Do not "align" the two without establishing which
			// function is right; parent-to-child access on real Enterprise data is
			// still to be qualified.
			// Acting on `child` by its identifier answers to its MFA requirement, and an
			// organization without a settings row requires MFA (fail closed, as for a
			// switch). Real organizations always carry one; give the raw child its row.
			settingsTx, e := admin.Begin(ctx)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = settingsTx.Exec(ctx, `SELECT set_config('milvago.organization_id',$1,true)`, child); e == nil {
				_, e = settingsTx.Exec(ctx, `INSERT INTO settings(organization_id,require_mfa) VALUES($1,false)`, child)
			}
			if e == nil {
				e = settingsTx.Commit(ctx)
			}
			if e != nil {
				t.Fatal(e)
			}
			created := call("POST", "/api/organizations", map[string]string{"name": "Inherited descendant", "parent_id": child}, sessionCookie, session.CSRF, c.AppURL, "")
			requireHTTP(t, created, 201)
			var descendant Organization
			if e := json.Unmarshal(created.Body.Bytes(), &descendant); e != nil {
				t.Fatal(e)
			}
			// Prove the inheritance rather than merely tolerate the status: the new
			// organization really hangs under the unassigned child.
			if descendant.ParentID == nil || *descendant.ParentID != child {
				t.Fatalf("the created organization is not a descendant of the unassigned child: %s", created.Body.String())
			}
		}
	})
	t.Run("logout returns standard upstream flow and destroys local session", func(t *testing.T) {
		w := call("POST", "/auth/logout", nil, sessionCookie, session.CSRF, c.AppURL, "")
		requireHTTP(t, w, 200)
		var result struct {
			URL string `json:"logout_url"`
		}
		json.Unmarshal(w.Body.Bytes(), &result)
		u, e := url.Parse(result.URL)
		// The session stores the raw ID token precisely so sign-out carries
		// id_token_hint and the provider redirects instead of stopping on a "do you
		// want to log out?" page (see sessionTokens in sessions.go). client_id is
		// the fallback the handler uses only when no hint could be recovered, so
		// exactly one of the two is present. This expectation asserted the fallback
		// and predates the hint; it was masked until the earlier stale expectations
		// in this file stopped aborting the test.
		if e != nil || u.Path != "/logout" || u.Query().Get("post_logout_redirect_uri") != c.AppURL+"/" {
			t.Fatal("invalid logout URL")
		}
		if u.Query().Get("id_token_hint") == "" || u.Query().Get("client_id") != "" {
			t.Fatal("logout must carry the ID token hint rather than the client id fallback")
		}
		requireHTTP(t, call("GET", "/api/session", nil, sessionCookie, "", "", ""), 401)
	})
}
