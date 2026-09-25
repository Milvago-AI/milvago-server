package app

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func validSetupRequest() setupRequest {
	var s setupRequest
	s.Admin.Email, s.Admin.FirstName, s.Admin.LastName, s.Admin.Password = "owner@example.test", "Alex", "Doe", "a-long-enough-passphrase"
	s.Organization.Name, s.Organization.PublicURL, s.Organization.DefaultLanguage = "Example organization", "https://milvago.example.test", "en"
	return s
}

func TestSetupRequestValidation(t *testing.T) {
	if e := func() error { s := validSetupRequest(); return s.validate() }(); e != nil {
		t.Fatal("valid request refused:", e)
	}
	for name, mutate := range map[string]func(*setupRequest){
		"display name in address": func(s *setupRequest) { s.Admin.Email = "Owner <owner@example.test>" },
		"no address":              func(s *setupRequest) { s.Admin.Email = "owner" },
		"control in name":         func(s *setupRequest) { s.Admin.FirstName = "Al\nex" },
		"empty last name":         func(s *setupRequest) { s.Admin.LastName = " " },
		"short password":          func(s *setupRequest) { s.Admin.Password = "short" },
		"password is the address": func(s *setupRequest) { s.Admin.Password = "OWNER@example.test" },
		"script URL":              func(s *setupRequest) { s.Organization.PublicURL = "javascript:alert(1)" },
		"plain HTTP remote URL":   func(s *setupRequest) { s.Organization.PublicURL = "http://milvago.example.test" },
		"URL with a path":         func(s *setupRequest) { s.Organization.PublicURL = "https://milvago.example.test/x" },
		"unknown language":        func(s *setupRequest) { s.Organization.DefaultLanguage = "de" },
		"empty organization":      func(s *setupRequest) { s.Organization.Name = "" },
		"SMTP header injection": func(s *setupRequest) {
			s.SMTP = &setupSMTP{Host: "mail.example.test", Port: 25, From: "a@example.test", FromName: "x\r\nBcc: b@example.test", Security: "none"}
		},
		"SMTP host with a path": func(s *setupRequest) {
			s.SMTP = &setupSMTP{Host: "mail.example.test/x", Port: 25, From: "a@example.test", Security: "none"}
		},
		"SMTP password without user": func(s *setupRequest) {
			s.SMTP = &setupSMTP{Host: "mail.example.test", Port: 587, From: "a@example.test", Security: "starttls", Password: "p"}
		},
		"SMTP unknown security": func(s *setupRequest) {
			s.SMTP = &setupSMTP{Host: "mail.example.test", Port: 25, From: "a@example.test", Security: "ssl3"}
		},
		"privacy out of bounds": func(s *setupRequest) { p := defaultPrivacy(); p.K = 0; s.Privacy = &p },
	} {
		t.Run(name, func(t *testing.T) {
			s := validSetupRequest()
			mutate(&s)
			if s.validate() == nil {
				t.Fatal("hostile or invalid input accepted")
			}
		})
	}
	m := setupSMTP{Host: "mail.example.test", Port: 465, From: "a@example.test", Security: "tls", Username: "u", Password: "p"}
	if k := m.keycloak(); k["ssl"] != "true" || k["starttls"] != "false" || k["auth"] != "true" || k["port"] != "465" || k["password"] != "p" {
		t.Fatalf("wrong realm SMTP mapping: %v", k)
	}
	if k := (setupSMTP{Host: "mail", Port: 25, From: "a@example.test", Security: "none"}).keycloak(); k["auth"] != "false" || k["user"] != "" || k["password"] != "" {
		t.Fatalf("credentials written without authentication: %v", k)
	}
}

func TestSetupWizard(t *testing.T) {
	runtimeURL, migrationURL := os.Getenv("TEST_DATABASE_URL"), os.Getenv("TEST_MIGRATION_DATABASE_URL")
	if runtimeURL == "" || migrationURL == "" {
		t.Skip("setup integration requires disposable milvago_test database")
	}
	for _, raw := range []string{runtimeURL, migrationURL} {
		if u, e := url.Parse(raw); e != nil || u.Path != "/milvago_test" {
			t.Fatal("setup tests require disposable database named milvago_test")
		}
	}
	ctx := context.Background()
	admin, e := pgxpool.New(ctx, migrationURL)
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
	const token = "synthetic-setup-token-of-sufficient-length"
	config := Config{DatabaseURL: runtimeURL, MigrationURL: migrationURL, RuntimeRole: "milvago_runtime", OrganizationName: "Milvago", AppURL: "http://localhost:4020", Issuer: p.server.URL, ClientID: "test-console", ClientSecret: "synthetic-secret", AdminClientID: "test-management", AdminClientSecret: "test-secret", SetupTokenHash: hash(token), SessionCipher: gcm, ContentKeys: testContentKeys(), ContentVersion: 1, SigningKey: ed25519.NewKeyFromSeed(make([]byte, 32))}
	db, e := OpenDatabase(ctx, config)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	a, e := New(ctx, config, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if e != nil {
		t.Fatal(e)
	}
	// OIDC verification needs the bare fake issuer; administration needs a realm path.
	adminIssuer := func() func() {
		a.config.Issuer = p.server.URL + "/realms/test"
		return func() { a.config.Issuer = p.server.URL }
	}
	// Every call comes from its own address, so the per-address budget only bites in
	// the subtest that aims at it; that one pins the address with fixedPeer.
	var peers atomic.Int32
	fixedPeer := ""
	call := func(method, path string, body any, cookie *http.Cookie, csrf, origin string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(method, path, bytes.NewReader(raw))
		r.RemoteAddr = fmt.Sprintf("198.51.100.%d:40000", peers.Add(1)%250+1)
		if fixedPeer != "" {
			r.RemoteAddr = fixedPeer
		}
		r.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		return w
	}
	const origin = "http://localhost:4020"
	open := func(t *testing.T) (*http.Cookie, string) {
		t.Helper()
		w := call("POST", "/api/setup/session", map[string]string{"token": token}, nil, "", origin)
		requireHTTP(t, w, 200)
		var body struct{ CSRF string }
		if json.Unmarshal(w.Body.Bytes(), &body) != nil || body.CSRF == "" {
			t.Fatal("setup session without CSRF token")
		}
		for _, c := range w.Result().Cookies() {
			if c.Name == cookieName("setup") {
				if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/api/setup" || c.MaxAge != 1800 {
					t.Fatalf("weak setup cookie: %+v", c)
				}
				return c, body.CSRF
			}
		}
		t.Fatal("setup session without cookie")
		return nil, ""
	}
	status := func(t *testing.T) (pending, ready bool) {
		t.Helper()
		w := call("GET", "/api/setup", nil, nil, "", "")
		requireHTTP(t, w, 200)
		var body struct{ Pending, Ready bool }
		if json.Unmarshal(w.Body.Bytes(), &body) != nil {
			t.Fatal("unreadable setup status")
		}
		return body.Pending, body.Ready
	}
	completion := func() setupRequest {
		s := validSetupRequest()
		s.AdminTOTP, s.RequireMFA = true, true
		s.SMTP = &setupSMTP{Host: "mail.example.test", Port: 587, From: "no-reply@example.test", FromName: "Milvago", Security: "starttls", Username: "mailer", Password: "synthetic-smtp-secret"}
		privacy := defaultPrivacy()
		privacy.K, privacy.DiscoveryEnabled = 7, true
		s.Privacy = &privacy
		return s
	}
	var org string
	if e = admin.QueryRow(ctx, `SELECT organization_id FROM app_config`).Scan(&org); e != nil {
		t.Fatal(e)
	}

	t.Run("fresh instance is pending and ready", func(t *testing.T) {
		if pending, ready := status(t); !pending || !ready {
			t.Fatalf("pending=%v ready=%v", pending, ready)
		}
	})
	t.Run("an identity without e-mail cannot bootstrap an unset instance", func(t *testing.T) {
		w := call("GET", "/auth/login", nil, nil, "", "")
		requireHTTP(t, w, 302)
		location, _ := url.Parse(w.Header().Get("Location"))
		p.nonce, p.challenge = location.Query().Get("nonce"), location.Query().Get("code_challenge")
		p.email, p.subject = "", "no-address"
		requireHTTP(t, call("GET", "/auth/callback?code=test-code&state="+url.QueryEscape(location.Query().Get("state")), nil, w.Result().Cookies()[0], "", ""), 403)
		var consumed bool
		if e := admin.QueryRow(ctx, `SELECT bootstrap_consumed FROM app_config`).Scan(&consumed); e != nil || consumed {
			t.Fatal("empty e-mail consumed the bootstrap")
		}
	})
	t.Run("setup token is required and compared exactly", func(t *testing.T) {
		requireHTTP(t, call("POST", "/api/setup/session", map[string]string{"token": token + "x"}, nil, "", origin), 403)
		requireHTTP(t, call("POST", "/api/setup/session", map[string]string{"token": ""}, nil, "", origin), 403)
		requireHTTP(t, call("POST", "/api/setup/session", map[string]string{"token": token}, nil, "", "https://attacker.example.test"), 403)
		requireHTTP(t, call("POST", "/api/setup/session", map[string]string{"token": token}, nil, "", ""), 403)
		saved := a.config.SetupTokenHash
		a.config.SetupTokenHash = nil
		requireHTTP(t, call("POST", "/api/setup/session", map[string]string{"token": token}, nil, "", origin), 503)
		if _, ready := status(t); ready {
			t.Fatal("ready without a setup token")
		}
		a.config.SetupTokenHash = saved
	})
	t.Run("guessing the token is throttled per address", func(t *testing.T) {
		fixedPeer = "203.0.113.9:40000"
		defer func() { fixedPeer = "" }()
		last := 0
		for i := 0; i < 11; i++ {
			last = call("POST", "/api/setup/session", map[string]string{"token": "guess"}, nil, "", origin).Code
		}
		if last != 429 {
			t.Fatalf("eleventh guess from one address answered %d", last)
		}
	})
	t.Run("a read-only demonstration never opens setup", func(t *testing.T) {
		a.config.DemoReadOnly = true
		defer func() { a.config.DemoReadOnly = false }()
		requireHTTP(t, call("POST", "/api/setup/session", map[string]string{"token": token}, nil, "", origin), 403)
		if _, ready := status(t); ready {
			t.Fatal("ready on a read-only instance")
		}
	})
	t.Run("mutations need the session, its own CSRF token and the origin", func(t *testing.T) {
		cookie, csrf := open(t)
		_, other := open(t)
		body := completion()
		requireHTTP(t, call("POST", "/api/setup/complete", body, nil, csrf, origin), 401)
		requireHTTP(t, call("POST", "/api/setup/complete", body, cookie, "", origin), 401)
		requireHTTP(t, call("POST", "/api/setup/complete", body, cookie, other, origin), 401)
		requireHTTP(t, call("POST", "/api/setup/complete", body, cookie, csrf, "https://attacker.example.test"), 403)
		requireHTTP(t, call("POST", "/api/setup/complete", body, &http.Cookie{Name: cookieName("setup"), Value: "forged"}, csrf, origin), 401)
		if _, e := admin.Exec(ctx, `UPDATE setup_sessions SET expires_at=now()-interval '1 second'`); e != nil {
			t.Fatal(e)
		}
		requireHTTP(t, call("POST", "/api/setup/complete", body, cookie, csrf, origin), 401)
	})
	t.Run("an existing identity is never taken over", func(t *testing.T) {
		defer adminIssuer()()
		cookie, csrf := open(t)
		body := completion()
		body.Admin.Email = "invitee@example.test"
		requireHTTP(t, call("POST", "/api/setup/complete", body, cookie, csrf, origin), 409)
		if pending, _ := status(t); !pending {
			t.Fatal("a refused completion closed setup")
		}
	})
	t.Run("the identity provider's password policy is reported", func(t *testing.T) {
		defer adminIssuer()()
		cookie, csrf := open(t)
		body := completion()
		body.Admin.Password = "thirteen-char"
		w := call("POST", "/api/setup/complete", body, cookie, csrf, origin)
		requireHTTP(t, w, 400)
		if !strings.Contains(w.Body.String(), "password_rejected") || strings.Contains(w.Body.String(), "thirteen-char") {
			t.Fatalf("unexpected refusal: %s", w.Body.String())
		}
	})
	t.Run("a failure after the account exists removes it", func(t *testing.T) {
		defer adminIssuer()()
		setTenant(t, admin, org)
		if _, e := admin.Exec(ctx, `DELETE FROM settings WHERE organization_id=$1`, org); e != nil {
			t.Fatal(e)
		}
		cookie, csrf := open(t)
		requireHTTP(t, call("POST", "/api/setup/complete", completion(), cookie, csrf, origin), 500)
		p.mu.Lock()
		for _, u := range p.users {
			if u.Email == "owner@example.test" {
				t.Error("compensation left the created account behind")
			}
		}
		p.mu.Unlock()
		if tag, e := admin.Exec(ctx, `INSERT INTO settings(organization_id) VALUES($1)`, org); e != nil || tag.RowsAffected() != 1 {
			t.Fatal("could not restore settings", e)
		}
		if pending, _ := status(t); !pending {
			t.Fatal("a failed completion closed setup")
		}
	})
	t.Run("concurrent completions leave one owner account", func(t *testing.T) {
		defer adminIssuer()()
		cookie, csrf := open(t)
		codes := make([]int, 2)
		var wg sync.WaitGroup
		for i := range codes {
			wg.Add(1)
			go func() {
				defer wg.Done()
				body := completion()
				if i == 1 {
					body.Admin.Email = "second@example.test"
				}
				codes[i] = call("POST", "/api/setup/complete", body, cookie, csrf, origin).Code
			}()
		}
		wg.Wait()
		slices.Sort(codes)
		// The loser finds its session consumed (401) or setup closed (404).
		if codes[0] != 200 || (codes[1] != 401 && codes[1] != 404) {
			t.Fatalf("concurrent completions answered %v", codes)
		}
		p.mu.Lock()
		created := 0
		for _, u := range p.users {
			if u.Email == "owner@example.test" || u.Email == "second@example.test" {
				created++
			}
		}
		p.mu.Unlock()
		if created != 1 {
			t.Fatalf("%d administrator accounts created", created)
		}
	})
	t.Run("completion applies every chosen value", func(t *testing.T) {
		var email, publicURL, language, name string
		var confirmed, requireMFA bool
		if e := admin.QueryRow(ctx, `SELECT bootstrap_email,public_url,public_url_confirmed,default_language FROM app_config`).Scan(&email, &publicURL, &confirmed, &language); e != nil {
			t.Fatal(e)
		}
		setTenant(t, admin, org)
		if e := admin.QueryRow(ctx, `SELECT o.name,s.require_mfa FROM organizations o JOIN settings s ON s.organization_id=o.id`).Scan(&name, &requireMFA); e != nil {
			t.Fatal(e)
		}
		if !slices.Contains([]string{"owner@example.test", "second@example.test"}, email) || publicURL != "https://milvago.example.test" || !confirmed || language != "en" || name != "Example organization" || !requireMFA {
			t.Fatalf("values not applied: %s %s %v %s %s %v", email, publicURL, confirmed, language, name, requireMFA)
		}
		var privacy []byte
		if e := admin.QueryRow(ctx, `SELECT configuration FROM privacy_settings WHERE organization_id=$1`, org).Scan(&privacy); e != nil || !bytes.Contains(privacy, []byte(`"k_anonymity": 7`)) {
			t.Fatalf("privacy defaults not applied: %s %v", privacy, e)
		}
		var sessions, audits int
		if e := admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM setup_sessions),(SELECT count(*) FROM audit WHERE action='setup.completed' AND actor='setup')`).Scan(&sessions, &audits); e != nil || sessions != 0 || audits != 1 {
			t.Fatalf("sessions=%d audits=%d %v", sessions, audits, e)
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.smtp["host"] != "mail.example.test" || p.smtp["starttls"] != "true" || p.smtp["user"] != "mailer" {
			t.Fatalf("realm SMTP not written: %v", p.smtp)
		}
		for _, u := range p.users {
			if u.Email == email && (u.Password != "a-long-enough-passphrase" || !u.EmailVerified || !slices.Equal(u.RequiredActions, []string{"CONFIGURE_TOTP"}) || u.FirstName != "Alex") {
				t.Fatalf("administrator account not as chosen: %+v", *u)
			}
		}
		var leaked int
		if e := admin.QueryRow(ctx, `SELECT count(*) FROM audit WHERE details::text LIKE '%passphrase%' OR details::text LIKE '%synthetic-smtp-secret%'`).Scan(&leaked); e != nil || leaked != 0 {
			t.Fatal("secret written to the audit trail", e)
		}
	})
	t.Run("setup is closed afterwards", func(t *testing.T) {
		if pending, ready := status(t); pending || ready {
			t.Fatal("setup still open")
		}
		requireHTTP(t, call("POST", "/api/setup/session", map[string]string{"token": token}, nil, "", origin), 404)
		requireHTTP(t, call("POST", "/api/setup/complete", completion(), nil, "", origin), 404)
		requireHTTP(t, call("POST", "/api/setup/smtp-test", map[string]any{}, nil, "", origin), 404)
	})
	t.Run("the chosen account becomes the owner at its first login", func(t *testing.T) {
		var email string
		if e := admin.QueryRow(ctx, `SELECT bootstrap_email FROM app_config`).Scan(&email); e != nil {
			t.Fatal(e)
		}
		w := call("GET", "/auth/login", nil, nil, "", "")
		requireHTTP(t, w, 302)
		location, _ := url.Parse(w.Header().Get("Location"))
		p.nonce, p.challenge = location.Query().Get("nonce"), location.Query().Get("code_challenge")
		p.email, p.subject, p.acr = email, "setup-owner", "2"
		requireHTTP(t, call("GET", "/auth/callback?code=test-code&state="+url.QueryEscape(location.Query().Get("state")), nil, w.Result().Cookies()[0], "", ""), 302)
		setTenant(t, admin, org)
		var role string
		if e := admin.QueryRow(ctx, `SELECT m.role FROM memberships m JOIN users u ON u.id=m.user_id WHERE u.subject='setup-owner'`).Scan(&role); e != nil || role != "owner" {
			t.Fatal("chosen account is not the owner", role, e)
		}
	})
}
