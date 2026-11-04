package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCredentialFingerprint(t *testing.T) {
	credentials := []identityCredential{
		{ID: "synthetic-otp", Type: "otp", CreatedDate: 10},
		{ID: "synthetic-password", Type: "password", CreatedDate: 20},
	}
	original := credentialFingerprint(credentials)
	if len(original) == 0 {
		t.Fatal("configured OTP did not produce a fingerprint")
	}
	reordered := []identityCredential{credentials[1], credentials[0]}
	reordered[1].UserLabel = "Renamed device"
	if !bytes.Equal(original, credentialFingerprint(reordered)) {
		t.Fatal("order and display labels must not invalidate trust")
	}
	for _, changed := range [][]identityCredential{
		{{ID: "replacement-otp", Type: "otp", CreatedDate: 10}, credentials[1]},
		{credentials[0], {ID: "synthetic-password", Type: "password", CreatedDate: 21}},
		{credentials[0], credentials[1], {ID: "additional-otp", Type: "otp"}},
		{credentials[1]},
		{{Type: "otp"}},
		nil,
	} {
		if bytes.Equal(original, credentialFingerprint(changed)) {
			t.Fatal("changed authentication methods retained trust")
		}
	}
}

func TestTrustedDeviceCookie(t *testing.T) {
	a := &App{config: Config{AppURL: "https://console.example.test"}}
	w := httptest.NewRecorder()
	expiry := time.Now().UTC().AddDate(0, 6, 0).Truncate(time.Second)
	a.setTrustedDeviceCookie(w, "synthetic-token", expiry)
	cookie := w.Result().Cookies()[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.Domain != "" || cookie.Path != "/" || !strings.HasPrefix(cookie.Name, "__Host-") || !cookie.Expires.Equal(expiry) {
		t.Fatalf("trusted-device cookie flags or expiry missing: %s", cookie)
	}
}

func TestTrustedEnrollmentNeedsRecentMFA(t *testing.T) {
	a := &App{}
	for _, claims := range []loginClaims{
		{AuthTime: time.Now().Unix()},
		{ACR: "2"},
		{ACR: "2", AuthTime: time.Now().Add(-6 * time.Minute).Unix()},
		{ACR: "2", AuthTime: time.Now().Add(time.Minute).Unix()},
	} {
		token, _, e := a.rememberLoginDevice(context.Background(), nil, nil, "", "", verifiedLogin{claims: claims})
		if e != nil || token != "" {
			t.Fatal("missing, stale or future MFA evidence enrolled a browser", e)
		}
	}
}

func TestTrustedLoginIntegration(t *testing.T) {
	f := newSecurityFixture(t)
	f.loginOwner(t)
	ctx := context.Background()
	p := f.p
	p.mu.Lock()
	p.users["test-owner"] = &fakeUser{ID: "test-owner", Email: "admin@example.test", OTP: true}
	p.mu.Unlock()
	p.authTime = time.Now().Unix()
	p.acr = ""
	var otherUser string
	if e := f.admin.QueryRow(ctx, `INSERT INTO users(subject,email,display_name) VALUES('synthetic-other-account','other@example.test','Synthetic account') RETURNING id`).Scan(&otherUser); e != nil {
		t.Fatal(e)
	}

	request := func(path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		for _, c := range cookies {
			if c != nil {
				r.AddCookie(c)
			}
		}
		w := httptest.NewRecorder()
		f.a.Handler().ServeHTTP(w, r)
		return w
	}
	responseCookie := func(w *httptest.ResponseRecorder, kind string) *http.Cookie {
		for _, c := range w.Result().Cookies() {
			if c.Name == f.a.cookieName(kind) && c.MaxAge > 0 {
				return c
			}
		}
		return nil
	}
	follow := func(w *httptest.ResponseRecorder) (*http.Cookie, string, *url.URL) {
		t.Helper()
		requireHTTP(t, w, 302)
		u, e := url.Parse(w.Header().Get("Location"))
		if e != nil {
			t.Fatal(e)
		}
		p.nonce, p.challenge = u.Query().Get("nonce"), u.Query().Get("code_challenge")
		c := responseCookie(w, "login")
		if c == nil || u.Query().Get("state") == "" {
			t.Fatalf("expected an OIDC login, got %s", w.Header().Get("Location"))
		}
		return c, u.Query().Get("state"), u
	}
	finish := func(login *http.Cookie, state string, extra ...*http.Cookie) *httptest.ResponseRecorder {
		return request("/auth/callback?code=test-code&state="+url.QueryEscape(state), append([]*http.Cookie{login}, extra...)...)
	}
	login, state, _ := follow(request("/auth/login?trust_device=1"))
	first := finish(login, state)
	if responseCookie(first, "trusted_device") != nil || responseCookie(first, "session") != nil {
		t.Fatal("password alone enrolled a trusted browser or opened a session")
	}
	login, state, u := follow(first)
	if u.Query().Get("acr_values") != "2" {
		t.Fatal("initial enrollment did not require MFA")
	}
	preference := func(method, state, csrf, origin string, login *http.Cookie, remember bool) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]bool{"remember": remember})
		r := httptest.NewRequest(method, "/auth/login/device-trust?state="+url.QueryEscape(state), bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		r.Header.Set("X-CSRF-Token", csrf)
		if login != nil {
			r.AddCookie(login)
		}
		w := httptest.NewRecorder()
		f.a.Handler().ServeHTTP(w, r)
		return w
	}
	get := preference("GET", state, "", "", login, false)
	requireHTTP(t, get, 200)
	var choice struct {
		CSRF     string `json:"csrf_token"`
		Remember bool   `json:"remember"`
	}
	if e := json.Unmarshal(get.Body.Bytes(), &choice); e != nil || choice.CSRF == "" || choice.Remember {
		t.Fatal("OTP choice must start off, ignoring the old login query", e)
	}
	t.Run("read-only demo hides the choice without blocking OTP", func(t *testing.T) {
		f.a.config.DemoReadOnly = true
		defer func() { f.a.config.DemoReadOnly = false }()
		requireHTTP(t, preference("GET", state, "", "", login, false), 403)
	})
	for _, attack := range []struct {
		name, state, csrf, origin string
		cookie                    *http.Cookie
		status                    int
	}{
		{"no browser binding", state, choice.CSRF, f.a.browserOrigin(), nil, 401},
		{"another attempt", randomToken(), choice.CSRF, f.a.browserOrigin(), login, 401},
		{"wrong CSRF", state, "wrong", f.a.browserOrigin(), login, 403},
		{"no origin", state, choice.CSRF, "", login, 403},
		{"foreign origin", state, choice.CSRF, "https://foreign.example.test", login, 403},
	} {
		t.Run(attack.name+" cannot record trust", func(t *testing.T) {
			requireHTTP(t, preference("POST", attack.state, attack.csrf, attack.origin, attack.cookie, true), attack.status)
		})
	}
	for _, remember := range []bool{true, false, true} {
		w := preference("POST", state, choice.CSRF, f.a.browserOrigin(), login, remember)
		requireHTTP(t, w, 200)
		if responseCookie(w, "trusted_device") != nil || responseCookie(w, "session") != nil {
			t.Fatal("preference alone created trust or a session before OTP validation")
		}
		var stored bool
		if e := f.admin.QueryRow(ctx, `SELECT remember_device FROM login_attempts WHERE state_hash=$1`, hash(state)).Scan(&stored); e != nil || stored != remember {
			t.Fatal("OTP choice was not saved against its login attempt", e)
		}
	}
	p.acr = "2"
	enrolled := finish(login, state)
	requireHTTP(t, enrolled, 302)
	trusted := responseCookie(enrolled, "trusted_device")
	if trusted == nil || responseCookie(enrolled, "session") == nil {
		t.Fatalf("successful MFA did not remember the opted-in browser: %s", enrolled.Body.String())
	}
	requireHTTP(t, preference("POST", state, choice.CSRF, f.a.browserOrigin(), login, true), 401)
	t.Run("sensitive step-up cannot record trust", func(t *testing.T) {
		binding, state, _ := follow(request("/auth/login?mfa=1"))
		requireHTTP(t, preference("GET", state, "", "", binding, false), 403)
	})
	var expiry time.Time
	var tokenHash []byte
	if e := f.admin.QueryRow(ctx, `SELECT token_hash,expires_at FROM trusted_login_devices WHERE user_id=$1`, f.session.User.ID).Scan(&tokenHash, &expiry); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(tokenHash, hash(trusted.Value)) || time.Until(expiry) < 180*24*time.Hour || time.Until(expiry) > 185*24*time.Hour {
		t.Fatal("trust must store only a hash and expire six months after enrollment")
	}
	p.acr = ""

	trustedLogin := func(path string, token *http.Cookie) *httptest.ResponseRecorder {
		login, state, _ := follow(request(path))
		return finish(login, state, token)
	}
	w := trustedLogin("/auth/login", trusted)
	requireHTTP(t, w, 302)
	sessionCookie := responseCookie(w, "session")
	if sessionCookie == nil || responseCookie(w, "trusted_device") != nil {
		t.Fatal("trusted login must open a session without renewing trust")
	}
	s, e := f.a.loadSession(httptest.NewRequest("GET", "/api/session", nil), sessionCookie.Value)
	if e != nil || s.MFA || !s.LoginTrusted {
		t.Fatalf("trusted login acquired second-factor evidence: %+v, %v", s, e)
	}
	if _, e := f.admin.Exec(ctx, `UPDATE settings SET require_mfa=true WHERE organization_id=$1`, f.session.Organization.ID); e != nil {
		t.Fatal(e)
	}
	requireHTTP(t, request("/api/session", sessionCookie), 200)
	tx, e := tenantTx(ctx, f.db, s.OrganizationID)
	if e != nil {
		t.Fatal(e)
	}
	if e := f.a.requireFreshMFA(httptest.NewRequest("GET", "/", nil), tx, s); e == nil {
		t.Fatal("trusted login authorized a sensitive action")
	}
	_ = tx.Rollback(ctx)
	zip := f.call("POST", "/api/installer/windows/package", nil, sessionCookie, s.CSRF, f.a.config.AppURL, "")
	requireHTTP(t, zip, 403)
	if !strings.Contains(zip.Body.String(), "fresh_mfa_required") {
		t.Fatalf("trusted login bypassed the ZIP's MFA check: %s", zip.Body.String())
	}
	// A refresh never upgrades remembered login into actual MFA evidence.
	p.acr = "2"
	if _, e := f.admin.Exec(ctx, `UPDATE sessions SET identity_expires_at=now()-interval '1 second' WHERE token_hash=$1`, hash(sessionCookie.Value)); e != nil {
		t.Fatal(e)
	}
	s, e = f.a.loadSession(httptest.NewRequest("GET", "/api/session", nil), sessionCookie.Value)
	if e != nil || s.MFA || !s.LoginTrusted {
		t.Fatal("token refresh promoted trusted login into MFA", e)
	}
	p.acr = ""

	t.Run("explicit step-up still requires a code", func(t *testing.T) {
		requireHTTP(t, trustedLogin("/auth/login?mfa=1&trust_device=1", trusted), 403)
	})
	t.Run("profile actions cannot reuse trust", func(t *testing.T) {
		login, state, _ := follow(request("/auth/login?action=configure_totp&trust_device=1", sessionCookie))
		w := finish(login, state, trusted)
		if responseCookie(w, "session") != nil {
			t.Fatal("account action bypassed MFA using a trusted browser")
		}
		_, _, u := follow(w)
		if u.Query().Get("acr_values") != "2" {
			t.Fatal("account action did not require MFA")
		}
	})
	for name, token := range map[string]*http.Cookie{
		"missing":   nil,
		"forged":    {Name: trusted.Name, Value: randomToken()},
		"malformed": {Name: trusted.Name, Value: "invalid"},
	} {
		t.Run(name+" trust requires MFA", func(t *testing.T) {
			w := trustedLogin("/auth/login", token)
			if responseCookie(w, "session") != nil {
				t.Fatal("invalid browser credential bypassed MFA")
			}
			follow(w)
		})
	}
	for _, mutation := range []struct{ name, sql string }{
		{"expired", `UPDATE trusted_login_devices SET expires_at=now()-interval '1 second'`},
		{"another realm", `UPDATE trusted_login_devices SET realm='synthetic-other-realm'`},
		{"another account", `UPDATE trusted_login_devices SET user_id='` + otherUser + `'`},
		{"changed authentication methods", `UPDATE trusted_login_devices SET credential_hash='\x00'::bytea`},
	} {
		t.Run(mutation.name+" trust requires MFA", func(t *testing.T) {
			var fingerprint []byte
			if e := f.admin.QueryRow(ctx, `SELECT credential_hash FROM trusted_login_devices WHERE token_hash=$1`, tokenHash).Scan(&fingerprint); e != nil {
				t.Fatal(e)
			}
			defer func() {
				if _, e := f.admin.Exec(ctx, `UPDATE trusted_login_devices SET expires_at=$1,realm='',credential_hash=$2,user_id=$4 WHERE token_hash=$3`, expiry, fingerprint, tokenHash, f.session.User.ID); e != nil {
					t.Error(e)
				}
			}()
			if _, e := f.admin.Exec(ctx, mutation.sql); e != nil {
				t.Fatal(e)
			}
			w := trustedLogin("/auth/login", trusted)
			if responseCookie(w, "session") != nil {
				t.Fatal("invalid trust bypassed MFA")
			}
			follow(w)
		})
	}
	t.Run("identity administration outage fails closed", func(t *testing.T) {
		previous := f.a.config.AdminClientID
		f.a.config.AdminClientID = ""
		defer func() { f.a.config.AdminClientID = previous }()
		requireHTTP(t, trustedLogin("/auth/login", trusted), 503)
	})
	t.Run("remembered login does not extend expiration", func(t *testing.T) {
		w := trustedLogin("/auth/login?trust_device=1", trusted)
		if responseCookie(w, "session") == nil || responseCookie(w, "trusted_device") != nil {
			t.Fatal("remembered login renewed trust or failed to open a session")
		}
		var after time.Time
		if e := f.admin.QueryRow(ctx, `SELECT expires_at FROM trusted_login_devices WHERE token_hash=$1`, tokenHash).Scan(&after); e != nil || !after.Equal(expiry) {
			t.Fatal("ordinary login changed the six-month deadline", e)
		}
	})
	t.Run("callback cannot opt in", func(t *testing.T) {
		p.acr = "2"
		login, state, _ := follow(request("/auth/login"))
		w := request("/auth/callback?code=test-code&state="+url.QueryEscape(state)+"&trust_device=1", login)
		requireHTTP(t, w, 302)
		if responseCookie(w, "trusted_device") != nil {
			t.Fatal("callback query enrolled a browser without bound opt-in")
		}
	})
}
