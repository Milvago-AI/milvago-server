package app

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type observabilityFixture struct {
	a         *App
	admin     *pgxpool.Pool
	org, user string
	owner     *http.Cookie
	csrf      string
}

func newObservabilityFixture(t *testing.T) *observabilityFixture {
	t.Helper()
	runtimeURL, migrationURL := os.Getenv("TEST_DATABASE_URL"), os.Getenv("TEST_MIGRATION_DATABASE_URL")
	if runtimeURL == "" || migrationURL == "" {
		t.Skip("requires disposable milvago_test database")
	}
	requireDisposableObservabilityURLs(t, runtimeURL, migrationURL)
	ctx := context.Background()
	poolConfig, e := pgxpool.ParseConfig(migrationURL)
	if e != nil {
		t.Fatal(e)
	}
	poolConfig.MaxConns = 1
	admin, e := pgxpool.NewWithConfig(ctx, poolConfig)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(admin.Close)
	if _, e = admin.Exec(ctx, "DROP SCHEMA public CASCADE; CREATE SCHEMA public"); e != nil {
		t.Fatal(e)
	}
	block, _ := aes.NewCipher(make([]byte, 32))
	gcm, _ := cipher.NewGCM(block)
	idp := identityProvider(t)
	cfg := Config{DatabaseURL: runtimeURL, MigrationURL: migrationURL, RuntimeRole: "milvago_runtime", OrganizationName: "Test organization", BootstrapEmail: "owner@example.test", AppURL: "http://localhost:4020", PublicURL: "http://localhost:4020", Issuer: idp.server.URL, ClientID: "test-console", SessionCipher: gcm, ContentKeys: testContentKeys(), ContentVersion: 1, SigningKey: ed25519.NewKeyFromSeed(make([]byte, 32))}
	pool, e := OpenDatabase(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(pool.Close)
	a, e := New(ctx, cfg, pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if e != nil {
		t.Fatal(e)
	}
	f := &observabilityFixture{a: a, admin: admin, csrf: randomToken()}
	if e = admin.QueryRow(ctx, "SELECT id FROM organizations LIMIT 1").Scan(&f.org); e != nil {
		t.Fatal(e)
	}
	if _, e = admin.Exec(ctx, "SELECT set_config('milvago.organization_id',$1,false)", f.org); e != nil {
		t.Fatal(e)
	}
	if e = admin.QueryRow(ctx, "INSERT INTO users(subject,email,display_name) VALUES('observability-owner','owner@example.test','Test owner') RETURNING id").Scan(&f.user); e != nil {
		t.Fatal(e)
	}
	if _, e = admin.Exec(ctx, "INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')", f.org, f.user); e != nil {
		t.Fatal(e)
	}
	token := randomToken()
	f.owner = &http.Cookie{Name: cookieName("session"), Value: token}
	if _, e = admin.Exec(ctx, `INSERT INTO sessions(token_hash,user_id,organization_id,csrf_token,encrypted_tokens,mfa,expires_at,identity_expires_at)
 VALUES($1,$2,$3,$4,$5,true,$6,$6)`, hash(token), f.user, f.org, f.csrf, []byte("synthetic-session"), time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	return f
}
func requireDisposableObservabilityURLs(t *testing.T, urls ...string) {
	t.Helper()
	for _, raw := range urls {
		u, e := url.Parse(raw)
		if e != nil || u.Path != "/milvago_test" {
			t.Fatal("requires disposable milvago_test database")
		}
	}
}

func (f *observabilityFixture) call(method, path string, body any, csrf string) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(method, path, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", f.a.config.AppURL)
	r.Header.Set("X-CSRF-Token", csrf)
	r.AddCookie(f.owner)
	w := httptest.NewRecorder()
	f.a.Handler().ServeHTTP(w, r)
	return w
}

// testContentKeys is the content-encryption root the tests seal with. It is
// deliberately not the all-zero key the session cipher uses in these fixtures:
// the two roots are separate in production, so a test that shared one would stop
// noticing if the separation regressed.
func testContentKeys() map[int][]byte { return map[int][]byte{1: bytes.Repeat([]byte{7}, 32)} }

func requireHTTP(t *testing.T, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("HTTP %d, want %d: %s", w.Code, status, w.Body.String())
	}
}
func TestDefaultLanguageIntegration(t *testing.T) {
	f := newObservabilityFixture(t)
	bootstrap := httptest.NewRecorder()
	f.a.Handler().ServeHTTP(bootstrap, httptest.NewRequest("GET", "/api/bootstrap", nil))
	requireHTTP(t, bootstrap, 200)
	var public map[string]any
	if e := json.Unmarshal(bootstrap.Body.Bytes(), &public); e != nil {
		t.Fatal(e)
	}
	// Public preferences: the default language and the edition name shown on the
	// signed-out entry page, and nothing else.
	// English is the instance default (product decision of 2026-09-25); the test then moves
	// it to French, so that persisting a change is actually observed.
	if len(public) != 2 || public["default_language"] != "en" || public["edition"] != Edition {
		t.Fatal("public preferences must contain only the default language and the edition")
	}
	body := map[string]any{"name": "Test organization", "event_retention_days": 90, "public_url": f.a.config.PublicURL, "default_language": "fr"}
	requireHTTP(t, f.call("PUT", "/api/settings", body, "invalid"), 403)
	body["default_language"] = "invalid"
	requireHTTP(t, f.call("PUT", "/api/settings", body, f.csrf), 400)
	body["default_language"] = "fr"
	requireHTTP(t, f.call("PUT", "/api/settings", body, f.csrf), 200)
	// Shortening retention deletes history within the hour: a fresh second factor.
	body["event_retention_days"] = 30
	if w := f.call("PUT", "/api/settings", body, f.csrf); w.Code != 403 || !strings.Contains(w.Body.String(), "fresh_mfa_required") {
		t.Fatalf("retention shortened without a fresh second factor: %d %s", w.Code, w.Body.String())
	}
	body["event_retention_days"] = 90
	for _, path := range []string{"/api/bootstrap", "/api/session", "/api/settings"} {
		w := f.call("GET", path, nil, "")
		requireHTTP(t, w, 200)
		var result map[string]any
		if e := json.Unmarshal(w.Body.Bytes(), &result); e != nil {
			t.Fatal(e)
		}
		if result["default_language"] != "fr" {
			t.Fatalf("%s did not persist language", path)
		}
	}
	// Identity-provider login receives the instance default, or the user's explicit UI choice.
	for _, test := range []struct{ path, want string }{{"/auth/login", "fr"}, {"/auth/login?lang=en", "en"}, {"/auth/login?lang=invalid", "fr"}} {
		w := f.call("GET", test.path, nil, "")
		requireHTTP(t, w, 302)
		target, e := url.Parse(w.Header().Get("Location"))
		if e != nil || target.Query().Get("ui_locales") != test.want {
			t.Fatal("identity-provider locale not applied")
		}
	}
	// Existing settings clients may omit language without resetting it.
	delete(body, "default_language")
	requireHTTP(t, f.call("PUT", "/api/settings", body, f.csrf), 200)
	if _, e := f.admin.Exec(context.Background(), "UPDATE memberships SET role='admin' WHERE user_id=$1", f.user); e != nil {
		t.Fatal(e)
	}
	body["default_language"] = "en"
	requireHTTP(t, f.call("PUT", "/api/settings", body, f.csrf), 403)
	var language string
	if e := f.admin.QueryRow(context.Background(), "SELECT default_language FROM app_config").Scan(&language); e != nil || language != "fr" {
		t.Fatal("unauthorized language change")
	}
	if Edition == "community" {
		requireHTTP(t, f.call("GET", "/api/observability", nil, ""), 404)
		requireHTTP(t, f.call("PUT", "/api/observability", map[string]any{"edition": "commercial"}, f.csrf), 404)
		if hasPermission(permissionCatalog, "observability.manage") {
			t.Fatal("Enterprise permission in Community catalog")
		}
		var absent bool
		if e := f.admin.QueryRow(context.Background(), "SELECT to_regclass('public.observability_settings') IS NULL").Scan(&absent); e != nil || !absent {
			t.Fatal("Enterprise tables in Community")
		}
	}
}
