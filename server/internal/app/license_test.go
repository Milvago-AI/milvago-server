package app

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jackc/pgx/v5/pgxpool"
)

const testInstance = "i-0123456789abcdef0123456789abcdef"

// useTestLicenseKey replaces the compiled-in key and drops the suite-wide grant, so
// that the licence code path runs for real.
func useTestLicenseKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	savedKey, savedGrant := licensePublicKey, licenseTestGrant
	licensePublicKey, licenseTestGrant = public, nil
	t.Cleanup(func() { licensePublicKey, licenseTestGrant = savedKey, savedGrant })
	return private
}

func signLicense(t *testing.T, key any, algorithm jose.SignatureAlgorithm, c licenseClaims) string {
	t.Helper()
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: algorithm, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if e != nil {
		t.Fatal(e)
	}
	raw, e := jwt.Signed(signer).Claims(c).Serialize()
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

func testLicense(kind, instance string, expires time.Time, devices int) licenseClaims {
	c := licenseClaims{Claims: jwt.Claims{Issuer: licenseIssuer, Subject: "customer-001", ID: "license-" + kind, IssuedAt: jwt.NewNumericDate(time.Now())}, Kind: kind, Instance: instance}
	if kind == "enterprise" {
		c.Expiry = jwt.NewNumericDate(expires)
		c.MaxDevices = &devices
	}
	return c
}

func TestLicenseVerification(t *testing.T) {
	key := useTestLicenseKey(t)
	year := time.Now().Add(365 * 24 * time.Hour)
	enterprise := signLicense(t, key, jose.EdDSA, testLicense("enterprise", testInstance, year, 10))
	community := signLicense(t, key, jose.EdDSA, testLicense("community", testInstance, time.Time{}, 0))
	if c, e := verifyLicense(enterprise, testInstance); e != nil || c.Kind != "enterprise" || *c.MaxDevices != 10 {
		t.Fatal("valid enterprise licence refused:", e)
	}
	c, e := verifyLicense(community, testInstance)
	if Edition == "commercial" {
		if e != errLicenseCommunity {
			t.Fatal("free licence accepted by Enterprise:", e)
		}
	} else if e != nil || c.Kind != "community" {
		t.Fatal("free licence refused by Community:", e)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	unsigned := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + strings.Split(enterprise, ".")[1] + "."
	parts := strings.Split(enterprise, ".")
	tampered := testLicense("enterprise", testInstance, year, 0)
	tamperedPayload, _ := json.Marshal(tampered)
	hostile := map[string]string{
		"another key":         signLicense(t, other, jose.EdDSA, testLicense("enterprise", testInstance, year, 10)),
		"alg none":            unsigned,
		"HS256 on public key": signLicense(t, []byte(licensePublicKey), jose.HS256, testLicense("enterprise", testInstance, year, 10)),
		"another instance":    signLicense(t, key, jose.EdDSA, testLicense("enterprise", "i-ffffffffffffffffffffffffffffffff", year, 10)),
		"quota rewritten":     parts[0] + "." + base64.RawURLEncoding.EncodeToString(tamperedPayload) + "." + parts[2],
		"truncated signature": enterprise[:len(enterprise)-4],
		"wrong issuer": signLicense(t, key, jose.EdDSA, func() licenseClaims {
			c := testLicense("enterprise", testInstance, year, 10)
			c.Issuer = "attacker.example.test"
			return c
		}()),
		"unknown kind": signLicense(t, key, jose.EdDSA, testLicense("platinum", testInstance, year, 10)),
		"enterprise without expiry": signLicense(t, key, jose.EdDSA, func() licenseClaims {
			c := testLicense("enterprise", testInstance, year, 10)
			c.Expiry = nil
			return c
		}()),
		"negative quota": signLicense(t, key, jose.EdDSA, testLicense("enterprise", testInstance, year, -1)),
		"oversized":      enterprise + strings.Repeat("A", licenseMaxLength),
		"empty":          "",
	}
	for name, raw := range hostile {
		t.Run(name, func(t *testing.T) {
			if _, e := verifyLicense(raw, testInstance); e == nil {
				t.Fatal("licence accepted")
			}
		})
	}
	t.Run("no compiled key verifies nothing", func(t *testing.T) {
		saved := licensePublicKey
		licensePublicKey = mustLicenseKey("LICENSE_PUBLIC_KEY_PLACEHOLDER")
		defer func() { licensePublicKey = saved }()
		if _, e := verifyLicense(enterprise, testInstance); e == nil {
			t.Fatal("licence accepted without a key")
		}
	})
}

func TestLicenseStatus(t *testing.T) {
	now := time.Now()
	for _, test := range []struct {
		name    string
		expires time.Duration
		state   string
	}{{"current", 24 * time.Hour, "valid"}, {"five days late", -5 * 24 * time.Hour, "grace"}, {"eleven days late", -11 * 24 * time.Hour, "expired"}} {
		t.Run(test.name, func(t *testing.T) { testLicenseStatusCase(t, now, test.expires, test.state) })
	}
	testLicenseStatusWithoutGrant(t, now)
}

func testLicenseStatusCase(t *testing.T, now time.Time, expires time.Duration, state string) {
	c := testLicense("enterprise", testInstance, now.Add(expires), 3)
	s := statusOf(&c, testInstance, now)
	usable := state != "expired"
	if s.State != state || s.Locked != (Edition == "commercial" && !usable) || s.Restricted != (Edition == "community" && !usable) {
		t.Fatalf("%+v", s)
	}
	if usable && s.deviceLimit() != 3 {
		t.Fatalf("quota %d", s.deviceLimit())
	}
}

func testLicenseStatusWithoutGrant(t *testing.T, now time.Time) {
	none := statusOf(nil, testInstance, now)
	if none.State != "none" || none.Locked != (Edition == "commercial") || none.Restricted != (Edition == "community") {
		t.Fatalf("%+v", none)
	}
	if Edition == "community" && none.deviceLimit() != communityDeviceLimit {
		t.Fatalf("restricted quota %d", none.deviceLimit())
	}
	free := testLicense("community", testInstance, time.Time{}, 0)
	if s := statusOf(&free, testInstance, now); s.State != "valid" || s.deviceLimit() != 0 {
		t.Fatalf("free licence %+v", s)
	}
}

// TestLicenseIntegration runs the wizard, sign-in and limits against the real
// database, with the licence code path live.
func TestLicenseIntegration(t *testing.T) {
	f := newLicenseIntegrationFixture(t)
	t.Run("the wizard shows the instance identifier", f.testLicenseWizardInstance)
	t.Run("licence check verifies before setup without saving", f.testLicenseCheck)
	t.Run("a licence for another instance is refused before any account exists", f.testLicenseWrongInstance)
	if Edition == "commercial" {
		t.Run("Enterprise setup needs an Enterprise licence", f.testLicenseEnterpriseSetup)
		requireHTTP(t, f.complete(t, f.enterprise(f.year, 2)), 200)
	} else {
		requireHTTP(t, f.complete(t, ""), 200)
	}
	t.Run("setup closed: no identifier, no licence request", f.testLicenseSetupClosed)

	f.prepareOwner(t)
	if Edition == "community" {
		t.Run("without a licence Community is restricted", f.testLicenseCommunityRestricted)
		t.Run("a revoked device frees its place", f.testLicenseRevocationFreesPlace)
		t.Run("a revoked device is never approved back into the quota", f.testLicenseRevocationCannotApprove)
		t.Run("concurrent enrollments cannot share the last place", f.testLicenseConcurrentQuota)
		t.Run("an SSO or directory account cannot sign in", f.testLicenseRestrictedSSO)
		t.Run("the free licence lifts every limit", f.testLicenseFreeGrant)
		t.Run("the licence request goes to the fixed webhook only", f.testLicenseWebhook)
	} else {
		t.Run("the Enterprise quota counts every organization", f.testLicenseEnterpriseQuota)
		t.Run("a free licence never replaces an Enterprise one", f.testLicenseEnterpriseRefusesFree)
		t.Run("ten days of grace, then everything stops", f.testLicenseGraceExpiry)
		t.Run("the gate reuses its last read and fails closed without one", f.testLicenseGateCache)
	}
	t.Run("only the instance owner enters a licence", f.testLicenseOwnerOnly)
}
func newLicenseIntegrationFixture(t *testing.T) *licenseIntegrationFixture {
	runtimeURL, migrationURL := os.Getenv("TEST_DATABASE_URL"), os.Getenv("TEST_MIGRATION_DATABASE_URL")
	if runtimeURL == "" || migrationURL == "" {
		t.Skip("licence integration requires disposable milvago_test database")
	}
	for _, raw := range []string{runtimeURL, migrationURL} {
		if u, e := url.Parse(raw); e != nil || u.Path != "/milvago_test" {
			t.Fatal("licence tests require disposable database named milvago_test")
		}
	}
	key := useTestLicenseKey(t)
	ctx := context.Background()
	admin, e := pgxpool.New(ctx, migrationURL)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(admin.Close)
	if _, e = admin.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); e != nil {
		t.Fatal(e)
	}
	p := identityProvider(t)
	block, _ := aes.NewCipher(make([]byte, 32))
	gcm, _ := cipher.NewGCM(block)
	const token = "synthetic-setup-token-of-sufficient-length"
	const origin = "http://localhost:4020"
	config := Config{DatabaseURL: runtimeURL, MigrationURL: migrationURL, RuntimeRole: "milvago_runtime", OrganizationName: "Milvago", AppURL: origin, Issuer: p.server.URL, ClientID: "test-console", ClientSecret: "synthetic-secret", AdminClientID: "test-management", AdminClientSecret: "test-secret", SetupTokenHash: hash(token), SessionCipher: gcm, ContentKeys: testContentKeys(), ContentVersion: 1, SigningKey: ed25519.NewKeyFromSeed(make([]byte, 32))}
	db, e := OpenDatabase(ctx, config)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(db.Close)
	a, e := New(ctx, config, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if e != nil {
		t.Fatal(e)
	}
	peer := 0
	call := func(method, path string, body any, cookies []*http.Cookie, csrf string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(method, path, bytes.NewReader(raw))
		peer++
		r.RemoteAddr = fmt.Sprintf("198.51.100.%d:40000", peer%250+1)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		for _, c := range cookies {
			r.AddCookie(c)
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		return w
	}
	var org, instance string
	if e = admin.QueryRow(ctx, `SELECT c.organization_id,p.instance_id FROM app_config c CROSS JOIN publisher_client_state p`).Scan(&org, &instance); e != nil {
		t.Fatal(e)
	}
	year := time.Now().Add(365 * 24 * time.Hour)
	enterprise := func(expires time.Time, devices int) string {
		return signLicense(t, key, jose.EdDSA, testLicense("enterprise", instance, expires, devices))
	}
	free := signLicense(t, key, jose.EdDSA, testLicense("community", instance, time.Time{}, 0))
	f := &licenseIntegrationFixture{admin: admin, p: p, a: a, key: key, instance: instance, year: year, free: free, enterprise: enterprise, call: call, org: org, origin: origin}

	complete := func(t *testing.T, license string) *httptest.ResponseRecorder {
		t.Helper()
		w := call("POST", "/api/setup/session", map[string]string{"token": token}, nil, "")
		requireHTTP(t, w, 200)
		var session struct{ CSRF string }
		_ = json.Unmarshal(w.Body.Bytes(), &session)
		body := validSetupRequest()
		body.Organization.PublicURL = origin
		body.License = license
		a.config.Issuer = p.server.URL + "/realms/test"
		defer func() { a.config.Issuer = p.server.URL }()
		return call("POST", "/api/setup/complete", body, w.Result().Cookies(), session.CSRF)
	}
	f.complete = complete
	return f
}

func (f *licenseIntegrationFixture) prepareOwner(t *testing.T) {
	call := f.call
	p := f.p
	admin := f.admin
	ctx := context.Background()
	org := f.org
	login := func(t *testing.T) ([]*http.Cookie, string) {
		t.Helper()
		w := call("GET", "/auth/login", nil, nil, "")
		requireHTTP(t, w, 302)
		location, _ := url.Parse(w.Header().Get("Location"))
		p.nonce, p.challenge = location.Query().Get("nonce"), location.Query().Get("code_challenge")
		p.email, p.subject, p.acr = "owner@example.test", "license-owner", "2"
		w = call("GET", "/auth/callback?code=test-code&state="+url.QueryEscape(location.Query().Get("state")), nil, w.Result().Cookies(), "")
		if w.Code != 302 {
			return nil, w.Body.String()
		}
		cookies := w.Result().Cookies()
		w = call("GET", "/api/session", nil, cookies, "")
		requireHTTP(t, w, 200)
		var s struct {
			CSRF string `json:"csrf_token"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &s)
		return cookies, s.CSRF
	}
	cookies, csrf := login(t)
	if cookies == nil {
		t.Fatal("owner sign-in refused:", csrf)
	}
	license := func(t *testing.T) licenseStatus {
		t.Helper()
		w := call("GET", "/api/session", nil, cookies, "")
		requireHTTP(t, w, 200)
		var s struct{ License licenseStatus }
		if e := json.Unmarshal(w.Body.Bytes(), &s); e != nil {
			t.Fatal(e)
		}
		return s.License
	}
	enrolled := 0
	enroll := func(t *testing.T) int {
		t.Helper()
		setTenant(t, admin, org)
		secret := randomToken()
		if _, e := admin.Exec(ctx, `INSERT INTO enrollments(organization_id,token_hash,label,expires_at) VALUES($1,$2,'licence test',now()+interval '10 minutes')`, org, hash(secret)); e != nil {
			t.Fatal(e)
		}
		enrolled++
		w := call("POST", "/v1/enroll", map[string]string{"token": secret, "hostname": fmt.Sprintf("endpoint-%02d", enrolled), "platform": "windows", "version": "1.0.0"}, nil, "")
		return w.Code
	}
	setLicense := func(t *testing.T, raw string, want int) {
		t.Helper()
		requireHTTP(t, call("PUT", "/api/license", map[string]string{"license": raw}, cookies, csrf), want)
	}

	f.login, f.license, f.enroll, f.setLicense, f.cookies, f.csrf = login, license, enroll, setLicense, cookies, csrf

}

type licenseIntegrationFixture struct {
	admin      *pgxpool.Pool
	p          *testIdentity
	a          *App
	key        ed25519.PrivateKey
	instance   string
	year       time.Time
	free       string
	enterprise func(time.Time, int) string
	call       func(string, string, any, []*http.Cookie, string) *httptest.ResponseRecorder
	complete   func(*testing.T, string) *httptest.ResponseRecorder
	login      func(*testing.T) ([]*http.Cookie, string)
	license    func(*testing.T) licenseStatus
	enroll     func(*testing.T) int
	setLicense func(*testing.T, string, int)
	cookies    []*http.Cookie
	csrf       string
	org        string
	origin     string
}

func (f *licenseIntegrationFixture) testLicenseWizardInstance(t *testing.T) {
	call := f.call
	instance := f.instance

	w := call("GET", "/api/setup", nil, nil, "")
	requireHTTP(t, w, 200)
	if !strings.Contains(w.Body.String(), instance) {
		t.Fatal("instance identifier missing:", w.Body.String())
	}
}

func (f *licenseIntegrationFixture) testLicenseCheck(t *testing.T) {
	opened := f.call("POST", "/api/setup/session", map[string]string{"token": "synthetic-setup-token-of-sufficient-length"}, nil, "")
	requireHTTP(t, opened, 200)
	var session struct{ CSRF string }
	if e := json.Unmarshal(opened.Body.Bytes(), &session); e != nil || session.CSRF == "" {
		t.Fatal("setup session missing CSRF", e)
	}
	cookies := opened.Result().Cookies()
	check := func(raw string, cookies []*http.Cookie, csrf string) *httptest.ResponseRecorder {
		return f.call("POST", "/api/setup/license-check", map[string]string{"license": raw}, cookies, csrf)
	}
	requireHTTP(t, check("invalid", nil, ""), 401)
	requireHTTP(t, check("invalid", cookies, "wrong-csrf"), 401)
	invalid := check("invalid", cookies, session.CSRF)
	requireHTTP(t, invalid, 400)
	if !strings.Contains(invalid.Body.String(), "license_invalid") {
		t.Fatal("invalid licence error missing")
	}
	wrong := signLicense(t, f.key, jose.EdDSA, testLicense("enterprise", testInstance, f.year, 0))
	requireHTTP(t, check(wrong, cookies, session.CSRF), 400)
	valid := f.free
	if Edition == "commercial" {
		wrongEdition := check(f.free, cookies, session.CSRF)
		requireHTTP(t, wrongEdition, 400)
		if !strings.Contains(wrongEdition.Body.String(), "license_community_on_enterprise") {
			t.Fatal("wrong edition error missing")
		}
		valid = f.enterprise(f.year, 2)
	}
	accepted := check(valid, cookies, session.CSRF)
	requireHTTP(t, accepted, 200)
	if strings.Contains(accepted.Body.String(), valid) {
		t.Fatal("license text reflected in check response")
	}
	var stored string
	if e := f.admin.QueryRow(context.Background(), `SELECT license FROM app_config`).Scan(&stored); e != nil || stored != "" {
		t.Fatal("licence check changed stored licence", e)
	}
	if len(f.p.users) != 1 {
		t.Fatal("licence check created an account")
	}
}

func (f *licenseIntegrationFixture) testLicenseWrongInstance(t *testing.T) {
	complete := f.complete
	p := f.p
	key := f.key
	year := f.year

	w := complete(t, signLicense(t, key, jose.EdDSA, testLicense("enterprise", testInstance, year, 0)))
	requireHTTP(t, w, 400)
	if len(p.users) != 1 {
		t.Fatal("an account was created for a refused licence")
	}
}

func (f *licenseIntegrationFixture) testLicenseEnterpriseSetup(t *testing.T) {
	complete := f.complete
	free := f.free

	requireHTTP(t, complete(t, ""), 400)
	w := complete(t, free)
	requireHTTP(t, w, 400)
	if !strings.Contains(w.Body.String(), "license_community_on_enterprise") {
		t.Fatal(w.Body.String())
	}
}

func (f *licenseIntegrationFixture) testLicenseSetupClosed(t *testing.T) {
	call := f.call
	instance := f.instance

	w := call("GET", "/api/setup", nil, nil, "")
	requireHTTP(t, w, 200)
	if strings.Contains(w.Body.String(), instance) {
		t.Fatal("instance identifier public after setup:", w.Body.String())
	}
	requireHTTP(t, call("POST", "/api/setup/license-request", map[string]string{"email": "owner@example.test"}, nil, ""), 404)
	requireHTTP(t, call("POST", "/api/setup/license-check", map[string]string{"license": f.free}, nil, ""), 404)
}

func (f *licenseIntegrationFixture) testLicenseCommunityRestricted(t *testing.T) {
	call := f.call
	license := f.license
	enroll := f.enroll
	instance := f.instance
	cookies := f.cookies
	csrf := f.csrf

	if l := license(t); !l.Restricted || l.State != "none" || l.Instance != instance {
		t.Fatalf("%+v", l)
	}
	for _, r := range []struct{ method, path string }{
		{"POST", "/api/roles"}, {"PUT", "/api/roles/admin"}, {"DELETE", "/api/roles/admin"},
		{"POST", "/api/members/invitations"}, {"PUT", "/api/members/00000000-0000-0000-0000-000000000000/role"},
		{"PUT", "/api/settings/ldap"}, {"POST", "/api/settings/ldap/test"}, {"GET", "/api/members/directory"}, {"POST", "/api/members/directory"},
	} {
		w := call(r.method, r.path, map[string]string{}, cookies, csrf)
		if w.Code != 403 || !strings.Contains(w.Body.String(), "license_restricted") {
			t.Errorf("%s %s answered %d %s", r.method, r.path, w.Code, w.Body.String())
		}
	}
	for i := 0; i < communityDeviceLimit; i++ {
		if code := enroll(t); code != 201 {
			t.Fatalf("device %d refused: %d", i+1, code)
		}
	}
	if code := enroll(t); code != 409 {
		t.Fatalf("sixth device answered %d", code)
	}
}

func (f *licenseIntegrationFixture) testLicenseRevocationFreesPlace(t *testing.T) {
	enroll := f.enroll
	admin := f.admin
	ctx := context.Background()
	org := f.org

	setTenant(t, admin, org)
	if tag, e := admin.Exec(ctx, `UPDATE devices SET status='revoked' WHERE id=(SELECT id FROM devices ORDER BY created_at LIMIT 1)`); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("could not revoke", e)
	}
	if code := enroll(t); code != 201 {
		t.Fatalf("enrollment after revocation answered %d", code)
	}
}

func (f *licenseIntegrationFixture) testLicenseRevocationCannotApprove(t *testing.T) {
	call := f.call
	enroll := f.enroll
	admin := f.admin
	ctx := context.Background()
	cookies := f.cookies
	csrf := f.csrf
	org := f.org

	setTenant(t, admin, org)
	var revoked string
	if e := admin.QueryRow(ctx, `SELECT id FROM devices WHERE status='revoked' LIMIT 1`).Scan(&revoked); e != nil {
		t.Fatal(e)
	}
	requireHTTP(t, call("POST", "/api/devices/"+revoked+"/approve", map[string]any{}, cookies, csrf), 409)
	if code := enroll(t); code != 409 {
		t.Fatalf("enrollment over the quota answered %d", code)
	}
}

func (f *licenseIntegrationFixture) testLicenseConcurrentQuota(t *testing.T) {
	racers := f.prepareLicenseRace(t)
	codes := f.runLicenseRace(racers)
	f.assertLicenseRace(t, codes)
}

func (f *licenseIntegrationFixture) prepareLicenseRace(t *testing.T) []*http.Request {
	admin := f.admin
	a := f.a
	ctx := context.Background()
	org := f.org
	setTenant(t, admin, org)
	if tag, e := admin.Exec(ctx, `UPDATE devices SET status='revoked' WHERE id=(SELECT id FROM devices WHERE status<>'revoked' ORDER BY created_at LIMIT 1)`); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("could not free a place", e)
	}
	saved := a.config.UpdatePublicKey
	a.config.UpdatePublicKey = ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	t.Cleanup(func() { a.config.UpdatePublicKey = saved })
	tx, e := tenantTx(ctx, a.db, org)
	if e != nil {
		t.Fatal(e)
	}
	provision, e := a.installerProvision(ctx, tx, org, "windows")
	tx.Rollback(ctx)
	if e != nil {
		t.Fatal(e)
	}
	var racers []*http.Request
	for i := 0; i < 4; i++ {
		secret := randomToken()
		if _, e := admin.Exec(ctx, `INSERT INTO enrollments(organization_id,token_hash,label,expires_at) VALUES($1,$2,'race',now()+interval '10 minutes')`, org, hash(secret)); e != nil {
			t.Fatal(e)
		}
		enrollBody, _ := json.Marshal(map[string]string{"token": secret, "hostname": fmt.Sprintf("racer-%d", i), "platform": "windows", "version": "1.0.0"})
		installBody, _ := json.Marshal(installationRequest{InstallationID: fmt.Sprintf("%08d-0000-4000-8000-%012d", i, i), InstallationSecret: randomToken(), Hostname: fmt.Sprintf("installer-%d", i), Platform: "windows", Version: "1.0.0"})
		for _, r := range []*http.Request{httptest.NewRequest("POST", "/v1/enroll", bytes.NewReader(enrollBody)), httptest.NewRequest("POST", "/v2/install", bytes.NewReader(installBody))} {
			r.Header.Set("Content-Type", "application/json")
			r.RemoteAddr = fmt.Sprintf("203.0.113.%d:40000", len(racers)+1)
			if r.URL.Path == "/v2/install" {
				r.Header.Set("Authorization", "Bearer "+provision.BootstrapToken)
			}
			racers = append(racers, r)
		}
	}
	return racers
}

func (f *licenseIntegrationFixture) runLicenseRace(racers []*http.Request) []int {
	a := f.a
	handler := a.Handler()
	codes := make([]int, len(racers))
	var wg sync.WaitGroup
	for i, r := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			codes[i] = w.Code
			if w.Code != 201 && !strings.Contains(w.Body.String(), "device_limit_reached") {
				codes[i] = -w.Code
			}
		}()
	}
	wg.Wait()
	return codes
}

func (f *licenseIntegrationFixture) assertLicenseRace(t *testing.T, codes []int) {
	admin := f.admin
	ctx := context.Background()
	won := 0
	for _, code := range codes {
		switch code {
		case 201:
			won++
		case 409:
		default:
			t.Errorf("racer answered %d without reaching the quota", -code)
		}
	}
	var live int
	if e := admin.QueryRow(ctx, `SELECT count(*) FROM devices WHERE status<>'revoked'`).Scan(&live); e != nil {
		t.Fatal(e)
	}
	if won != 1 || live != communityDeviceLimit {
		t.Fatalf("%d racers won, %d live devices: %v", won, live, codes)
	}
}

func (f *licenseIntegrationFixture) testLicenseRestrictedSSO(t *testing.T) {
	login := f.login
	admin := f.admin
	ctx := context.Background()
	org := f.org

	setTenant(t, admin, org)
	if tag, e := admin.Exec(ctx, `UPDATE users SET identity_type='sso' WHERE subject='license-owner'`); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("could not mark the account", e)
	}
	defer admin.Exec(ctx, `UPDATE users SET identity_type='local' WHERE subject='license-owner'`)
	if c, body := login(t); c != nil || !strings.Contains(body, "license_restricted") {
		t.Fatal("SSO sign-in accepted without a licence:", body)
	}
}

func (f *licenseIntegrationFixture) testLicenseFreeGrant(t *testing.T) {
	call := f.call
	license := f.license
	enroll := f.enroll
	setLicense := f.setLicense
	free := f.free
	cookies := f.cookies
	csrf := f.csrf

	setLicense(t, "not-a-licence", 400)
	setLicense(t, free, 200)
	if l := license(t); l.Restricted || l.State != "valid" || l.Kind != "community" {
		t.Fatalf("%+v", l)
	}
	if code := enroll(t); code != 201 {
		t.Fatalf("enrollment with a licence answered %d", code)
	}
	w := call("POST", "/api/roles", map[string]any{"name": "Reviewer", "permissions": []string{permEventsRead}}, cookies, csrf)
	if w.Code == 403 {
		t.Fatal("roles still restricted:", w.Body.String())
	}
}

func (f *licenseIntegrationFixture) testLicenseWebhook(t *testing.T) {
	call := f.call
	instance := f.instance
	cookies := f.cookies
	csrf := f.csrf

	var got map[string]string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(200)
	}))
	defer hook.Close()
	saved := licenseRequestURL
	licenseRequestURL = hook.URL
	defer func() { licenseRequestURL = saved }()
	requireHTTP(t, call("POST", "/api/license/request", map[string]string{"email": "Owner <owner@example.test>"}, cookies, csrf), 400)
	requireHTTP(t, call("POST", "/api/license/request", map[string]string{"email": "owner@example.test"}, cookies, csrf), 202)
	if got["email"] != "owner@example.test" || got["instance"] != instance || len(got) != 2 {
		t.Fatalf("webhook received %v", got)
	}
}

func (f *licenseIntegrationFixture) testLicenseEnterpriseQuota(t *testing.T) {
	license := f.license
	enroll := f.enroll
	admin := f.admin
	ctx := context.Background()
	org := f.org

	if l := license(t); l.Locked || l.State != "valid" || l.MaxDevices != 2 {
		t.Fatalf("%+v", l)
	}
	if code := enroll(t); code != 201 {
		t.Fatalf("first device answered %d", code)
	}
	var child string
	if e := admin.QueryRow(ctx, `INSERT INTO organizations(name,parent_id) VALUES('Child organization',$1) RETURNING id`, org).Scan(&child); e != nil {
		t.Fatal(e)
	}
	setTenant(t, admin, child)
	if _, e := admin.Exec(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status) VALUES($1,$2,'child-endpoint','windows','1.0.0','approved')`, child, hash(randomToken())); e != nil {
		t.Fatal(e)
	}
	if code := enroll(t); code != 409 {
		t.Fatalf("third device across organizations answered %d", code)
	}
}

func (f *licenseIntegrationFixture) testLicenseEnterpriseRefusesFree(t *testing.T) {
	setLicense := f.setLicense
	free := f.free

	setLicense(t, free, 400)
}

func (f *licenseIntegrationFixture) testLicenseGraceExpiry(t *testing.T) {
	call := f.call
	license := f.license
	enroll := f.enroll
	setLicense := f.setLicense
	year := f.year
	enterprise := f.enterprise
	cookies := f.cookies
	csrf := f.csrf

	setLicense(t, enterprise(time.Now().Add(-5*24*time.Hour), 0), 200)
	if l := license(t); l.State != "grace" || l.Locked {
		t.Fatalf("%+v", l)
	}
	requireHTTP(t, call("GET", "/api/members", nil, cookies, ""), 200)
	setLicense(t, enterprise(time.Now().Add(-11*24*time.Hour), 0), 200)
	if l := license(t); l.State != "expired" || !l.Locked {
		t.Fatalf("%+v", l)
	}
	requireHTTP(t, call("GET", "/api/members", nil, cookies, ""), 402)
	requireHTTP(t, call("GET", "/api/setup/../members", nil, cookies, ""), 402)
	requireHTTP(t, call("POST", "/api/license/request", map[string]string{"email": "owner@example.test"}, cookies, csrf), 402)
	if code := enroll(t); code != 402 {
		t.Fatalf("enrollment on an expired licence answered %d", code)
	}
	requireHTTP(t, call("POST", "/mcp", map[string]any{}, nil, ""), 402)
	// Spellings the mux routes to a gated handler while path.Clean of the decoded
	// path does not see one.
	for _, target := range []string{"/%61pi/members", "/api/roles/..%2F..%2F..%2Fsetup/members", "/api/shadow/events/..%2F..%2F..%2F..%2Fx", "/v2/update/artifact/..%2F..%2F..%2F..%2Fx", "/auth/device?token=" + strings.Repeat("a", 43)} {
		if w := call("GET", target, nil, cookies, ""); w.Code != 402 {
			t.Errorf("GET %s answered %d %s", target, w.Code, w.Body.String())
		}
	}
	setLicense(t, enterprise(year, 0), 200)
	requireHTTP(t, call("GET", "/api/members", nil, cookies, ""), 200)
}

func (f *licenseIntegrationFixture) testLicenseGateCache(t *testing.T) {
	call := f.call
	a := f.a
	ctx := context.Background()
	cookies := f.cookies

	requireHTTP(t, call("GET", "/api/members", nil, cookies, ""), 200)
	closed, e := pgxpool.NewWithConfig(ctx, a.db.Config())
	if e != nil {
		t.Fatal(e)
	}
	closed.Close()
	original := a.db
	a.db = closed
	defer func() { a.db = original }()
	// Warm: the gate lets the request through and the handler meets the outage.
	if w := call("GET", "/v1/policy", nil, nil, ""); w.Code == 402 || strings.Contains(w.Body.String(), "license_unavailable") {
		t.Fatalf("warm gate consulted the database: %d %s", w.Code, w.Body.String())
	}
	a.forgetLicense()
	w := call("GET", "/v1/policy", nil, nil, "")
	requireHTTP(t, w, 503)
	if !strings.Contains(w.Body.String(), "license_unavailable") {
		t.Fatal(w.Body.String())
	}
}

func (f *licenseIntegrationFixture) testLicenseOwnerOnly(t *testing.T) {
	call := f.call
	a := f.a
	free := f.free
	cookies := f.cookies
	csrf := f.csrf
	origin := f.origin

	requireHTTP(t, call("PUT", "/api/license", map[string]string{"license": free}, cookies, ""), 403)
	// A machine credential never changes the licence, even beside a valid session.
	raw, _ := json.Marshal(map[string]string{"license": free})
	r := httptest.NewRequest("PUT", "/api/license", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", origin)
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("Authorization", "Bearer mlv_synthetic")
	for _, c := range cookies {
		r.AddCookie(c)
	}
	bearer := httptest.NewRecorder()
	a.Handler().ServeHTTP(bearer, r)
	if bearer.Code != 403 || !strings.Contains(bearer.Body.String(), "session_required") {
		t.Fatalf("bearer licence change answered %d %s", bearer.Code, bearer.Body.String())
	}
	w := call("PUT", "/api/license", map[string]string{"license": free}, nil, "")
	if w.Code != 401 && w.Code != 403 {
		t.Fatalf("anonymous licence change answered %d", w.Code)
	}
}
