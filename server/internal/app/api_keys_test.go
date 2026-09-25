package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The limiter's window is fixed and the whole map is dropped when it turns, so
// the boundary is worth pinning down explicitly rather than only through HTTP.
func TestAPIKeyRateWindow(t *testing.T) {
	var limiter ingestLimiter
	start := time.Date(2026, 9, 10, 12, 0, 30, 0, time.UTC)
	for i := 0; i < apiKeyBudget; i++ {
		if !limiter.allow("apikey a", apiKeyBudget, start) {
			t.Fatalf("refused request %d of %d", i, apiKeyBudget)
		}
	}
	if limiter.allow("apikey a", apiKeyBudget, start) {
		t.Fatal("the budget did not bound the key")
	}
	// A second key is counted separately.
	if !limiter.allow("apikey b", apiKeyBudget, start) {
		t.Fatal("one key's flood bounded another")
	}
	// The next window starts clean.
	if !limiter.allow("apikey a", apiKeyBudget, start.Add(time.Minute)) {
		t.Fatal("the window did not turn")
	}
}

// Unit coverage: no database, so it runs in every `go test` invocation.

func TestAPIKeyHeaderShape(t *testing.T) {
	if apiKeyLength != 47 {
		t.Fatalf("an API key must be 47 characters, got %d", apiKeyLength)
	}
	// The device credential header is exactly len("Bearer ")+43 = 50 bytes and is
	// compared with ==, so the two credential classes must not be able to satisfy
	// each other's length check in either direction.
	if len("Bearer ")+apiKeyLength == 50 {
		t.Fatal("an API key header must not be the length of a device credential header")
	}
	valid := apiKeyPrefix + randomToken()
	for name, token := range map[string]string{
		"empty":               "",
		"device credential":   randomToken(),
		"no prefix":           "aaaa" + randomToken(),
		"prefix only":         apiKeyPrefix,
		"one character short": valid[:len(valid)-1],
		"one character long":  valid + "x",
	} {
		if len(token) == apiKeyLength && strings.HasPrefix(token, apiKeyPrefix) {
			t.Fatalf("%s should not satisfy the key shape", name)
		}
	}
	if len(valid) != apiKeyLength || !strings.HasPrefix(valid, apiKeyPrefix) {
		t.Fatal("a minted key must satisfy its own shape check")
	}
	if a, b := apiKeyPrefix+randomToken(), apiKeyPrefix+randomToken(); a == b {
		t.Fatal("minted keys must not repeat")
	}
}

func TestPermissionIntersection(t *testing.T) {
	for _, c := range []struct {
		name             string
		granted, ceiling []string
		want             string
	}{
		{"subset", []string{"events.read", "devices.manage"}, []string{"events.read"}, "events.read"},
		{"disjoint", []string{"events.read"}, []string{"audit.read"}, ""},
		{"ceiling wider than granted", []string{"events.read"}, []string{"events.read", "audit.read"}, "events.read"},
		{"empty ceiling", []string{"events.read"}, nil, ""},
		{"empty grant", nil, []string{"events.read"}, ""},
	} {
		got := strings.Join(intersect(c.granted, c.ceiling), ",")
		if got != c.want {
			t.Fatalf("%s: intersect gave %q wanted %q", c.name, got, c.want)
		}
	}
	// A key can only ever subtract: nothing outside the creator's live rights can
	// appear in the result, whatever the stored ceiling claims.
	if got := intersect([]string{"events.read"}, []string{"organizations.manage"}); len(got) != 0 {
		t.Fatalf("intersection invented a permission: %v", got)
	}
	if intersect(nil, nil) == nil {
		t.Fatal("intersect must return an empty slice, not nil, so it encodes as []")
	}
}

func TestAPIKeyLifetimeAllowlist(t *testing.T) {
	for _, days := range []int{30, 90, 365} {
		if !apiKeyLifetimes[days] {
			t.Fatalf("%d days must be accepted", days)
		}
	}
	for _, days := range []int{-1, 0, 1, 29, 31, 366, 3650} {
		if apiKeyLifetimes[days] {
			t.Fatalf("%d days must be refused", days)
		}
	}
}

// The key published for a demo is shown only there, and only when the operator
// put it in the environment: a customer instance meets neither condition, and a
// value forgotten in the environment of an instance that accepts writes must
// never become a displayed identifier.
func TestDemoMCPKeyIsKeptOnlyForAReadOnlyInstance(t *testing.T) {
	for _, c := range []struct {
		readOnly bool
		env      string
		want     string
		why      string
	}{
		{true, "mvk_demo", "mvk_demo", "une démonstration publie sa clé"},
		{true, "  mvk_demo  ", "mvk_demo", "les espaces d'un fichier d'environnement ne font pas partie de la clé"},
		{false, "mvk_demo", "", "une instance qui accepte les écritures n'affiche aucune clé"},
		{true, "", "", "sans clé configurée, rien à afficher"},
		{false, "", "", "le cas ordinaire"},
	} {
		t.Setenv("MILVAGO_DEMO_READONLY", map[bool]string{true: "1", false: "0"}[c.readOnly])
		t.Setenv("MILVAGO_DEMO_MCP_KEY", c.env)
		got, e := LoadConfig()
		if e != nil && got.DemoMCPKey != c.want {
			t.Fatalf("%s: configuration refusée (%v)", c.why, e)
		}
		if got.DemoMCPKey != c.want {
			t.Fatalf("%s: clé=%q, attendu %q", c.why, got.DemoMCPKey, c.want)
		}
	}
}

func TestMayGrantNonAmplification(t *testing.T) {
	session := &Session{Permissions: []string{"events.read", "devices.read"}}
	if session.mayGrant([]string{"organizations.manage"}) {
		t.Fatal("an interactive session must not grant permissions it lacks")
	}
	key := &Session{APIKeyID: "key", Permissions: []string{"events.read", "devices.read"}}
	if !key.mayGrant([]string{"events.read"}) {
		t.Fatal("a key may hand out what it holds")
	}
	if key.mayGrant([]string{"events.read", "organizations.manage"}) {
		t.Fatal("a key must not hand out a permission it does not hold")
	}
	if !key.mayGrant(nil) {
		t.Fatal("granting nothing is always allowed")
	}
}

// apiKeyTestState shares the request helpers across the API key subtests.
type apiKeyTestState struct {
	subsystemFixture
}

func (s *apiKeyTestState) call(method, path string, body any, cookie *http.Cookie, csrf, origin, bearer string) *httptest.ResponseRecorder {
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
	s.a.Handler().ServeHTTP(w, r)
	return w
}

func (s *apiKeyTestState) want(t *testing.T, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("HTTP %d wanted %d: %s", w.Code, status, w.Body.String())
	}
}

func (s *apiKeyTestState) owner(method, path string, body any) *httptest.ResponseRecorder {
	return s.call(method, path, body, s.cookie, s.csrf, s.a.config.AppURL, "")
}

// A key authenticates with the bearer alone: no cookie, no CSRF token and a
// hostile Origin, so every success also proves CSRF does not apply to this branch.
func (s *apiKeyTestState) key(method, path string, body any, secret string) *httptest.ResponseRecorder {
	return s.call(method, path, body, nil, "", "https://attacker.example", secret)
}

func (s *apiKeyTestState) code(w *httptest.ResponseRecorder) string {
	var body struct{ Error string }
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return body.Error
}

func (s *apiKeyTestState) mint(t *testing.T, name string, days int, permissions []string) (string, string) {
	t.Helper()
	w := s.owner("POST", "/api/profile/api-keys", map[string]any{"name": name, "expires_in_days": days, "permissions": permissions})
	s.want(t, w, 201)
	var created struct {
		Key    apiKeyView `json:"key"`
		Secret string     `json:"secret"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &created); e != nil {
		t.Fatal(e)
	}
	if created.Secret == "" || len(created.Secret) != apiKeyLength {
		t.Fatalf("creation must return the plaintext once: %q", created.Secret)
	}
	return created.Key.ID, created.Secret
}

func (s *apiKeyTestState) revoke(t *testing.T, id string) {
	t.Helper()
	s.want(t, s.owner("DELETE", "/api/profile/api-keys/"+id, nil), 200)
}

// guardMembership restores demotions and deletions even when a subtest fails.
func (s *apiKeyTestState) guardMembership(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	var role string
	if e := s.admin.QueryRow(ctx, `SELECT role FROM memberships WHERE organization_id=$1 AND user_id=$2`, s.org, s.user).Scan(&role); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if _, e := s.admin.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,$3)
			ON CONFLICT (organization_id,user_id) DO UPDATE SET role=EXCLUDED.role`, s.org, s.user, role); e != nil {
			t.Errorf("could not restore the membership fixture: %v", e)
		}
	})
}

// testAPIKeySubsystem is the integration half, called from
// TestDatabaseSecurityAndHTTP once a console session exists.
func testAPIKeySubsystem(t *testing.T, f subsystemFixture) {
	t.Helper()
	state := &apiKeyTestState{subsystemFixture: f}
	t.Run("the secret is returned once and stored only as a digest", func(t *testing.T) {
		testAPIKeySecretStorage(t, state)
	})

	t.Run("a key reaches the console surface without a cookie or CSRF token", func(t *testing.T) {
		testAPIKeyConsoleSurface(t, state)
	})

	t.Run("every rejection is indistinguishable", func(t *testing.T) {
		testAPIKeyUniformRejection(t, state)
	})

	t.Run("permissions are the live intersection, not a snapshot", func(t *testing.T) {
		testAPIKeyLivePermissions(t, state)
	})

	t.Run("a creator without a membership leaves the key inert", func(t *testing.T) {
		testAPIKeyOrphanCreator(t, state)
	})

	t.Run("a key cannot manage keys or reach interactive routes", func(t *testing.T) {
		testAPIKeyInteractiveRoutes(t, state)
	})

	t.Run("a header never falls back to the cookie", func(t *testing.T) {
		testAPIKeyHeaderPrecedence(t, state)
	})

	t.Run("creation is validated and capped", func(t *testing.T) {
		testAPIKeyCreationLimits(t, state)
	})

	t.Run("a key cannot be granted more than its creator holds", func(t *testing.T) {
		testAPIKeyCreatorCeiling(t, state)
	})

	t.Run("a key cannot hand out authority it lacks", func(t *testing.T) {
		testAPIKeyNonAmplification(t, state)
	})

	t.Run("a key never writes an instance level value", func(t *testing.T) {
		testAPIKeyInstanceSettings(t, state)
	})

	t.Run("the audit trail names the key", func(t *testing.T) {
		testAPIKeyAuditTrail(t, state)
	})

	t.Run("usage is recorded even for reads, and throttled", func(t *testing.T) {
		testAPIKeyUsageTimestamp(t, state)
	})

	t.Run("prompt content needs its own grant", func(t *testing.T) {
		testAPIKeyContentGrant(t, state)
	})

	t.Run("a human cannot grant authority it does not hold", func(t *testing.T) {
		testAPIKeyHumanGrantCeiling(t, state)
	})

	t.Run("prompt content is refused to a key without its own grant", func(t *testing.T) {
		testAPIKeyContentReadCeiling(t, state)
	})

	t.Run("the rate budget is per key", func(t *testing.T) {
		testAPIKeyRateBudget(t, state)
	})

	t.Run("keys are tenant isolated", func(t *testing.T) {
		testAPIKeyTenantIsolation(t, state)
	})

	t.Run("a key is refused by the endpoint protocols", func(t *testing.T) {
		testAPIKeyEndpointProtocols(t, state)
	})

	if Edition == "commercial" {
		t.Run("a key is pinned to one organization", func(t *testing.T) {
			testAPIKeyOrganizationPin(t, state)
		})
	}

	t.Run("a withdrawn identity loses its keys, an unreachable provider does not", func(t *testing.T) {
		testAPIKeyIdentityWithdrawal(t, state)
	})

	t.Run("the expiry ceiling is enforced by the database", func(t *testing.T) {
		testAPIKeyDatabaseExpiry(t, state)
	})
}

func testAPIKeySecretStorage(t *testing.T, s *apiKeyTestState) {
	t.Helper()
	admin := s.admin
	ctx := context.Background()
	want := s.want
	owner := s.owner
	mint := s.mint
	revoke := s.revoke

	id, secret := mint(t, "first key", 30, []string{"events.read"})
	defer revoke(t, id)
	w := owner("GET", "/api/profile/api-keys", nil)
	want(t, w, 200)
	if strings.Contains(w.Body.String(), secret) {
		t.Fatal("the list disclosed the secret")
	}
	// Not even a prefix of it: a fragment would narrow a brute force.
	if strings.Contains(w.Body.String(), secret[:16]) {
		t.Fatal("the list disclosed a fragment of the secret")
	}
	var digests int
	if e := admin.QueryRow(ctx, `SELECT count(*) FROM api_keys WHERE secret_hash=$1`, hash(secret)).Scan(&digests); e != nil || digests != 1 {
		t.Fatal("the digest was not stored exactly once", e)
	}
	var leaked int
	if e := admin.QueryRow(ctx, `SELECT count(*) FROM api_keys WHERE to_jsonb(api_keys.*)::text LIKE '%'||$1||'%'`, secret).Scan(&leaked); e != nil || leaked != 0 {
		t.Fatal("the plaintext appears somewhere in the row", e)
	}
}

func testAPIKeyConsoleSurface(t *testing.T, s *apiKeyTestState) {
	t.Helper()
	a := s.a
	ownerCookie := s.cookie
	call := s.call
	want := s.want
	key := s.key
	mint := s.mint
	revoke := s.revoke

	id, secret := mint(t, "reader", 30, []string{"overview.read", "events.read", "devices.read"})
	defer revoke(t, id)
	for _, path := range []string{"/api/overview", "/api/events", "/api/devices", "/api/session"} {
		want(t, key("GET", path, nil, secret), 200)
	}
	// The same mutation is refused for a cookie session with no CSRF token,
	// so the bearer branch has not weakened the cookie branch.
	want(t, call("POST", "/api/enrollments", map[string]string{"label": "no csrf"}, ownerCookie, "", a.config.AppURL, ""), 403)
}

func testAPIKeyUniformRejection(t *testing.T, s *apiKeyTestState) {
	t.Helper()
	admin := s.admin
	ctx := context.Background()
	want := s.want
	key := s.key
	mint := s.mint
	revoke := s.revoke

	id, secret := mint(t, "to be revoked", 30, []string{"overview.read"})
	want(t, key("GET", "/api/overview", nil, secret), 200)
	revoke(t, id)
	revoked := key("GET", "/api/overview", nil, secret)
	want(t, revoked, 401)

	expiredID, expiredSecret := mint(t, "to be expired", 30, []string{"overview.read"})
	defer revoke(t, expiredID)
	// created_at moves with it: the CHECK requires expires_at to sit after
	// creation and within a year of it, so a key can only be aged, never simply
	// back-dated. That the constraint refuses the naive form is itself covered
	// by "the expiry ceiling is enforced by the database".
	if _, e := admin.Exec(ctx, `UPDATE api_keys SET created_at=now()-interval '31 days',expires_at=now()-interval '1 second' WHERE id=$1`, expiredID); e != nil {
		t.Fatal(e)
	}
	expired := key("GET", "/api/overview", nil, expiredSecret)
	want(t, expired, 401)

	unknown := key("GET", "/api/overview", nil, apiKeyPrefix+randomToken())
	want(t, unknown, 401)
	malformed := key("GET", "/api/overview", nil, randomToken())
	want(t, malformed, 401)
	// One body for all four: the endpoint must not say which key is real.
	for _, w := range []*httptest.ResponseRecorder{expired, unknown, malformed} {
		if w.Body.String() != revoked.Body.String() {
			t.Fatalf("rejection reasons are distinguishable:\n%s\n%s", revoked.Body.String(), w.Body.String())
		}
	}
}

func testAPIKeyLivePermissions(t *testing.T, s *apiKeyTestState) {
	t.Helper()
	admin := s.admin
	org := s.org
	user := s.user
	ctx := context.Background()
	want := s.want
	key := s.key
	mint := s.mint
	revoke := s.revoke
	guardMembership := s.guardMembership

	guardMembership(t)
	id, secret := mint(t, "narrow", 30, []string{"events.read"})
	defer revoke(t, id)
	want(t, key("GET", "/api/events", nil, secret), 200)
	// Held by the creator but not chosen for the key.
	want(t, key("POST", "/api/enrollments", map[string]string{"label": "denied"}, secret), 403)

	wide, wideSecret := mint(t, "wide", 30, []string{"events.read", "devices.manage"})
	defer revoke(t, wide)
	want(t, key("POST", "/api/enrollments", map[string]string{"label": "allowed"}, wideSecret), 201)
	// Demote the creator: the key must shrink at once, with no revocation.
	if _, e := admin.Exec(ctx, `UPDATE memberships SET role='viewer' WHERE organization_id=$1 AND user_id=$2`, org, user); e != nil {
		t.Fatal(e)
	}
	want(t, key("POST", "/api/enrollments", map[string]string{"label": "now denied"}, wideSecret), 403)
	want(t, key("GET", "/api/events", nil, wideSecret), 200)
	if _, e := admin.Exec(ctx, `UPDATE memberships SET role='owner' WHERE organization_id=$1 AND user_id=$2`, org, user); e != nil {
		t.Fatal(e)
	}
	want(t, key("POST", "/api/enrollments", map[string]string{"label": "allowed again"}, wideSecret), 201)
}

func testAPIKeyOrphanCreator(t *testing.T, s *apiKeyTestState) {
	t.Helper()
	admin := s.admin
	org := s.org
	user := s.user
	ctx := context.Background()
	want := s.want
	key := s.key
	mint := s.mint
	revoke := s.revoke
	guardMembership := s.guardMembership

	guardMembership(t)
	id, secret := mint(t, "orphan", 30, []string{"overview.read"})
	defer revoke(t, id)
	var role string
	if e := admin.QueryRow(ctx, `DELETE FROM memberships WHERE organization_id=$1 AND user_id=$2 RETURNING role`, org, user).Scan(&role); e != nil {
		t.Fatal(e)
	}
	want(t, key("GET", "/api/overview", nil, secret), 403)
	if _, e := admin.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,$3)`, org, user, role); e != nil {
		t.Fatal(e)
	}
	want(t, key("GET", "/api/overview", nil, secret), 200)
}

func testAPIKeyInteractiveRoutes(t *testing.T, s *apiKeyTestState) {
	t.Helper()
	want := s.want
	owner := s.owner
	key := s.key
	code := s.code
	mint := s.mint
	revoke := s.revoke

	id, secret := mint(t, "self service denied", 30, []string{"overview.read", "content.read", "members.manage"})
	defer revoke(t, id)
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/api/profile/api-keys", nil},
		{"POST", "/api/profile/api-keys", map[string]any{"name": "forged", "expires_in_days": 365, "permissions": []string{"overview.read"}}},
		{"DELETE", "/api/profile/api-keys/" + id, nil},
		{"POST", "/auth/logout", nil},
		{"GET", "/api/profile", nil},
		{"PUT", "/api/profile", map[string]any{"language": "en"}},
	} {
		w := key(c.method, c.path, c.body, secret)
		want(t, w, 403)
		if code(w) != "session_required" {
			t.Fatalf("%s %s refused as %q, wanted session_required", c.method, c.path, code(w))
		}
	}
	// The same routes still work for the human.
	want(t, owner("GET", "/api/profile/api-keys", nil), 200)
	want(t, owner("GET", "/api/profile", nil), 200)
}

func testAPIKeyHeaderPrecedence(t *testing.T, s *apiKeyTestState) {
	t.Helper()
	a := s.a
	ownerCookie := s.cookie
	ownerCSRF := s.csrf
	call := s.call
	want := s.want
	mint := s.mint
	revoke := s.revoke

	id, secret := mint(t, "narrow again", 30, []string{"events.read"})
	defer revoke(t, id)
	// Cookie of an owner plus a narrow key: the key decides, so a route the
	// key lacks is refused even though the cookie would allow it.
	want(t, call("POST", "/api/enrollments", map[string]string{"label": "no"}, ownerCookie, ownerCSRF, a.config.AppURL, secret), 403)
	// A revoked key with a valid owner cookie must fail closed, not silently
	// execute as the human.
	dead, deadSecret := mint(t, "dead", 30, []string{"events.read"})
	revoke(t, dead)
	want(t, call("GET", "/api/overview", nil, ownerCookie, ownerCSRF, a.config.AppURL, deadSecret), 401)
	// A device-shaped credential in the header is not retried as a session.
	want(t, call("GET", "/api/overview", nil, ownerCookie, ownerCSRF, a.config.AppURL, randomToken()), 401)
}

func testAPIKeyCreationLimits(t *testing.T, s *apiKeyTestState) {
	t.Helper()
	admin := s.admin
	ctx := context.Background()
	want := s.want
	owner := s.owner
	code := s.code
	mint := s.mint
	revoke := s.revoke

	for _, body := range []map[string]any{
		{"name": "", "expires_in_days": 30, "permissions": []string{"events.read"}},
		{"name": strings.Repeat("x", 61), "expires_in_days": 30, "permissions": []string{"events.read"}},
		{"name": "badbell", "expires_in_days": 30, "permissions": []string{"events.read"}},
		{"name": "no expiry", "expires_in_days": 0, "permissions": []string{"events.read"}},
		{"name": "too long", "expires_in_days": 366, "permissions": []string{"events.read"}},
		{"name": "no permission", "expires_in_days": 30, "permissions": []string{}},
		{"name": "unknown", "expires_in_days": 30, "permissions": []string{"not.a.permission"}},
	} {
		want(t, owner("POST", "/api/profile/api-keys", body), 400)
	}
	var rows int
	if e := admin.QueryRow(ctx, `SELECT count(*) FROM api_keys WHERE name LIKE 'no %' OR name LIKE 'too %' OR name='unknown'`).Scan(&rows); e != nil || rows != 0 {
		t.Fatal("a refused creation left a row", e)
	}
	ids := []string{}
	for i := 0; i < apiKeyLimit; i++ {
		id, _ := mint(t, "capped "+string(rune('a'+i)), 30, []string{"overview.read"})
		ids = append(ids, id)
	}
	over := owner("POST", "/api/profile/api-keys", map[string]any{"name": "one too many", "expires_in_days": 30, "permissions": []string{"overview.read"}})
	want(t, over, 409)
	if code(over) != "api_key_limit" {
		t.Fatalf("cap refused as %q, wanted api_key_limit", code(over))
	}
	revoke(t, ids[0])
	extra, _ := mint(t, "room again", 30, []string{"overview.read"})
	ids = append(ids[1:], extra)
	for _, id := range ids {
		revoke(t, id)
	}
}

func testAPIKeyCreatorCeiling(t *testing.T, s *apiKeyTestState) {
	t.Helper()
	admin := s.admin
	org := s.org
	user := s.user
	ctx := context.Background()
	want := s.want
	owner := s.owner
	code := s.code
	guardMembership := s.guardMembership

	guardMembership(t)
	// Demote so the creator genuinely lacks something in the catalogue.
	if _, e := admin.Exec(ctx, `UPDATE memberships SET role='viewer' WHERE organization_id=$1 AND user_id=$2`, org, user); e != nil {
		t.Fatal(e)
	}
	w := owner("POST", "/api/profile/api-keys", map[string]any{"name": "over reach", "expires_in_days": 30, "permissions": []string{"organizations.manage"}})
	want(t, w, 403)
	if code(w) != "permission_not_held" {
		t.Fatalf("refused as %q, wanted permission_not_held", code(w))
	}
	if _, e := admin.Exec(ctx, `UPDATE memberships SET role='owner' WHERE organization_id=$1 AND user_id=$2`, org, user); e != nil {
		t.Fatal(e)
	}
}

func testAPIKeyNonAmplification(t *testing.T, s *apiKeyTestState) {
	t.Helper()
	admin := s.admin
	org := s.org
	ctx := context.Background()
	want := s.want
	owner := s.owner
	key := s.key
	code := s.code
	mint := s.mint
	revoke := s.revoke

	// The lateral escalation the per-request intersection does not cover: a
	// narrow key defining or assigning a broad role to a second account.
	id, secret := mint(t, "role maker", 30, []string{"events.read", "roles.manage", "members.manage"})
	defer revoke(t, id)
	w := key("POST", "/api/roles", map[string]any{"name": "smuggled", "permissions": []string{"organizations.manage"}}, secret)
	want(t, w, 403)
	if code(w) != "permission_not_held" {
		t.Fatalf("role creation refused as %q, wanted permission_not_held", code(w))
	}
	// Within its own ceiling it still works, so the rule is a bound and not a ban.
	want(t, key("POST", "/api/roles", map[string]any{"name": "within bounds", "permissions": []string{"events.read"}}, secret), 201)
	want(t, owner("DELETE", "/api/roles/within%20bounds", nil), 200)
	// The owner keeps the authority they always had.
	want(t, owner("POST", "/api/roles", map[string]any{"name": "owner made", "permissions": []string{"organizations.manage"}}), 201)
	want(t, owner("DELETE", "/api/roles/owner%20made", nil), 200)
	// Taking a role away is bounded like handing one out: a key whose creator is an
	// owner may not remove, or demote, a co-owner it could never have made owner.
	var coOwner string
	if e := admin.QueryRow(ctx, `INSERT INTO users(subject,email,display_name,identity_type) VALUES('key-co-owner','co-owner@example.test','Synthetic co-owner','local') RETURNING id`).Scan(&coOwner); e != nil {
		t.Fatal(e)
	}
	if _, e := admin.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, org, coOwner); e != nil {
		t.Fatal(e)
	}
	for _, attempt := range []*httptest.ResponseRecorder{key("DELETE", "/api/members/"+coOwner, nil, secret), key("PUT", "/api/members/"+coOwner+"/role", map[string]string{"role": "viewer"}, secret)} {
		want(t, attempt, 403)
		if code(attempt) != "permission_not_held" {
			t.Fatalf("co-owner change refused as %q, wanted permission_not_held", code(attempt))
		}
	}
	want(t, owner("DELETE", "/api/members/"+coOwner, nil), 200)
}

func testAPIKeyInstanceSettings(t *testing.T, s *apiKeyTestState) {
	t.Helper()
	admin := s.admin
	ctx := context.Background()
	want := s.want
	key := s.key
	mint := s.mint
	revoke := s.revoke

	id, secret := mint(t, "settings", 30, []string{"settings.manage"})
	defer revoke(t, id)
	w := key("GET", "/api/settings", nil, secret)
	want(t, w, 200)
	var view struct {
		PublicURLEditable       bool `json:"public_url_editable"`
		DefaultLanguageEditable bool `json:"default_language_editable"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &view); e != nil {
		t.Fatal(e)
	}
	if view.PublicURLEditable || view.DefaultLanguageEditable {
		t.Fatal("a key was told it may edit an instance level value")
	}
	var before string
	if e := admin.QueryRow(ctx, `SELECT public_url FROM app_config`).Scan(&before); e != nil {
		t.Fatal(e)
	}
	// Retention is legitimately hers; the agent-facing origin is not.
	want(t, key("PUT", "/api/settings", map[string]any{"name": "Test organization", "event_retention_days": 31, "public_url": "https://attacker.example"}, secret), 403)
	var after string
	if e := admin.QueryRow(ctx, `SELECT public_url FROM app_config`).Scan(&after); e != nil {
		t.Fatal(e)
	}
	if after != before {
		t.Fatalf("a key redirected the fleet: %q became %q", before, after)
	}
}

func testAPIKeyAuditTrail(t *testing.T, s *apiKeyTestState) {
	t.Helper()
	admin := s.admin
	user := s.user
	ctx := context.Background()
	want := s.want
	owner := s.owner
	key := s.key
	mint := s.mint
	revoke := s.revoke

	id, secret := mint(t, "auditor", 30, []string{"devices.manage"})
	defer revoke(t, id)
	want(t, key("POST", "/api/enrollments", map[string]string{"label": "audited"}, secret), 201)
	var attributed int
	if e := admin.QueryRow(ctx, `SELECT count(*) FROM audit WHERE api_key_id=$1 AND actor=$2`, id, user).Scan(&attributed); e != nil || attributed == 0 {
		t.Fatal("a key driven mutation was not attributed to the key", e)
	}
	want(t, owner("POST", "/api/enrollments", map[string]string{"label": "by hand"}), 201)
	var byHand int
	if e := admin.QueryRow(ctx, `SELECT count(*) FROM audit WHERE action='enrollment.create' AND api_key_id IS NULL`).Scan(&byHand); e != nil || byHand == 0 {
		t.Fatal("a cookie driven mutation must leave api_key_id null", e)
	}
	// Creating and revoking a key is itself only ever an interactive act.
	var selfMade int
	if e := admin.QueryRow(ctx, `SELECT count(*) FROM audit WHERE action IN ('api_key.create','api_key.revoke') AND api_key_id IS NOT NULL`).Scan(&selfMade); e != nil || selfMade != 0 {
		t.Fatal("a key appears to have managed keys", e)
	}
	if _, e := admin.Exec(ctx, `UPDATE audit SET api_key_id=NULL WHERE api_key_id=$1`, id); e == nil {
		t.Fatal("the audit trail accepted an update")
	}
}

func testAPIKeyUsageTimestamp(t *testing.T, s *apiKeyTestState) {
	t.Helper()
	admin := s.admin
	ctx := context.Background()
	want := s.want
	key := s.key
	mint := s.mint
	revoke := s.revoke

	id, secret := mint(t, "used", 30, []string{"overview.read"})
	defer revoke(t, id)
	var used *string
	if e := admin.QueryRow(ctx, `SELECT last_used_at::text FROM api_keys WHERE id=$1`, id).Scan(&used); e != nil || used != nil {
		t.Fatal("a fresh key must have no usage", e)
	}
	// A read rolls its request transaction back, so this also proves the write
	// does not ride on that transaction.
	want(t, key("GET", "/api/overview", nil, secret), 200)
	var first string
	if e := admin.QueryRow(ctx, `SELECT last_used_at::text FROM api_keys WHERE id=$1`, id).Scan(&first); e != nil || first == "" {
		t.Fatal("a read did not record usage", e)
	}
	want(t, key("GET", "/api/overview", nil, secret), 200)
	var second string
	if e := admin.QueryRow(ctx, `SELECT last_used_at::text FROM api_keys WHERE id=$1`, id).Scan(&second); e != nil {
		t.Fatal(e)
	}
	if second != first {
		t.Fatal("usage was rewritten inside the throttle window")
	}
	if _, e := admin.Exec(ctx, `UPDATE api_keys SET last_used_at=now()-interval '6 minutes' WHERE id=$1`, id); e != nil {
		t.Fatal(e)
	}
	want(t, key("GET", "/api/overview", nil, secret), 200)
	var third string
	if e := admin.QueryRow(ctx, `SELECT last_used_at::text FROM api_keys WHERE id=$1`, id).Scan(&third); e != nil {
		t.Fatal(e)
	}
	if third == second {
		t.Fatal("usage was not recorded once the throttle window passed")
	}
}

func testAPIKeyContentGrant(t *testing.T, s *apiKeyTestState) {
	t.Helper()
	admin := s.admin
	org := s.org
	user := s.user
	ctx := context.Background()
	want := s.want
	owner := s.owner
	mint := s.mint
	revoke := s.revoke
	guardMembership := s.guardMembership

	guardMembership(t)
	// The creator may read content — it is their role that says so since
	// 2026-09-15 — but a key that was not given the grant must not inherit it
	// just because its creator holds the right.
	w := owner("GET", "/api/profile/api-keys", nil)
	want(t, w, 200)
	var list struct {
		ContentAccessAvailable bool `json:"content_access_available"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &list); e != nil {
		t.Fatal(e)
	}
	if !list.ContentAccessAvailable {
		t.Fatal("the creator's role carries content.read but the panel was not told")
	}
	plain, _ := mint(t, "no content", 30, []string{"events.read"})
	defer revoke(t, plain)
	var stored bool
	if e := admin.QueryRow(ctx, `SELECT content_access FROM api_keys WHERE id=$1`, plain).Scan(&stored); e != nil || stored {
		t.Fatal("content access must be opt in", e)
	}
	granted, _ := mintWithContent(t, owner, want, "with content", []string{"events.read"})
	defer revoke(t, granted)
	// Once the creator's role no longer carries content.read, the key's own grant
	// is worth nothing — and a new one can no longer be minted with it.
	if _, e := admin.Exec(ctx, `UPDATE memberships SET role='viewer' WHERE organization_id=$1 AND user_id=$2`, org, user); e != nil {
		t.Fatal(e)
	}
	refused := owner("POST", "/api/profile/api-keys", map[string]any{"name": "cannot grant", "expires_in_days": 30, "permissions": []string{"events.read"}, "content_access": true})
	want(t, refused, 400)
}

func testAPIKeyHumanGrantCeiling(t *testing.T, s *apiKeyTestState) {
	t.Helper()
	admin := s.admin
	org := s.org
	user := s.user
	ctx := context.Background()
	want := s.want
	owner := s.owner
	guardMembership := s.guardMembership

	guardMembership(t)
	want(t, owner("POST", "/api/roles", map[string]any{"name": "high authority", "permissions": []string{"organizations.manage"}}), 201)
	// Managing roles stays with the built-in owner role: a custom role cannot carry it.
	want(t, owner("POST", "/api/roles", map[string]any{"name": "role manager", "permissions": []string{"roles.manage"}}), 400)
	want(t, owner("POST", "/api/roles", map[string]any{"name": "role operator", "permissions": []string{"members.manage", "overview.read", "events.read", "devices.read", "reports.aggregate"}}), 201)
	var second string
	if e := admin.QueryRow(ctx, "INSERT INTO users(subject,email,display_name) VALUES($1,$2,$3) RETURNING id", "synthetic-rbac", "synthetic-rbac@example.test", "Synthetic RBAC member").Scan(&second); e != nil {
		t.Fatal(e)
	}
	if tag, e := admin.Exec(ctx, "INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'viewer')", org, second); e != nil || tag.RowsAffected() != 1 {
		t.Fatal(e)
	}
	if tag, e := admin.Exec(ctx, "UPDATE memberships SET role='role operator' WHERE organization_id=$1 AND user_id=$2", org, user); e != nil || tag.RowsAffected() != 1 {
		t.Fatal(e)
	}
	want(t, owner("PUT", "/api/members/"+second+"/role", map[string]string{"role": "high authority"}), 403)
	want(t, owner("POST", "/api/members/invitations", map[string]string{"email": "blocked-before-identity@example.test", "role": "high authority"}), 403)
	want(t, owner("PUT", "/api/members/"+second+"/role", map[string]string{"role": "viewer"}), 200)
	for _, r := range []struct {
		method, path string
		body         any
	}{{"POST", "/api/roles", map[string]any{"name": "blocked role", "permissions": []string{"events.read"}}}, {"PUT", "/api/roles/high%20authority", map[string]any{"permissions": []string{"events.read"}}}, {"DELETE", "/api/roles/high%20authority", nil}} {
		want(t, owner(r.method, r.path, r.body), 403)
	}
	if tag, e := admin.Exec(ctx, "UPDATE memberships SET role='owner' WHERE organization_id=$1 AND user_id=$2", org, user); e != nil || tag.RowsAffected() != 1 {
		t.Fatal(e)
	}
	want(t, owner("DELETE", "/api/roles/role%20operator", nil), 200)
	want(t, owner("DELETE", "/api/roles/high%20authority", nil), 200)
}

func testAPIKeyContentReadCeiling(t *testing.T, s *apiKeyTestState) {
	t.Helper()
	admin := s.admin
	org := s.org
	user := s.user
	ctx := context.Background()
	want := s.want
	owner := s.owner
	key := s.key
	mint := s.mint
	revoke := s.revoke
	guardMembership := s.guardMembership

	guardMembership(t)
	device, event, prompt := seedAPIKeyContentFixture(t, s)
	// The creator's right to read content is their role. Demoting them to viewer
	// takes it away; owner carries content.read.
	setContent := func(value bool) {
		role := "viewer"
		if value {
			role = "owner"
		}
		tag, e := admin.Exec(ctx, "UPDATE memberships SET role=$1 WHERE organization_id=$2 AND user_id=$3", role, org, user)
		if e != nil || tag.RowsAffected() != 1 {
			t.Fatalf("content fixture update affected %d rows: %v", tag.RowsAffected(), e)
		}
	}
	read := func(secret string) map[string]json.RawMessage {
		w := key("GET", "/api/shadow/events/"+event+"?device_id="+device, nil, secret)
		want(t, w, 200)
		var body map[string]json.RawMessage
		if e := json.Unmarshal(w.Body.Bytes(), &body); e != nil {
			t.Fatal(e)
		}
		return body
	}
	setContent(true)
	plain, plainSecret := mint(t, "metadata only", 30, []string{"events.read"})
	defer revoke(t, plain)
	denied := read(plainSecret)
	if string(denied["can_read_content"]) != "false" || strings.Contains(string(denied["content"]), prompt) {
		t.Fatalf("metadata key received prompt content: %s", denied)
	}
	granted, grantedSecret := mintWithContent(t, owner, want, "content reader", []string{"events.read"})
	defer revoke(t, granted)
	allowed := read(grantedSecret)
	if string(allowed["can_read_content"]) != "true" || !strings.Contains(string(allowed["content"]), prompt) {
		t.Fatalf("content key did not receive plaintext: %s", allowed)
	}
	setContent(false)
	revoked := read(grantedSecret)
	if string(revoked["can_read_content"]) != "false" || strings.Contains(string(revoked["content"]), prompt) {
		t.Fatalf("revoked key received prompt content: %s", revoked)
	}
}

func seedAPIKeyContentFixture(t *testing.T, s *apiKeyTestState) (device, event, prompt string) {
	t.Helper()
	a, admin, org := s.a, s.admin, s.org
	ctx := context.Background()
	var originalPrivacy []byte
	if e := admin.QueryRow(ctx, "SELECT configuration FROM privacy_settings WHERE organization_id=$1", org).Scan(&originalPrivacy); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if tag, e := admin.Exec(ctx, "UPDATE privacy_settings SET configuration=$2 WHERE organization_id=$1", org, originalPrivacy); e != nil || tag.RowsAffected() != 1 {
			t.Fatal("privacy fixture restore failed", e)
		}
	})
	if tag, e := admin.Exec(ctx, `UPDATE privacy_settings SET configuration=configuration||'{"pseudonymous":false}'::jsonb WHERE organization_id=$1`, org); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("privacy fixture not applied", e)
	}
	if e := admin.QueryRow(ctx, "INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status) VALUES($1,$2,'content-fixture','test','1','approved') RETURNING id", org, hash(randomToken())).Scan(&device); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _, _ = admin.Exec(ctx, "DELETE FROM devices WHERE id=$1", device) })
	if e := admin.QueryRow(ctx, "INSERT INTO shadow_events(organization_id,device_id,id,occurred_at,kind,provider,tool,source,action,policy_revision,characters,sensitivity) VALUES($1,$2,gen_random_uuid(),now(),'prompt','openai','chatgpt','browser','observed',1,42,'normal') RETURNING id", org, device).Scan(&event); e != nil {
		t.Fatal(e)
	}
	prompt = "synthetic prompt content"
	sealed, e := a.sealShadow(org, "event:"+device+":"+event, []byte("{\"prompt\":\""+prompt+"\"}"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e := admin.Exec(ctx, "INSERT INTO shadow_content(organization_id,device_id,event_id,encrypted,expires_at) VALUES($1,$2,$3,$4,now()+interval '1 hour')", org, device, event, []byte(sealed)); e != nil {
		t.Fatal(e)
	}
	return device, event, prompt
}

func testAPIKeyRateBudget(t *testing.T, s *apiKeyTestState) {
	t.Helper()
	a := s.a
	want := s.want
	key := s.key
	code := s.code
	mint := s.mint
	revoke := s.revoke

	first, firstSecret := mint(t, "noisy", 30, []string{"overview.read"})
	defer revoke(t, first)
	second, secondSecret := mint(t, "quiet", 30, []string{"overview.read"})
	defer revoke(t, second)
	// The budget is spent by seeding the limiter rather than by issuing 600
	// real requests. Driving it over HTTP took several seconds and straddled
	// the limiter's fixed one-minute window, which resets the whole map: the
	// counter went back to zero mid-loop and the test passed or failed on
	// wall-clock luck. Seeding is deterministic and tests the same boundary.
	now := time.Now()
	if next := now.Truncate(time.Minute).Add(time.Minute); next.Sub(now) < 2*time.Second {
		// Too close to the turn for the seeded window to still be current when
		// the request lands.
		time.Sleep(next.Sub(now) + 100*time.Millisecond)
		now = time.Now()
	}
	for i := 0; i < apiKeyBudget; i++ {
		if !a.ingestRate.allow("apikey "+first, apiKeyBudget, now) {
			t.Fatalf("the budget was exhausted after %d of %d", i, apiKeyBudget)
		}
	}
	limited := key("GET", "/api/overview", nil, firstSecret)
	want(t, limited, 429)
	if code(limited) != "rate_limited" {
		t.Fatalf("bounded as %q, wanted rate_limited", code(limited))
	}
	// The counter is keyed on the key, so a second one is untouched.
	want(t, key("GET", "/api/overview", nil, secondSecret), 200)
}

func testAPIKeyTenantIsolation(t *testing.T, s *apiKeyTestState) {
	t.Helper()
	admin := s.admin
	org := s.org
	ctx := context.Background()

	// These settings are session scoped, not transaction local, and the admin
	// pool holds a single connection: leaving one behind poisons every later
	// query in the run rather than just this subtest. Restore unconditionally.
	t.Cleanup(func() {
		if _, e := admin.Exec(ctx, `SELECT set_config('milvago.organization_id',$1,false)`, org); e != nil {
			t.Errorf("could not restore the tenant context: %v", e)
		}
	})
	if _, e := admin.Exec(ctx, `SELECT set_config('milvago.organization_id','',false)`); e != nil {
		t.Fatal(e)
	}
	var visible int
	if e := admin.QueryRow(ctx, `SELECT count(*) FROM api_keys`).Scan(&visible); e != nil || visible != 0 {
		t.Fatal("the table owner bypassed FORCE row level security on api_keys", e)
	}
	if _, e := admin.Exec(ctx, `SELECT set_config('milvago.organization_id',$1,false)`, org); e != nil {
		t.Fatal(e)
	}
	// The cross-tenant lookup answers nothing for a digest it has never seen,
	// and exposes exactly two columns.
	var columns string
	if e := admin.QueryRow(ctx, `SELECT pg_get_function_result(oid) FROM pg_proc WHERE proname='api_key_identity'`).Scan(&columns); e != nil {
		t.Fatal(e)
	}
	for _, forbidden := range []string{"permissions", "content_access", "name", "secret_hash"} {
		if strings.Contains(columns, forbidden) {
			t.Fatalf("api_key_identity returns %s before a tenant context exists: %s", forbidden, columns)
		}
	}
	var rows int
	if e := admin.QueryRow(ctx, `SELECT count(*) FROM api_key_identity($1)`, hash("never issued")).Scan(&rows); e != nil || rows != 0 {
		t.Fatal("the lookup answered for an unknown digest", e)
	}
}

func testAPIKeyEndpointProtocols(t *testing.T, s *apiKeyTestState) {
	t.Helper()
	a := s.a
	call := s.call
	key := s.key
	mint := s.mint
	revoke := s.revoke

	id, secret := mint(t, "wrong door", 30, []string{"overview.read", "events.read"})
	defer revoke(t, id)
	// The device credential header is a bare 43-character token and is length
	// checked with ==, so a prefixed key cannot be mistaken for one. Proving it
	// per route matters because these paths never pass through the console
	// wrapper and have their own resolver.
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/v1/policy", nil},
		{"POST", "/v1/events", map[string]any{"events": []any{}}},
		{"GET", "/v2/policy", nil},
		{"POST", "/v2/events", map[string]any{"events": []any{}}},
		{"GET", "/v3/policy", nil},
	} {
		w := key(c.method, c.path, c.body, secret)
		// Never a success. The assertion is deliberately "not 2xx" rather than
		// "401", because the ingestion handlers decode and validate the request
		// body before they authenticate (endpoint.go, ingestRequest), so an
		// unauthenticated caller is refused as 400 on the payload before the
		// credential is ever examined. That ordering is pre-existing and out of
		// scope here, but it means a 400 is also a refusal, not an acceptance.
		if w.Code >= 200 && w.Code < 300 {
			t.Fatalf("%s %s accepted an API key with HTTP %d: %s", c.method, c.path, w.Code, w.Body.String())
		}
	}
	// An API key is not the metrics token either. The token has to be
	// configured for the assertion to mean anything: left empty,
	// metricTokenAllowed admits any caller, so /metrics would answer an
	// anonymous request too and the key would prove nothing. (That the
	// unconfigured case is open at all is pre-existing and outside this
	// feature.)
	previous := a.config.MetricsToken
	a.config.MetricsToken = "metrics-" + randomToken()
	defer func() { a.config.MetricsToken = previous }()
	if w := key("GET", "/metrics", nil, secret); w.Code == 200 {
		t.Fatal("an API key was accepted as the metrics token")
	}
	if w := call("GET", "/metrics", nil, nil, "", "", a.config.MetricsToken); w.Code != 200 {
		t.Fatalf("the configured metrics token stopped working: HTTP %d", w.Code)
	}
}

func testAPIKeyOrganizationPin(t *testing.T, s *apiKeyTestState) {
	t.Helper()
	admin := s.admin
	ownerCookie := s.cookie
	org := s.org
	ctx := context.Background()
	want := s.want
	owner := s.owner
	key := s.key
	mint := s.mint
	revoke := s.revoke

	// A child organization the creator legitimately owns through the
	// hierarchy: a cookie session may act on it, a key never may.
	w := owner("POST", "/api/organizations", map[string]string{"name": "Pinned child"})
	want(t, w, 201)
	var child Organization
	if e := json.Unmarshal(w.Body.Bytes(), &child); e != nil {
		t.Fatal(e)
	}
	id, secret := mint(t, "parent scoped", 30, []string{"overview.read", "installers.manage", "organizations.manage"})
	defer revoke(t, id)
	// The cookie can reach the child, which is what makes the refusal below
	// a statement about the key and not about the creator's rights.
	want(t, owner("GET", "/api/organizations/"+child.ID+"/deployment-key", nil), 200)
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/api/organizations/" + child.ID + "/deployment-key", nil},
		{"POST", "/api/organizations/" + child.ID + "/deployment-key/rotate", nil},
		{"POST", "/api/organizations/" + child.ID + "/deployment-key/revoke", nil},
		{"PUT", "/api/organizations/" + child.ID, map[string]string{"name": "Renamed by key"}},
		{"DELETE", "/api/organizations/" + child.ID, nil},
		{"POST", "/api/organizations", map[string]any{"name": "Grandchild", "parent_id": child.ID}},
		{"POST", "/api/session/organization", map[string]string{"organization_id": child.ID}},
	} {
		w := key(c.method, c.path, c.body, secret)
		if w.Code != 403 {
			t.Fatalf("%s %s let a key leave its organization with HTTP %d: %s", c.method, c.path, w.Code, w.Body.String())
		}
	}
	// Creating makes the creator owner of the new organization, every permission
	// included: a key without them cannot, even in its own organization.
	if w := key("POST", "/api/organizations", map[string]any{"name": "Key-made child", "parent_id": org}, secret); w.Code != 403 || !strings.Contains(w.Body.String(), "permission_not_held") {
		t.Fatalf("a narrow key created an organization it would own: HTTP %d %s", w.Code, w.Body.String())
	}
	var name string
	if e := admin.QueryRow(ctx, `SELECT name FROM organizations WHERE id=$1`, child.ID).Scan(&name); e != nil || name != "Pinned child" {
		t.Fatal("a key renamed an organization it is not pinned to", e, name)
	}
	assertAPIKeySQLPin(t, s, child.ID)
	// Deleting an organization takes a fresh second factor.
	want(t, owner("DELETE", "/api/organizations/"+child.ID, nil), 403)
	if _, e := admin.Exec(ctx, `UPDATE sessions SET mfa=true,mfa_verified_at=clock_timestamp() WHERE token_hash=$1`, hash(ownerCookie.Value)); e != nil {
		t.Fatal(e)
	}
	want(t, owner("DELETE", "/api/organizations/"+child.ID, nil), 200)
	if _, e := admin.Exec(ctx, `UPDATE sessions SET mfa=false,mfa_verified_at=NULL WHERE token_hash=$1`, hash(ownerCookie.Value)); e != nil {
		t.Fatal(e)
	}
}

func assertAPIKeySQLPin(t *testing.T, s *apiKeyTestState, childID string) {
	t.Helper()
	admin, org, user := s.admin, s.org, s.user
	ctx := context.Background()
	var name string
	// The pin is enforced in SQL too, so a handler that forgot the helper
	// still fails closed.
	var rows int
	t.Cleanup(func() {
		if _, e := admin.Exec(ctx, `SELECT set_config('milvago.api_key_org','',false)`); e != nil {
			t.Errorf("could not clear the API key organization pin: %v", e)
		}
	})
	if e := admin.QueryRow(ctx, `SELECT set_config('milvago.api_key_org',$1,false)`, org).Scan(&name); e != nil {
		t.Fatal(e)
	}
	if e := admin.QueryRow(ctx, `SELECT count(*) FROM effective_access($1,$2)`, user, childID).Scan(&rows); e != nil || rows != 0 {
		t.Fatal("effective_access answered outside the pinned organization", e, rows)
	}
	if _, e := admin.Exec(ctx, `SELECT set_config('milvago.api_key_org','',false)`); e != nil {
		t.Fatal(e)
	}
	if e := admin.QueryRow(ctx, `SELECT count(*) FROM effective_access($1,$2)`, user, childID).Scan(&rows); e != nil || rows == 0 {
		t.Fatal("the pin leaked into a cookie session", e)
	}
}

func testAPIKeyIdentityWithdrawal(t *testing.T, s *apiKeyTestState) {
	t.Helper()
	a := s.a
	admin := s.admin
	user := s.user
	p := s.identity
	ctx := context.Background()
	want := s.want
	owner := s.owner
	key := s.key
	mint := s.mint

	var subject string
	if e := admin.QueryRow(ctx, `SELECT subject FROM users WHERE id=$1`, user).Scan(&subject); e != nil {
		t.Fatal(e)
	}
	// The sweep reads the provider, so the account has to exist there.
	p.seedUser(&fakeUser{ID: subject, Username: "owner", Email: "admin@example.test"})
	t.Cleanup(func() { p.setUserDisabled(subject, false) })
	oldID, oldSecret, oldIssuer := a.config.AdminClientID, a.config.AdminClientSecret, a.config.Issuer
	t.Cleanup(func() {
		a.config.AdminClientID, a.config.AdminClientSecret, a.config.Issuer = oldID, oldSecret, oldIssuer
	})

	// No deferred revoke on either key below: the sweep revoking them is the
	// expected outcome, and a DELETE on an already revoked key answers 404.
	id, secret := mint(t, "offboarding", 30, []string{"overview.read"})
	want(t, key("GET", "/api/overview", nil, secret), 200)

	// 1. Identity administration not configured. The sweep must do nothing:
	//    revocation is irreversible and fleet-wide, so an outage must never
	//    destroy every key in the deployment.
	a.config.AdminClientID, a.config.AdminClientSecret = "", ""
	a.revokeWithdrawnIdentities(ctx)
	want(t, key("GET", "/api/overview", nil, secret), 200)

	// 2. Configured and reachable, account in good standing: still nothing.
	a.config.AdminClientID, a.config.AdminClientSecret = "test-management", "test-secret"
	a.config.Issuer = oldIssuer + "/realms/test"
	a.revokeWithdrawnIdentities(ctx)
	want(t, key("GET", "/api/overview", nil, secret), 200)

	// 3. Provider reachable but refusing, which is what a wrong realm or a
	//    revoked service account looks like. Errors are not verdicts.
	a.config.Issuer = oldIssuer + "/realms/absent"
	a.revokeWithdrawnIdentities(ctx)
	want(t, key("GET", "/api/overview", nil, secret), 200)
	a.config.Issuer = oldIssuer + "/realms/test"

	// 4. Disabled in the directory: the realistic offboarding action.
	p.setUserDisabled(subject, true)
	a.revokeWithdrawnIdentities(ctx)
	want(t, key("GET", "/api/overview", nil, secret), 401)
	var revoked bool
	if e := admin.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM api_keys WHERE id=$1`, id).Scan(&revoked); e != nil || !revoked {
		t.Fatal("the key was refused but not actually revoked", e)
	}
	var audited int
	if e := admin.QueryRow(ctx, `SELECT count(*) FROM audit WHERE action='api_key.identity_withdrawn' AND actor=$1 AND api_key_id IS NULL`, user).Scan(&audited); e != nil || audited == 0 {
		t.Fatal("the withdrawal left no audit trail", e)
	}
	// Re-enabling does not resurrect it: revocation is final by design.
	p.setUserDisabled(subject, false)
	want(t, key("GET", "/api/overview", nil, secret), 401)

	// 5. Deleted outright.
	_, secondSecret := mint(t, "offboarding deleted", 30, []string{"overview.read"})
	want(t, key("GET", "/api/overview", nil, secondSecret), 200)
	removed := p.removeUser(subject)
	a.revokeWithdrawnIdentities(ctx)
	want(t, key("GET", "/api/overview", nil, secondSecret), 401)
	if removed != nil {
		p.seedUser(removed)
	}
	// A cookie session is unaffected by this sweep -- it has its own mechanism.
	want(t, owner("GET", "/api/profile/api-keys", nil), 200)
}

func testAPIKeyDatabaseExpiry(t *testing.T, s *apiKeyTestState) {
	t.Helper()
	admin := s.admin
	org := s.org
	user := s.user
	ctx := context.Background()

	if _, e := admin.Exec(ctx, `INSERT INTO api_keys(organization_id,user_id,name,secret_hash,permissions,expires_at) VALUES($1,$2,'forged',$3,ARRAY['events.read'],now()+interval '400 days')`, org, user, hash(randomToken())); e == nil {
		t.Fatal("the database accepted a key outliving the ceiling")
	}
	if _, e := admin.Exec(ctx, `INSERT INTO api_keys(organization_id,user_id,name,secret_hash,permissions,expires_at) VALUES($1,$2,'backdated',$3,ARRAY['events.read'],now()-interval '1 day')`, org, user, hash(randomToken())); e == nil {
		t.Fatal("the database accepted a key that expires before it exists")
	}
}

// mintWithContent creates a key carrying the prompt-content grant, which the
// plain mint helper deliberately never sets.
func mintWithContent(t *testing.T, owner func(string, string, any) *httptest.ResponseRecorder, want func(*testing.T, *httptest.ResponseRecorder, int), name string, permissions []string) (string, string) {
	t.Helper()
	w := owner("POST", "/api/profile/api-keys", map[string]any{"name": name, "expires_in_days": 30, "permissions": permissions, "content_access": true})
	want(t, w, 201)
	var created struct {
		Key    apiKeyView `json:"key"`
		Secret string     `json:"secret"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &created); e != nil {
		t.Fatal(e)
	}
	return created.Key.ID, created.Secret
}
