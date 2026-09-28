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
	"strings"
	"testing"
	"time"
)

// projectionSentinels are identity values planted in one organization. While
// the subject is not revealed, none of them may appear in any projection: a
// route body, an export, a report, an MCP answer or an observability payload.
// Administration identities (console members) are a separate identity system
// and are deliberately not sentinels.
type projectionSentinels struct {
	name, email, subject, host, osUser, eventUser, team, file string
}

func (p projectionSentinels) all() []string {
	return []string{p.name, p.email, p.subject, p.host, p.osUser, p.eventUser, p.team, p.file}
}

type projectionFixture struct {
	*observabilityFixture
	s                             projectionSentinels
	subject, device, event, group string
	// key is an owner API key carrying the whole permission catalog.
	key      string
	sessions map[string]*http.Cookie
	csrfs    map[string]string
}

var projectionActors = []string{"owner", "admin", "viewer", "reporter", "key"}

func newProjectionFixture(t *testing.T) *projectionFixture {
	t.Helper()
	f := newObservabilityFixture(t)
	ctx := context.Background()
	tag := fmt.Sprintf("%08X", time.Now().UnixNano()&0xFFFFFFFF)
	p := &projectionFixture{observabilityFixture: f, sessions: map[string]*http.Cookie{}, csrfs: map[string]string{}}
	p.s = projectionSentinels{name: "SENTINEL-NAME-" + tag, email: "sentinel-" + strings.ToLower(tag) + "@example.test", subject: "sentinel-oidc-" + tag, host: "SENTINEL-HOST-" + tag, osUser: "SENTINEL-OSUSER-" + tag, eventUser: "SENTINEL-EVENTUSER-" + tag, team: "SENTINEL-TEAM-" + tag, file: "SENTINEL-FILE-" + tag + ".docx"}
	if tag, e := f.admin.Exec(ctx, "UPDATE sessions SET mfa_verified_at=clock_timestamp() WHERE token_hash=$1", hash(f.owner.Value)); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("fresh authentication fixture missing", e)
	}
	tx, e := tenantTx(ctx, f.a.db, f.org)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if p.subject, e = f.a.associateIdentity(ctx, tx, f.org, p.s.subject, p.s.email, p.s.name); e != nil {
		t.Fatal(e)
	}
	if tag, e := tx.Exec(ctx, "UPDATE collaborators SET team=$2 WHERE id=$1", p.subject, p.s.team); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("team fixture missing", e)
	}
	if e = tx.QueryRow(ctx, "INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status) VALUES($1,$2,'','test','0.5.0','approved') RETURNING id", f.org, hash(randomToken())).Scan(&p.device); e != nil {
		t.Fatal(e)
	}
	if e = f.a.storeDeviceName(ctx, tx, f.org, p.device, p.s.host); e != nil {
		t.Fatal(e)
	}
	// The device belongs to a group so the group policy route has a row to serve.
	if e = tx.QueryRow(ctx, "INSERT INTO device_groups(organization_id,name) VALUES($1,'Projection group') RETURNING id", f.org).Scan(&p.group); e != nil {
		t.Fatal(e)
	}
	if tag, e := tx.Exec(ctx, "UPDATE devices SET group_id=$2,group_revision=nextval('shadow_revision') WHERE id=$1", p.device, p.group); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("group fixture missing", e)
	}
	sealedUser, e := f.a.sealIdentity(f.org, "device-user:"+p.device, p.s.osUser)
	if e != nil {
		t.Fatal(e)
	}
	if tag, e := tx.Exec(ctx, "UPDATE devices SET os_user=$2 WHERE id=$1", p.device, sealedUser); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("os user fixture missing", e)
	}
	files, _ := json.Marshal([]string{p.s.file})
	if e = tx.QueryRow(ctx, "INSERT INTO shadow_events(organization_id,device_id,id,occurred_at,kind,provider,tool,source,action,policy_revision,characters,sensitivity,collaborator_id,files) VALUES($1,$2,gen_random_uuid(),now()-interval '1 minute','prompt','claude.ai','chrome','browser','observed',1,42,'unknown',$3,$4) RETURNING id", f.org, p.device, p.subject, files).Scan(&p.event); e != nil {
		t.Fatal(e)
	}
	sealedEventUser, e := f.a.sealIdentity(f.org, "event-user:"+p.device+":"+p.event, p.s.eventUser)
	if e != nil {
		t.Fatal(e)
	}
	if tag, e := tx.Exec(ctx, `UPDATE shadow_events SET "user"=$2 WHERE id=$1`, p.event, sealedEventUser); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("event user fixture missing", e)
	}
	if _, e = tx.Exec(ctx, "INSERT INTO events(organization_id,device_id,id,occurred_at,provider,action,source,characters,labels) VALUES($1,$2,gen_random_uuid(),now(),'claude.ai','observed','browser',10,'[]')", f.org, p.device); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	for _, role := range []string{"admin", "viewer", "reporter"} {
		var user string
		if e = f.admin.QueryRow(ctx, "INSERT INTO users(subject,email,display_name) VALUES($1,$2,$3) RETURNING id", "projection-"+role, role+"@example.test", "Projection "+role).Scan(&user); e != nil {
			t.Fatal(e)
		}
		if _, e = f.admin.Exec(ctx, "INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,$3)", f.org, user, role); e != nil {
			t.Fatal(e)
		}
		token, csrf := randomToken(), randomToken()
		if _, e = f.admin.Exec(ctx, `INSERT INTO sessions(token_hash,user_id,organization_id,csrf_token,encrypted_tokens,mfa,expires_at,identity_expires_at) VALUES($1,$2,$3,$4,$5,true,$6,$6)`, hash(token), user, f.org, csrf, []byte("synthetic-session"), time.Now().Add(time.Hour)); e != nil {
			t.Fatal(e)
		}
		p.sessions[role] = &http.Cookie{Name: cookieName("session"), Value: token}
		p.csrfs[role] = csrf
	}
	p.sessions["owner"], p.csrfs["owner"] = f.owner, f.csrf
	w := f.call("POST", "/api/profile/api-keys", map[string]any{"name": "projection audit", "expires_in_days": 30, "permissions": permissionCatalog}, f.csrf)
	requireHTTP(t, w, 201)
	var created struct {
		Secret string `json:"secret"`
	}
	if e = json.Unmarshal(w.Body.Bytes(), &created); e != nil || created.Secret == "" {
		t.Fatal("api key fixture missing", e)
	}
	p.key = created.Secret
	return p
}

// as performs one request as the named actor: a console session with its CSRF
// token, or the owner's API key as a bearer credential without any cookie.
func (p *projectionFixture) as(actor, method, path string, body any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(method, path, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", p.a.config.AppURL)
	if actor == "key" {
		r.Header.Set("Authorization", "Bearer "+p.key)
	} else {
		r.Header.Set("X-CSRF-Token", p.csrfs[actor])
		r.AddCookie(p.sessions[actor])
	}
	w := httptest.NewRecorder()
	p.a.Handler().ServeHTTP(w, r)
	return w
}

// scan fails when a sentinel appears in a body, case-insensitively, except the
// ones a caller declares legitimate for that projection.
func (p *projectionFixture) scan(t *testing.T, where string, body []byte, legitimate ...string) {
	t.Helper()
	upper := strings.ToUpper(string(body))
	for _, s := range p.s.all() {
		if slices.Contains(legitimate, s) {
			continue
		}
		if strings.Contains(upper, strings.ToUpper(s)) {
			excerpt := string(body)
			if len(excerpt) > 600 {
				excerpt = excerpt[:600] + "…"
			}
			t.Fatalf("%s discloses %q: %s", where, s, excerpt)
		}
	}
}

// projectionRoute is one line of the audit table. Every registered console route
// must appear here exactly once: either exercised (path set) or exempt with a
// written reason. Extra lines without a pattern are variants of a route.
type projectionRoute struct {
	pattern string
	path    string
	// expect is the status the owner session must obtain, 0 when any status is
	// acceptable (the body is scanned regardless). Without it a refusal would
	// read as a passed check.
	expect int
	exempt string
	// optional marks a route registered in one edition only.
	optional bool
	// legitimate lists sentinels the projection may carry by design.
	legitimate []string
}

func (p *projectionFixture) routes() []projectionRoute {
	detail := "/api/shadow/events/" + p.event + "?device_id=" + p.device
	thread := "/api/shadow/conversation?key=event:" + p.event + "&device_id=" + p.device
	return []projectionRoute{
		{pattern: "POST /auth/logout", exempt: "session mutation"},
		{pattern: "GET /api/session", path: "/api/session", expect: 200},
		{pattern: "GET /api/profile", path: "/api/profile", expect: 200},
		{pattern: "PUT /api/profile", exempt: "mutation of the caller's own profile"},
		{pattern: "GET /api/overview", path: "/api/overview", expect: 200},
		{pattern: "GET /api/events", path: "/api/events", expect: 200},
		{pattern: "GET /api/devices", path: "/api/devices", expect: 200},
		{pattern: "POST /api/enrollments", exempt: "mutation"},
		{pattern: "POST /api/devices/{id}/approve", exempt: "mutation"},
		{pattern: "POST /api/devices/{id}/revoke", exempt: "mutation"},
		{pattern: "DELETE /api/devices/{id}", exempt: "mutation"},
		{pattern: "GET /api/members", path: "/api/members", expect: 200},
		{pattern: "GET /api/roles", path: "/api/roles", expect: 200},
		{pattern: "POST /api/roles", exempt: "mutation"},
		{pattern: "PUT /api/roles/{name}", exempt: "mutation"},
		{pattern: "DELETE /api/roles/{name}", exempt: "mutation"},
		{pattern: "GET /api/roles/{name}/members", path: "/api/roles/viewer/members", expect: 200},
		{pattern: "POST /api/members/invitations", exempt: "mutation"},
		{pattern: "PUT /api/members/{id}/role", exempt: "mutation"},
		{pattern: "PUT /api/members/{id}/language", exempt: "mutation"},
		{pattern: "DELETE /api/members/{id}", exempt: "mutation"},
		{pattern: "GET /api/audit", path: "/api/audit", expect: 200},
		{pattern: "GET /api/settings", path: "/api/settings", expect: 200},
		{pattern: "PUT /api/settings", exempt: "mutation"},
		{pattern: "PUT /api/license", exempt: "mutation"},
		{pattern: "POST /api/license/request", exempt: "mutation"},
		{pattern: "GET /api/detection/catalog", path: "/api/detection/catalog", expect: 200},
		{pattern: "PUT /api/detection/catalog", exempt: "mutation"},
		{pattern: "POST /api/detection/catalog/import", exempt: "signed catalogue preview/publication contains declarative configuration only; covered by TestDetectionCatalogImport"},
		{pattern: "GET /api/detection/health", path: "/api/detection/health", expect: 200},
		{pattern: "GET /api/detection/candidates", path: "/api/detection/candidates", expect: 200},
		{pattern: "PATCH /api/detection/candidates", exempt: "mutation"},
		{pattern: "GET /api/detection/candidates/{domain}/devices", exempt: "names the machines behind a candidate domain by design, under the same machineName projection as /api/devices; gates covered by TestCandidateDomainDevices", optional: true},
		{pattern: "GET /api/detection/platforms/{provider}/devices", exempt: "names the machines behind a known platform by design, same projection and same gates; covered by TestKnownPlatformDevices", optional: true},
		{pattern: "GET /api/detection/platforms", path: "/api/detection/platforms", expect: 200},
		{pattern: "PATCH /api/detection/platforms", exempt: "mutation"},
		{pattern: "GET /api/privacy", path: "/api/privacy", expect: 200},
		{pattern: "PUT /api/privacy", exempt: "mutation"},
		{pattern: "POST /api/subjects/{id}/reveal", exempt: "discloses by design under identity.reveal, fresh MFA and audit; covered by TestPrivacyIntegration"},
		{pattern: "DELETE /api/subjects/{id}", exempt: "mutation"},
		{pattern: "POST /api/privacy/alias-key/rotate", exempt: "mutation"},
		{pattern: "POST " + mcpPath, exempt: "answers an API key, never a browser session: the sweep's console actors cannot reach it, and what it may disclose is settled per tool by the key's own permissions; covered by TestMCPToolCatalogMatchesConsoleRoutes and the mcp_*_commercial tests", optional: true},
		{pattern: "GET /api/shadow/aggregate", path: "/api/shadow/aggregate", expect: 200, legitimate: []string{p.s.team}},
		{pattern: "GET /api/profile/api-keys", path: "/api/profile/api-keys", expect: 200},
		{pattern: "POST /api/profile/api-keys", exempt: "mutation"},
		{pattern: "DELETE /api/profile/api-keys/{id}", exempt: "mutation"},
		{pattern: "GET /api/settings/ldap", path: "/api/settings/ldap", optional: true},
		{pattern: "PUT /api/settings/ldap", exempt: "mutation", optional: true},
		{pattern: "DELETE /api/settings/ldap", exempt: "mutation", optional: true},
		{pattern: "POST /api/settings/ldap/test", exempt: "mutation", optional: true},
		{pattern: "GET /api/settings/sso", path: "/api/settings/sso", optional: true},
		{pattern: "PUT /api/settings/sso/{provider}", exempt: "mutation", optional: true},
		{pattern: "DELETE /api/settings/sso/{provider}", exempt: "mutation", optional: true},
		{pattern: "GET /api/members/directory", path: "/api/members/directory?query=sentinel", optional: true},
		{pattern: "POST /api/members/directory", exempt: "mutation", optional: true},
		{pattern: "GET /api/deployment-key", path: "/api/deployment-key"},
		{pattern: "POST /api/deployment-key/rotate", exempt: "mutation"},
		{pattern: "POST /api/deployment-key/revoke", exempt: "mutation"},
		{pattern: "GET /api/installer/{platform}", path: "/api/installer/windows"},
		{pattern: "GET /api/organizations/{id}/deployment-key", path: "/api/organizations/" + p.org + "/deployment-key", optional: true},
		{pattern: "POST /api/organizations/{id}/deployment-key/rotate", exempt: "mutation", optional: true},
		{pattern: "POST /api/organizations/{id}/deployment-key/revoke", exempt: "mutation", optional: true},
		{pattern: "GET /api/model-access/status", path: "/api/model-access/status", optional: true},
		{pattern: "GET /api/shadow/settings", path: "/api/shadow/settings", expect: 200},
		{pattern: "PUT /api/shadow/settings", exempt: "mutation"},
		{pattern: "GET /api/devices/{id}/shadow", path: "/api/devices/" + p.device + "/shadow", expect: 200},
		{pattern: "PUT /api/devices/{id}/shadow", exempt: "mutation"},
		{pattern: "GET /api/groups", path: "/api/groups", expect: 200},
		{pattern: "POST /api/groups", exempt: "mutation"},
		{pattern: "PUT /api/groups/{id}", exempt: "mutation"},
		{pattern: "DELETE /api/groups/{id}", exempt: "mutation"},
		{pattern: "PUT /api/devices/{id}/group", exempt: "mutation"},
		{pattern: "GET /api/groups/{id}/shadow", path: "/api/groups/" + p.group + "/shadow", expect: 200},
		{pattern: "PUT /api/groups/{id}/shadow", exempt: "mutation"},
		{pattern: "GET /api/shadow/events", path: "/api/shadow/events", expect: 200},
		{path: "/api/shadow/events?actor_id=" + p.subject, expect: 200},
		{path: "/api/shadow/events?device_id=" + p.device, expect: 200},
		{pattern: "GET /api/shadow/events/{id}", path: detail, expect: 200},
		{pattern: "GET /api/shadow/conversations", path: "/api/shadow/conversations", expect: 200},
		{pattern: "GET /api/shadow/conversation", path: thread, expect: 200},
		{pattern: "GET /api/shadow/cartography", path: "/api/shadow/cartography", expect: 200},
		{path: "/api/shadow/cartography?actor_id=" + p.subject, expect: 200},
		{pattern: "GET /api/shadow/filters", path: "/api/shadow/filters", expect: 200},
		{pattern: "POST /api/shadow/filters", exempt: "mutation"},
		{pattern: "PUT /api/shadow/filters/{id}", exempt: "mutation"},
		{pattern: "DELETE /api/shadow/filters/{id}", exempt: "mutation"},
		{pattern: "GET /api/shadow/export", path: "/api/shadow/export?format=json", expect: 200},
		{path: "/api/shadow/export?format=csv", expect: 200},
		{pattern: "POST /api/shadow/content/purge", exempt: "mutation"},
		{pattern: "GET /api/shadow/operations", path: "/api/shadow/operations", expect: 200},
		{pattern: "GET /api/shadow/metrics", path: "/api/shadow/metrics"},
		{pattern: "GET /api/publisher/preview", path: "/api/publisher/preview"},
		{pattern: "GET /api/observability", path: "/api/observability", optional: true},
		{pattern: "PUT /api/observability", exempt: "mutation", optional: true},
		{pattern: "POST /api/observability/test", exempt: "mutation", optional: true},
		{pattern: "GET /api/observability/dashboard", path: "/api/observability/dashboard", optional: true},
		{pattern: "GET /api/tools", path: "/api/tools", optional: true},
		{pattern: "GET /api/organizations", path: "/api/organizations", optional: true},
		{pattern: "POST /api/organizations", exempt: "mutation", optional: true},
		{pattern: "PUT /api/organizations/{id}", exempt: "mutation", optional: true},
		{pattern: "DELETE /api/organizations/{id}", exempt: "mutation", optional: true},
		{pattern: "POST /api/session/organization", exempt: "mutation", optional: true},
		// Who may register a connector by itself: identity-provider configuration, so
		// the answer names hosts and a client ceiling and never a person or a machine.
		{pattern: "GET /api/mcp/registration", path: "/api/mcp/registration", optional: true},
		{pattern: "PUT /api/mcp/registration", exempt: "mutation", optional: true},
	}
}

// registered returns the console routes the application actually mounted.
func (p *projectionFixture) registered() map[string]bool {
	out := map[string]bool{}
	for _, r := range p.a.routes {
		out[r.Pattern] = true
	}
	return out
}

// sweep exercises every listed route as every actor and scans each body. Under
// aggregate-only, an individual route answers 403 aggregate_only instead of the
// owner's expected status; that refusal is the point of the mode, so it is
// accepted there and only there.
func (p *projectionFixture) sweep(t *testing.T, label string, aggregateOnly bool) {
	t.Helper()
	registered := p.registered()
	for _, actor := range projectionActors {
		for _, r := range p.routes() {
			if r.path == "" || (r.optional && r.pattern != "" && !registered[r.pattern]) {
				continue
			}
			p.sweepRoute(t, label, aggregateOnly, actor, r)
		}
	}
}

func (p *projectionFixture) sweepRoute(t *testing.T, label string, aggregateOnly bool, actor string, r projectionRoute) {
	t.Helper()
	w := p.as(actor, "GET", r.path, nil)
	refused := aggregateOnly && w.Code == 403 && strings.Contains(w.Body.String(), "aggregate_only")
	if actor == "owner" && r.expect != 0 && w.Code != r.expect && !refused {
		t.Fatalf("%s: owner GET %s: HTTP %d, want %d: %s", label, r.path, w.Code, r.expect, w.Body.String())
	}
	allowed := append([]string{}, r.legitimate...)
	u, _ := url.Parse(r.path)
	switch u.Path {
	case "/api/devices", "/api/events", "/api/shadow/events", "/api/shadow/conversations", "/api/shadow/conversation", "/api/model-access/status", "/api/tools":
		if u.Query().Get("identity") != "aliases" {
			allowed = append(allowed, p.s.host)
		}
	default:
		if strings.HasPrefix(u.Path, "/api/shadow/events/") && u.Query().Get("identity") != "aliases" {
			allowed = append(allowed, p.s.host)
		}
	}
	p.scan(t, label+": "+actor+" GET "+r.path, w.Body.Bytes(), allowed...)
}

func TestPrivacyProjections(t *testing.T) {
	p := newProjectionFixture(t)
	t.Run("every registered route is audited", func(t *testing.T) { testRegisteredProjectionRoutes(t, p) })
	t.Run("pseudonymous: no sentinel leaves the server", func(t *testing.T) {
		p.sweep(t, "pseudonymous", false)
	})
	t.Run("search by a private value matches nothing", func(t *testing.T) { testProjectionPrivateSearch(t, p) })
	t.Run("aggregate only: no individual row and still no sentinel", func(t *testing.T) { testProjectionAggregateOnly(t, p) })
}

func testRegisteredProjectionRoutes(t *testing.T, p *projectionFixture) {
	registered := p.registered()
	if len(registered) < 40 {
		t.Fatal("route recorder is empty or incomplete", len(registered))
	}
	listed := map[string]bool{}
	for _, r := range p.routes() {
		if r.pattern == "" {
			continue
		}
		if listed[r.pattern] {
			t.Fatal("route listed twice", r.pattern)
		}
		listed[r.pattern] = true
		if r.path == "" && r.exempt == "" {
			t.Fatal("route neither exercised nor exempt with a reason", r.pattern)
		}
		if !registered[r.pattern] && !r.optional {
			t.Fatal("route listed but not registered", r.pattern)
		}
	}
	for pattern := range registered {
		if !listed[pattern] {
			t.Fatalf("registered route is not covered by the identity-projection audit: %s", pattern)
		}
	}
}

func testProjectionPrivateSearch(t *testing.T, p *projectionFixture) {
	// Positive control first: the alias is searchable, so an empty result
	// below is a decision, not a broken filter.
	var alias string
	if e := p.admin.QueryRow(context.Background(), "SELECT alias FROM collaborators WHERE id=$1", p.subject).Scan(&alias); e != nil {
		t.Fatal(e)
	}
	count := func(t *testing.T, path string) int {
		t.Helper()
		w := p.as("owner", "GET", path, nil)
		requireHTTP(t, w, 200)
		var out struct {
			Items []json.RawMessage `json:"items"`
		}
		if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
			t.Fatal(e)
		}
		return len(out.Items)
	}
	if count(t, "/api/shadow/events?query="+url.QueryEscape(alias)) == 0 {
		t.Fatal("alias search matched nothing: the control is broken")
	}
	for _, private := range []string{p.s.host, p.s.name, p.s.email, p.s.osUser, p.s.eventUser} {
		for _, base := range []string{"/api/shadow/events?query=", "/api/events?query="} {
			if n := count(t, base+url.QueryEscape(private)); n != 0 {
				t.Fatalf("search %s%q matched %d rows", base, private, n)
			}
		}
	}
}

func testProjectionAggregateOnly(t *testing.T, p *projectionFixture) {
	cfg := defaultPrivacy()
	cfg.AggregateOnly = true
	requireHTTP(t, putPrivacyTest(t, p.observabilityFixture, cfg), 200)
	detail := "/api/shadow/events/" + p.event + "?device_id=" + p.device
	for _, path := range []string{"/api/events", "/api/shadow/events", detail, "/api/shadow/cartography", "/api/shadow/export?format=json", "/api/shadow/export?format=csv"} {
		w := p.as("owner", "GET", path, nil)
		requireHTTP(t, w, 403)
		if !strings.Contains(w.Body.String(), "aggregate_only") {
			t.Fatal("wrong refusal", path, w.Body.String())
		}
	}
	requireHTTP(t, p.as("owner", "GET", "/api/devices", nil), 200)
	p.sweep(t, "aggregate only", true)
}
