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

// wideEventWindow pins an explicit, generous time range on a /api/shadow/events
// request instead of relying on the endpoint's default 24h window, which is
// computed from the Go test process's own clock. The fixtures timestamp their
// rows with the database server's now(), a different clock (observed about
// 180ms apart in this environment); a default window would silently drop a row
// on any skew large enough to place it on the wrong side of "now".
func wideEventWindow(path string) string {
	now := time.Now().UTC()
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + "from=" + url.QueryEscape(now.Add(-2*time.Hour).Format(time.RFC3339Nano)) + "&to=" + url.QueryEscape(now.Add(2*time.Hour).Format(time.RFC3339Nano))
}

// sessionCall issues one request as an arbitrary session cookie and CSRF token,
// for an actor the shared fixtures do not construct on their own -- here, a
// fresh membership carrying a custom role.
func sessionCall(f *observabilityFixture, cookie *http.Cookie, csrf, method, path string, body any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(method, path, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", f.a.config.AppURL)
	r.Header.Set("X-CSRF-Token", csrf)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	f.a.Handler().ServeHTTP(w, r)
	return w
}

func TestPrivacyRevealLifecycle(t *testing.T) {
	t.Run("custom role loses reveal on demotion", func(t *testing.T) {
		f, subject, device := privacyFixture(t)
		ctx := context.Background()
		id := addPrivacyEvent(t, f, subject, device, time.Now(), "claude.ai")
		detail := "/api/shadow/events/" + id + "?device_id=" + device

		w := f.call("POST", "/api/roles", map[string]any{"name": "synthetic-reader", "permissions": []string{"events.read", "devices.read", "identity.reveal"}}, f.csrf)
		requireHTTP(t, w, 201)

		var user string
		if e := f.admin.QueryRow(ctx, "INSERT INTO users(subject,email,display_name) VALUES('synthetic-custom-role-user','custom-role@example.test','Synthetic custom role user') RETURNING id").Scan(&user); e != nil {
			t.Fatal(e)
		}
		if _, e := f.admin.Exec(ctx, "INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'synthetic-reader')", f.org, user); e != nil {
			t.Fatal(e)
		}
		token, csrf := randomToken(), randomToken()
		cookie := &http.Cookie{Name: cookieName("session"), Value: token}
		if _, e := f.admin.Exec(ctx, `INSERT INTO sessions(token_hash,user_id,organization_id,csrf_token,encrypted_tokens,mfa,expires_at,identity_expires_at) VALUES($1,$2,$3,$4,$5,true,$6,$6)`, hash(token), user, f.org, csrf, []byte("synthetic-session"), time.Now().Add(time.Hour)); e != nil {
			t.Fatal(e)
		}
		if tag, e := f.admin.Exec(ctx, "UPDATE sessions SET mfa_verified_at=clock_timestamp() WHERE token_hash=$1", hash(token)); e != nil || tag.RowsAffected() != 1 {
			t.Fatal("fresh authentication fixture missing", e)
		}

		requireHTTP(t, sessionCall(f, cookie, csrf, "POST", "/api/subjects/"+subject+"/reveal", map[string]string{"reason": "Synthetic verification purpose"}), 200)
		w = sessionCall(f, cookie, csrf, "GET", detail, nil)
		requireHTTP(t, w, 200)
		if !strings.Contains(w.Body.String(), "Synthetic identity") {
			t.Fatal("reveal did not apply for the custom role", w.Body.String())
		}

		if tag, e := f.admin.Exec(ctx, "UPDATE memberships SET role='viewer' WHERE organization_id=$1 AND user_id=$2", f.org, user); e != nil || tag.RowsAffected() != 1 {
			t.Fatal("demotion fixture missing", e)
		}
		w = sessionCall(f, cookie, csrf, "GET", detail, nil)
		requireHTTP(t, w, 200)
		if strings.Contains(w.Body.String(), "Synthetic identity") {
			t.Fatal("a demoted role still sees a previously revealed identity", w.Body.String())
		}
	})

	t.Run("privacy update revokes reveals", func(t *testing.T) {
		f, subject, device := privacyFixture(t)
		ctx := context.Background()
		id := addPrivacyEvent(t, f, subject, device, time.Now(), "claude.ai")
		detail := "/api/shadow/events/" + id + "?device_id=" + device

		requireHTTP(t, f.call("POST", "/api/subjects/"+subject+"/reveal", map[string]string{"reason": "Synthetic verification purpose"}, f.csrf), 200)
		w := f.call("GET", detail, nil, "")
		requireHTTP(t, w, 200)
		if !strings.Contains(w.Body.String(), "Synthetic identity") {
			t.Fatal("reveal did not apply", w.Body.String())
		}

		// An unchanged configuration still counts as an update: only the reason and
		// the revision bump are new, and that alone must revoke every reveal.
		requireHTTP(t, putPrivacyTest(t, f, defaultPrivacy()), 200)

		w = f.call("GET", detail, nil, "")
		requireHTTP(t, w, 200)
		if strings.Contains(w.Body.String(), "Synthetic identity") {
			t.Fatal("a reveal survived a privacy settings update", w.Body.String())
		}
		var n int
		if e := f.admin.QueryRow(ctx, "SELECT count(*) FROM identity_reveals").Scan(&n); e != nil || n != 0 {
			t.Fatal("identity_reveals not cleared by the update", e, n)
		}
	})

	t.Run("api key and aggregate-only cannot reveal", func(t *testing.T) {
		p := newProjectionFixture(t)
		w := p.as("key", "POST", "/api/subjects/"+p.subject+"/reveal", map[string]string{"reason": "Synthetic verification purpose"})
		requireHTTP(t, w, 403)
		if !strings.Contains(w.Body.String(), "session_required") {
			t.Fatal("wrong refusal for an API key", w.Body.String())
		}

		cfg := defaultPrivacy()
		cfg.AggregateOnly = true
		requireHTTP(t, putPrivacyTest(t, p.observabilityFixture, cfg), 200)

		w = p.as("owner", "POST", "/api/subjects/"+p.subject+"/reveal", map[string]string{"reason": "Synthetic verification purpose"})
		requireHTTP(t, w, 403)
		if !strings.Contains(w.Body.String(), "aggregate_only") {
			t.Fatal("wrong refusal under aggregate-only", w.Body.String())
		}
	})

	t.Run("two reveals then boundary expiry", func(t *testing.T) {
		f, subject, device := privacyFixture(t)
		ctx := context.Background()
		id := addPrivacyEvent(t, f, subject, device, time.Now(), "claude.ai")
		detail := "/api/shadow/events/" + id + "?device_id=" + device

		for i := 0; i < 2; i++ {
			requireHTTP(t, f.call("POST", "/api/subjects/"+subject+"/reveal", map[string]string{"reason": "Synthetic verification purpose"}, f.csrf), 200)
		}
		var n int
		if e := f.admin.QueryRow(ctx, "SELECT count(*) FROM identity_reveals WHERE collaborator_id=$1", subject).Scan(&n); e != nil {
			t.Fatal(e)
		}
		if n != 2 {
			t.Fatalf("want 2 identity_reveals rows after two reveals, got %d", n)
		}
		w := f.call("GET", detail, nil, "")
		requireHTTP(t, w, 200)
		if !strings.Contains(w.Body.String(), "Synthetic identity") {
			t.Fatal("reveal did not apply", w.Body.String())
		}

		// revealed() checks expires_at>clock_timestamp() -- a strict ">". Pushing
		// every row to this exact instant still shows an alias an instant later,
		// which is the earliest observable point to exercise that boundary.
		tag, e := f.admin.Exec(ctx, "UPDATE identity_reveals SET expires_at=clock_timestamp() WHERE collaborator_id=$1", subject)
		if e != nil {
			t.Fatal(e)
		}
		if tag.RowsAffected() != 2 {
			t.Fatalf("want 2 rows pushed to their expiry boundary, got %d", tag.RowsAffected())
		}
		w = f.call("GET", detail, nil, "")
		requireHTTP(t, w, 200)
		if strings.Contains(w.Body.String(), "Synthetic identity") {
			t.Fatal("an expired reveal still disclosed the identity", w.Body.String())
		}
	})

	t.Run("session switch revokes reveals", func(t *testing.T) {
		if Edition != "commercial" {
			t.Skip("organization hierarchy is an Enterprise capability")
		}
		f, subject, _ := privacyFixture(t)
		ctx := context.Background()
		requireHTTP(t, f.call("POST", "/api/subjects/"+subject+"/reveal", map[string]string{"reason": "Synthetic verification purpose"}, f.csrf), 200)
		var before int
		if e := f.admin.QueryRow(ctx, "SELECT count(*) FROM identity_reveals").Scan(&before); e != nil || before != 1 {
			t.Fatal("reveal fixture missing", e, before)
		}

		w := f.call("POST", "/api/organizations", map[string]any{"name": "Synthetic child organization", "parent_id": f.org}, f.csrf)
		requireHTTP(t, w, 201)
		var child struct {
			ID string `json:"id"`
		}
		if e := json.Unmarshal(w.Body.Bytes(), &child); e != nil {
			t.Fatal(e)
		}

		requireHTTP(t, f.call("POST", "/api/session/organization", map[string]any{"organization_id": child.ID}, f.csrf), 200)

		// f.admin already defaults to f.org (the root); kept explicit since these
		// rows live in the root's tenant and FORCE RLS makes a stale tenant look
		// merely empty, never wrong.
		setTenant(t, f.admin, f.org)
		var after int
		if e := f.admin.QueryRow(ctx, "SELECT count(*) FROM identity_reveals WHERE session_hash=$1", hash(f.owner.Value)).Scan(&after); e != nil {
			t.Fatal(e)
		}
		if after != 0 {
			t.Fatalf("identity_reveals survived an organization switch: %d rows", after)
		}
	})

	t.Run("parent lock is protective only", func(t *testing.T) {
		if Edition != "commercial" {
			t.Skip("organization hierarchy is an Enterprise capability")
		}
		f, _, _ := privacyFixture(t)
		cfg := defaultPrivacy()
		cfg.LockDescendants = true
		cfg.ShareHealth = true
		requireHTTP(t, putPrivacyTest(t, f, cfg), 200)

		w := f.call("POST", "/api/organizations", map[string]any{"name": "Synthetic child organization", "parent_id": f.org}, f.csrf)
		requireHTTP(t, w, 201)
		var child struct {
			ID string `json:"id"`
		}
		if e := json.Unmarshal(w.Body.Bytes(), &child); e != nil {
			t.Fatal(e)
		}
		requireHTTP(t, f.call("POST", "/api/session/organization", map[string]any{"organization_id": child.ID}, f.csrf), 200)

		view := readPrivacyTest(t, f)
		if view.LockedBy != f.org {
			t.Fatalf("locked_by = %q, want the root organization %q", view.LockedBy, f.org)
		}
		if view.Config.ShareHealth {
			t.Fatal("a consent (share_health) was inherited from the parent lock")
		}

		for _, attempt := range []struct {
			name  string
			apply func(*IdentityPrivacyConfig)
		}{
			{"pseudonymous", func(c *IdentityPrivacyConfig) { c.Pseudonymous = false }},
			{"k", func(c *IdentityPrivacyConfig) { c.K = 2 }},
			{"identity_days", func(c *IdentityPrivacyConfig) { c.IdentityDays = 7 }},
		} {
			t.Run(attempt.name, func(t *testing.T) {
				attempted := view.Config
				attempt.apply(&attempted)
				w := putPrivacyTest(t, f, attempted)
				requireHTTP(t, w, 403)
				if !strings.Contains(w.Body.String(), "configuration_enforced") {
					t.Fatal("wrong refusal", w.Body.String())
				}
			})
		}
	})
}

func TestEraseSubjectLeavesNoLink(t *testing.T) {
	t.Run("erase removes every link", func(t *testing.T) {
		p := newProjectionFixture(t)
		ctx := context.Background()

		requireHTTP(t, p.call("POST", "/api/subjects/"+p.subject+"/reveal", map[string]string{"reason": "Synthetic verification purpose"}, p.csrf), 200)
		requireHTTP(t, p.call("GET", "/api/shadow/events/"+p.event+"?device_id="+p.device, nil, ""), 200)

		var revealAuditID string
		if e := p.admin.QueryRow(ctx, "SELECT id FROM audit WHERE organization_id=$1 AND action='identity.reveal' AND target=$2 ORDER BY occurred_at DESC LIMIT 1", p.org, p.subject).Scan(&revealAuditID); e != nil {
			t.Fatal(e)
		}
		if _, e := p.admin.Exec(ctx, "INSERT INTO privacy_audit_outbox(organization_id,audit_id,configuration_key) VALUES($1,$2,'synthetic-outbox-key')", p.org, revealAuditID); e != nil {
			t.Fatal(e)
		}

		// The fixture never writes shadow_content; add one tied to its event so the
		// cascade this test hunts for ("if shadow_content keeps a row for the
		// erased event") is actually exercised instead of vacuously true.
		sealedContent, e := p.a.sealShadow(p.org, "event:"+p.device+":"+p.event, []byte(`{"prompt":"synthetic erasure fixture"}`))
		if e != nil {
			t.Fatal(e)
		}
		if _, e := p.admin.Exec(ctx, "INSERT INTO shadow_content(organization_id,device_id,event_id,encrypted,expires_at) VALUES($1,$2,$3,$4,now()+interval '1 hour')", p.org, p.device, p.event, []byte(sealedContent)); e != nil {
			t.Fatal(e)
		}

		// buildAggregateReports needs a fully elapsed week that predates the
		// organization, so back-date privacy_settings.created_at the same way the
		// existing "fixed weeks" fixture does.
		now := time.Now().UTC()
		start := weekStart(now).AddDate(0, 0, -7)
		if tag, e := p.admin.Exec(ctx, "UPDATE privacy_settings SET created_at=$2 WHERE organization_id=$1", p.org, start.AddDate(0, 0, -14)); e != nil || tag.RowsAffected() != 1 {
			t.Fatal("privacy_settings backdate fixture missing", e)
		}
		tx, e := tenantTx(ctx, p.a.db, p.org)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		if e := p.a.buildAggregateReports(ctx, tx, p.org, now); e != nil {
			t.Fatal(e)
		}
		if e := tx.Commit(ctx); e != nil {
			t.Fatal(e)
		}
		var reportRows int
		if e := p.admin.QueryRow(ctx, "SELECT count(*) FROM aggregate_reports").Scan(&reportRows); e != nil || reportRows == 0 {
			t.Fatal("aggregate_reports fixture missing", e, reportRows)
		}

		// Positive controls: a fixture that never linked anything would make every
		// assertion below pass for the wrong reason.
		for _, check := range []struct{ table, column, value string }{
			{"identity_reveals", "collaborator_id", p.subject},
			{"subject_views", "subject", p.subject},
			{"privacy_audit_outbox", "audit_id", revealAuditID},
			{"shadow_content", "event_id", p.event},
		} {
			var n int
			if e := p.admin.QueryRow(ctx, "SELECT count(*) FROM "+check.table+" WHERE "+check.column+"=$1", check.value).Scan(&n); e != nil {
				t.Fatal(e)
			}
			if n == 0 {
				t.Fatalf("fixture broken: no %s row links %s", check.table, check.value)
			}
		}

		requireHTTP(t, p.call("DELETE", "/api/subjects/"+p.subject, nil, p.csrf), 200)

		tables := []string{"shadow_events", "shadow_content", "device_collaborators", "collaborators", "identity_reveals", "subject_views", "privacy_audit_outbox", "aggregate_reports", "detector_health", "candidate_domains"}
		needles := append([]string{p.subject}, p.s.all()...)
		for _, table := range tables {
			for _, needle := range needles {
				var n int
				if e := p.admin.QueryRow(ctx, "SELECT count(*) FROM "+table+" t WHERE t::text ILIKE '%'||$1||'%'", needle).Scan(&n); e != nil {
					t.Fatal(e)
				}
				if n != 0 {
					t.Fatalf("%s still links to %q after erasure: %d rows", table, needle, n)
				}
			}
		}
		// audit is append-only and durably keeps the subject UUID (target); it must
		// never carry a plaintext identity field alongside it.
		for _, needle := range []string{p.s.name, p.s.email, p.s.host} {
			var n int
			if e := p.admin.QueryRow(ctx, "SELECT count(*) FROM audit t WHERE t::text ILIKE '%'||$1||'%'", needle).Scan(&n); e != nil {
				t.Fatal(e)
			}
			if n != 0 {
				t.Fatalf("audit contains sentinel %q after erasure: %d rows", needle, n)
			}
		}
	})

	t.Run("expiry anonymises the same way", func(t *testing.T) {
		f, subject, device := privacyFixture(t)
		ctx := context.Background()
		if tag, e := f.admin.Exec(ctx, "UPDATE privacy_settings SET configuration=$2 WHERE organization_id=$1", f.org, []byte(`{"identity_link_days":7}`)); e != nil || tag.RowsAffected() != 1 {
			t.Fatal(e)
		}
		old := time.Now().AddDate(0, 0, -8)
		addPrivacyEvent(t, f, subject, device, old, "claude.ai")
		if tag, e := f.admin.Exec(ctx, "UPDATE collaborators SET last_associated_at=$2 WHERE id=$1", subject, old); e != nil || tag.RowsAffected() != 1 {
			t.Fatal(e)
		}

		tx, e := tenantTx(ctx, f.a.db, f.org)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		if e := f.a.maintainPrivacy(ctx, tx, f.org, time.Now()); e != nil {
			t.Fatal(e)
		}
		if e := tx.Commit(ctx); e != nil {
			t.Fatal(e)
		}

		var events int
		if e := f.admin.QueryRow(ctx, "SELECT count(*) FROM shadow_events").Scan(&events); e != nil || events != 0 {
			t.Fatal("expired event survived retention", e, events)
		}
		var subjects int
		if e := f.admin.QueryRow(ctx, "SELECT count(*) FROM collaborators WHERE id=$1", subject).Scan(&subjects); e != nil || subjects != 0 {
			t.Fatal("expired collaborator survived retention", e, subjects)
		}
		var raw []byte
		if e := f.admin.QueryRow(ctx, "SELECT details FROM audit WHERE action='retention.purge' AND target='organization' ORDER BY occurred_at DESC LIMIT 1").Scan(&raw); e != nil {
			t.Fatal("retention.purge audit row missing", e)
		}
		var counts map[string]int64
		if e := json.Unmarshal(raw, &counts); e != nil {
			t.Fatal(e)
		}
		if counts["events"] < 1 || counts["subjects"] < 1 {
			t.Fatalf("retention.purge counts missing events/subjects: %v", counts)
		}
	})
}

// osOnlyEventFixture creates a projection fixture plus a second shadow_event
// whose collaborator_id is NULL and whose sealed "user" column holds sentinel:
// a machine-reported OS account that was never bound to a verified subject.
func osOnlyEventFixture(t *testing.T, sentinel string) (*projectionFixture, string) {
	t.Helper()
	p := newProjectionFixture(t)
	ctx := context.Background()
	tx, e := tenantTx(ctx, p.a.db, p.org)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	var event string
	if e := tx.QueryRow(ctx, `INSERT INTO shadow_events(organization_id,device_id,id,occurred_at,kind,provider,tool,source,action,policy_revision,characters,sensitivity) VALUES($1,$2,gen_random_uuid(),now(),'prompt','claude.ai','chrome','browser','observed',1,42,'unknown') RETURNING id`, p.org, p.device).Scan(&event); e != nil {
		t.Fatal(e)
	}
	sealedUser, e := p.a.sealIdentity(p.org, "event-user:"+p.device+":"+event, sentinel)
	if e != nil {
		t.Fatal(e)
	}
	if tag, e := tx.Exec(ctx, `UPDATE shadow_events SET "user"=$2 WHERE id=$1`, event, sealedUser); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("OS-only event fixture missing", e)
	}
	if e := tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	return p, event
}

// findShadowEvent locates one event by id in a /api/shadow/events list body.
func findShadowEvent(t *testing.T, body []byte, id string) map[string]any {
	t.Helper()
	var out struct {
		Items []map[string]any `json:"items"`
	}
	if e := json.Unmarshal(body, &out); e != nil {
		t.Fatal(e)
	}
	for _, item := range out.Items {
		if item["id"] == id {
			return item
		}
	}
	t.Fatal("event not found in the response")
	return nil
}

func TestOSIdentityWithoutAssociation(t *testing.T) {
	// Each subtest builds its own fixture so neither depends on the other having
	// run first: -shuffle=on reorders sibling subtests, and this package's own
	// discipline (test-suite.md) is to never let declaration order be a contract.
	t.Run("pseudonymous: unattributed and no user disclosed", func(t *testing.T) {
		const sentinel = "SENTINEL-OSONLY-SUBJECT"
		p, event := osOnlyEventFixture(t, sentinel)
		w := p.as("owner", "GET", wideEventWindow("/api/shadow/events"), nil)
		requireHTTP(t, w, 200)
		row := findShadowEvent(t, w.Body.Bytes(), event)
		if row["actor_id"] != "unknown" {
			t.Fatalf("actor_id = %v, want %q", row["actor_id"], "unknown")
		}
		if row["actor_name"] != "Unattributed" {
			t.Fatalf("actor_name = %v, want %q", row["actor_name"], "Unattributed")
		}
		if v, present := row["user"]; present {
			t.Fatalf("user disclosed under pseudonymisation: %v", v)
		}
		if strings.Contains(w.Body.String(), sentinel) {
			t.Fatal("OS user leaked outside its own field", w.Body.String())
		}
		var collaborators int
		if e := p.admin.QueryRow(context.Background(), "SELECT count(*) FROM collaborators").Scan(&collaborators); e != nil {
			t.Fatal(e)
		}
		if collaborators != 1 {
			t.Fatalf("an OS-only event created a subject: %d collaborators, want 1", collaborators)
		}
	})

	t.Run("pseudonymisation disabled: user disclosed, actor stays unattributed", func(t *testing.T) {
		const sentinel = "SENTINEL-OSONLY-DISCLOSED"
		p, event := osOnlyEventFixture(t, sentinel)
		cfg := defaultPrivacy()
		cfg.Pseudonymous = false
		requireHTTP(t, putPrivacyTest(t, p.observabilityFixture, cfg), 200)
		w := p.as("owner", "GET", wideEventWindow("/api/shadow/events"), nil)
		requireHTTP(t, w, 200)
		row := findShadowEvent(t, w.Body.Bytes(), event)
		if row["actor_name"] != "Unattributed" {
			t.Fatalf("actor_name = %v, want %q even without pseudonymisation: an OS user is never a verified identity", row["actor_name"], "Unattributed")
		}
		if row["user"] != sentinel {
			t.Fatalf("user = %v, want the disclosed sentinel %q", row["user"], sentinel)
		}
	})
}
