package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func privacyFixture(t *testing.T) (*observabilityFixture, string, string) {
	t.Helper()
	f := newObservabilityFixture(t)
	ctx := context.Background()
	tag, e := f.admin.Exec(ctx, "UPDATE sessions SET mfa_verified_at=clock_timestamp() WHERE token_hash=$1", hash(f.owner.Value))
	if e != nil || tag.RowsAffected() != 1 {
		t.Fatal("fresh authentication fixture missing", e)
	}
	tx, e := tenantTx(ctx, f.a.db, f.org)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	subject, e := f.a.associateIdentity(ctx, tx, f.org, "synthetic-subject", "subject@example.test", "Synthetic identity")
	if e != nil {
		t.Fatal(e)
	}
	var device string
	e = tx.QueryRow(ctx, "INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status) VALUES($1,$2,'','test','0.5.0','approved') RETURNING id", f.org, hash(randomToken())).Scan(&device)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.a.storeDeviceName(ctx, tx, f.org, device, "synthetic-private-host"); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	return f, subject, device
}
func readPrivacyTest(t *testing.T, f *observabilityFixture) PrivacyView {
	t.Helper()
	w := f.call("GET", "/api/privacy", nil, "")
	requireHTTP(t, w, 200)
	var p PrivacyView
	if e := json.Unmarshal(w.Body.Bytes(), &p); e != nil {
		t.Fatal(e)
	}
	return p
}
func putPrivacyTest(t *testing.T, f *observabilityFixture, c IdentityPrivacyConfig) *httptest.ResponseRecorder {
	t.Helper()
	p := readPrivacyTest(t, f)
	return f.call("PUT", "/api/privacy", map[string]any{"revision": p.Revision, "config": c, "reason": "Synthetic verification purpose"}, f.csrf)
}

// reportFlag reads one boolean out of the first week of an aggregate response, so a test
// asserts the flag itself rather than the presence of its name in the raw body.
func reportFlag(t *testing.T, body []byte, name string) bool {
	t.Helper()
	var out struct {
		Items []struct {
			Report map[string]json.RawMessage `json:"report"`
		} `json:"items"`
	}
	if e := json.Unmarshal(body, &out); e != nil || len(out.Items) == 0 {
		t.Fatal("aggregate response carries no week", e, string(body))
	}
	var value bool
	if e := json.Unmarshal(out.Items[0].Report[name], &value); e != nil {
		t.Fatal("missing report flag "+name, e, string(body))
	}
	return value
}
func addPrivacyEvent(t *testing.T, f *observabilityFixture, subject, device string, at time.Time, provider string) string {
	t.Helper()
	var id string
	e := f.admin.QueryRow(context.Background(), "INSERT INTO shadow_events(organization_id,device_id,id,occurred_at,kind,provider,tool,source,action,policy_revision,characters,sensitivity,collaborator_id) VALUES($1,$2,gen_random_uuid(),$3,'prompt',$4,'chrome','browser','observed',1,42,'unknown',$5) RETURNING id", f.org, device, at, provider, subject).Scan(&id)
	if e != nil {
		t.Fatal(e)
	}
	return id
}
func TestPrivacyIntegration(t *testing.T) {
	t.Run("sealed identity and temporary audited reveal", testPrivacyReveal)
	t.Run("aggregate-only and reporter boundaries", testPrivacyAggregateOnly)
	t.Run("fixed weeks suppress small cells and survive purge", testPrivacyFixedWeeks)
	t.Run("a cell withheld on one breakdown is withheld on both", testPrivacyCrossBreakdownSuppression)
	t.Run("a week published before the group breakdown keeps its exact bytes", testPrivacyHistoricReport)
	t.Run("breakdown availability follows what was observed, not what was configured", testPrivacyBreakdownAvailability)
	t.Run("defaults keep the identity link effective", testPrivacyDefaults)
	t.Run("device names follow one decision on every route", testPrivacyDeviceNames)
	t.Run("tenant RLS covers new tables", testPrivacyTableRLS)
}

func testPrivacyReveal(t *testing.T) {
	f, subject, device := privacyFixture(t)
	id := addPrivacyEvent(t, f, subject, device, time.Now(), "claude.ai")
	detail := "/api/shadow/events/" + id + "?device_id=" + device
	checkPrivacySealed(t, f, subject, detail)
	checkPrivacyTemporaryReveal(t, f, subject, detail)
	checkPrivacyRevealExpiry(t, f, subject, detail)
}

func checkPrivacySealed(t *testing.T, f *observabilityFixture, subject, detail string) {
	t.Helper()
	ctx := context.Background()
	var raw string
	if e := f.admin.QueryRow(ctx, "SELECT to_jsonb(c)::text FROM collaborators c WHERE id=$1", subject).Scan(&raw); e != nil {
		t.Fatal(e)
	}
	for _, private := range []string{"Synthetic identity", "subject@example.test", "synthetic-subject"} {
		if strings.Contains(raw, private) {
			t.Fatal("identity stored in plaintext")
		}
	}
	for _, path := range []string{"/api/shadow/events", detail, "/api/shadow/cartography", "/api/shadow/export?format=json", "/api/shadow/export?format=csv", "/api/devices"} {
		w := f.call("GET", path, nil, "")
		requireHTTP(t, w, 200)
		if strings.Contains(w.Body.String(), "Synthetic identity") || (strings.Contains(path, "export") && strings.Contains(w.Body.String(), "synthetic-private-host")) {
			t.Fatal("identity disclosure", path)
		}
	}
}

func checkPrivacyTemporaryReveal(t *testing.T, f *observabilityFixture, subject, detail string) {
	t.Helper()
	ctx := context.Background()
	w := f.call("POST", "/api/subjects/"+subject+"/reveal", map[string]string{"reason": "Synthetic incident investigation"}, f.csrf)
	requireHTTP(t, w, 200)
	if !strings.Contains(w.Body.String(), "Synthetic identity") {
		t.Fatal("reveal did not decrypt")
	}
	w = f.call("GET", detail, nil, "")
	requireHTTP(t, w, 200)
	if !strings.Contains(w.Body.String(), "Synthetic identity") {
		t.Fatal("session reveal not applied")
	}
	if strings.Contains(f.call("GET", "/api/shadow/export?format=json", nil, "").Body.String(), "Synthetic identity") {
		t.Fatal("export implicitly applied reveal")
	}
	if !strings.Contains(f.call("GET", "/api/shadow/export?format=json&identity=revealed", nil, "").Body.String(), "Synthetic identity") {
		t.Fatal("explicit named export did not apply reveal")
	}
	var n int
	if e := f.admin.QueryRow(ctx, "SELECT count(*) FROM audit WHERE action='identity.reveal' AND target=$1 AND details->>'reason'='Synthetic incident investigation'", subject).Scan(&n); e != nil || n != 1 {
		t.Fatal("durable audit missing", e)
	}
}

func checkPrivacyRevealExpiry(t *testing.T, f *observabilityFixture, subject, detail string) {
	t.Helper()
	ctx := context.Background()
	if tag, e := f.admin.Exec(ctx, "UPDATE identity_reveals SET expires_at=now()-interval '1 second' WHERE collaborator_id=$1", subject); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("expiry fixture missing", e)
	}
	if strings.Contains(f.call("GET", detail, nil, "").Body.String(), "Synthetic identity") {
		t.Fatal("expired reveal disclosed identity")
	}
	if tag, e := f.admin.Exec(ctx, "UPDATE sessions SET mfa_verified_at=now()-interval '6 minutes' WHERE token_hash=$1", hash(f.owner.Value)); e != nil || tag.RowsAffected() != 1 {
		t.Fatal(e)
	}
	requireHTTP(t, f.call("POST", "/api/subjects/"+subject+"/reveal", map[string]string{"reason": "Synthetic incident investigation"}, f.csrf), 403)
}

func testPrivacyAggregateOnly(t *testing.T) {
	f, subject, device := privacyFixture(t)
	id := addPrivacyEvent(t, f, subject, device, time.Now(), "claude.ai")
	cfg := defaultPrivacy()
	cfg.AggregateOnly = true
	requireHTTP(t, putPrivacyTest(t, f, cfg), 200)
	for _, path := range []string{"/api/events", "/api/shadow/events", "/api/shadow/events/" + id + "?device_id=" + device, "/api/shadow/cartography", "/api/shadow/export?format=json"} {
		w := f.call("GET", path, nil, "")
		requireHTTP(t, w, 403)
		if !strings.Contains(w.Body.String(), "aggregate_only") {
			t.Fatal("wrong refusal")
		}
	}
	requireHTTP(t, f.call("GET", "/api/shadow/aggregate", nil, ""), 200)
	if tag, e := f.admin.Exec(context.Background(), "UPDATE memberships SET role='reporter' WHERE user_id=$1", f.user); e != nil || tag.RowsAffected() != 1 {
		t.Fatal(e)
	}
	requireHTTP(t, f.call("GET", "/api/overview", nil, ""), 200)
	requireHTTP(t, f.call("GET", "/api/devices", nil, ""), 403)
	requireHTTP(t, f.call("GET", "/api/shadow/aggregate?team=synthetic", nil, ""), 400)
}

func testPrivacyFixedWeeks(t *testing.T) {
	f, subject, device := privacyFixture(t)
	// Fix the processing clock to Wednesday: on Mondays the previous week
	// is still inside its required 24-hour late-arrival allowance.
	now := weekStart(time.Now().UTC()).Add(48 * time.Hour)
	start := weekStart(now).AddDate(0, 0, -7)
	seedPrivacyFixedWeek(t, f, subject, device, start)
	publishPrivacyFixedWeek(t, f, start, now)
	verifyPrivacyFixedWeek(t, f, subject, device, start, now)
}

func seedPrivacyFixedWeek(t *testing.T, f *observabilityFixture, subject, device string, start time.Time) {
	t.Helper()
	ctx := context.Background()
	if tag, e := f.admin.Exec(ctx, "UPDATE privacy_settings SET created_at=$2,configuration=$3 WHERE organization_id=$1", f.org, start.AddDate(0, 0, -14), []byte("{\"identity_link_days\":14}")); e != nil || tag.RowsAffected() != 1 {
		t.Fatal(e)
	}
	// The same week is also broken down by device group, so the fixture's device
	// belongs to one. Both breakdowns must protect the same small cell.
	var group string
	if e := f.admin.QueryRow(ctx, "INSERT INTO device_groups(organization_id,name) VALUES($1,'Synthetic office') RETURNING id", f.org).Scan(&group); e != nil {
		t.Fatal(e)
	}
	if tag, e := f.admin.Exec(ctx, "UPDATE devices SET group_id=$2 WHERE id=$1", device, group); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("device not assigned to the synthetic group", e)
	}
	addPrivacyEvent(t, f, subject, device, start.Add(time.Hour), "small.test")
	tx, e := tenantTx(ctx, f.a.db, f.org)
	if e != nil {
		t.Fatal(e)
	}
	ids := []string{}
	for i := 0; i < 5; i++ {
		s, e := f.a.associateIdentity(ctx, tx, f.org, fmt.Sprintf("group-%d", i), fmt.Sprintf("group-%d@example.test", i), "Synthetic group member")
		if e != nil {
			t.Fatal(e)
		}
		ids = append(ids, s)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	for _, s := range ids {
		addPrivacyEvent(t, f, s, device, start.Add(time.Hour), "large.test")
	}
}

func publishPrivacyFixedWeek(t *testing.T, f *observabilityFixture, start, now time.Time) {
	t.Helper()
	ctx := context.Background()
	tx, e := tenantTx(ctx, f.a.db, f.org)
	if e != nil {
		t.Fatal(e)
	}
	// The target week must remain unpublished before the full allowance.
	if e = f.a.buildAggregateReports(ctx, tx, f.org, start.AddDate(0, 0, 7).Add(23*time.Hour)); e != nil {
		t.Fatal(e)
	}
	var premature int
	if e = tx.QueryRow(ctx, "SELECT count(*) FROM aggregate_reports WHERE week_start=$1", start).Scan(&premature); e != nil || premature != 0 {
		t.Fatal("week published before the late-arrival allowance", premature, e)
	}
	if e = f.a.buildAggregateReports(ctx, tx, f.org, now); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
}

func verifyPrivacyFixedWeek(t *testing.T, f *observabilityFixture, subject, device string, start, now time.Time) {
	t.Helper()
	ctx := context.Background()
	path := "/api/shadow/aggregate?week=" + start.Format("2006-01-02")
	w := f.call("GET", path, nil, "")
	requireHTTP(t, w, 200)
	if !strings.Contains(w.Body.String(), "large.test") || strings.Contains(w.Body.String(), "small.test") || strings.Contains(w.Body.String(), device) || strings.Contains(w.Body.String(), subject) {
		t.Fatal("invalid protected report", w.Body.String())
	}
	// The group breakdown publishes the same qualifying cell, under the group name
	// frozen at build time, and raises its own flag for the one it withheld.
	if !strings.Contains(w.Body.String(), "Synthetic office") {
		t.Fatal("group breakdown missing its published cell", w.Body.String())
	}
	if !reportFlag(t, w.Body.Bytes(), "group_suppressed") {
		t.Fatal("group breakdown withheld a cell without saying so", w.Body.String())
	}
	before := append([]byte{}, w.Body.Bytes()...)
	tx, e := tenantTx(ctx, f.a.db, f.org)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.a.maintainPrivacy(ctx, tx, f.org, now.AddDate(0, 0, 14)); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	var n int
	if e = f.admin.QueryRow(ctx, "SELECT count(*) FROM shadow_events").Scan(&n); e != nil || n != 0 {
		t.Fatal("event links survived expiry", e, n)
	}
	if !bytes.Equal(before, f.call("GET", path, nil, "").Body.Bytes()) {
		t.Fatal("historical report changed after purge")
	}
}

func testPrivacyCrossBreakdownSuppression(t *testing.T) {
	// Both breakdowns count the same events, so for one (tool, provider, model) their
	// totals are equal. Publishing a complete team side next to a group side missing
	// one cell would hand back that cell exactly, by subtraction. Here one provider
	// carries five subjects -- enough for the team side on its own -- split three and
	// two across two device groups, so the group side must withhold the pair of two.
	// Nothing about that provider may then be published on either side.
	f, _, device := privacyFixture(t)
	now := weekStart(time.Now().UTC()).Add(48 * time.Hour)
	start := weekStart(now).AddDate(0, 0, -7)
	seedPrivacyCrossBreakdown(t, f, device, start)
	ctx := context.Background()
	tx, e := tenantTx(ctx, f.a.db, f.org)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.a.buildAggregateReports(ctx, tx, f.org, now); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	w := f.call("GET", "/api/shadow/aggregate?week="+start.Format("2006-01-02"), nil, "")
	requireHTTP(t, w, 200)
	if strings.Contains(w.Body.String(), "cross.test") {
		t.Fatal("a breakdown published what the other one withheld", w.Body.String())
	}
	if !reportFlag(t, w.Body.Bytes(), "suppressed") || !reportFlag(t, w.Body.Bytes(), "group_suppressed") {
		t.Fatal("both breakdowns withheld a cell without saying so", w.Body.String())
	}
}

func seedPrivacyCrossBreakdown(t *testing.T, f *observabilityFixture, device string, start time.Time) {
	t.Helper()
	second := seedPrivacyCrossDevices(t, f, device, start)
	seedPrivacyCrossEvents(t, f, device, second, start)
}

func seedPrivacyCrossDevices(t *testing.T, f *observabilityFixture, device string, start time.Time) string {
	t.Helper()
	ctx := context.Background()
	if tag, e := f.admin.Exec(ctx, "UPDATE privacy_settings SET created_at=$2 WHERE organization_id=$1", f.org, start.AddDate(0, 0, -14)); e != nil || tag.RowsAffected() != 1 {
		t.Fatal(e)
	}
	var second string
	if e := f.admin.QueryRow(ctx, "INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status) VALUES($1,$2,'','test','0.5.0','approved') RETURNING id", f.org, hash(randomToken())).Scan(&second); e != nil {
		t.Fatal(e)
	}
	for _, seed := range []struct{ name, target string }{{"Group Alpha", device}, {"Group Beta", second}} {
		var id string
		if e := f.admin.QueryRow(ctx, "INSERT INTO device_groups(organization_id,name) VALUES($1,$2) RETURNING id", f.org, seed.name).Scan(&id); e != nil {
			t.Fatal(e)
		}
		if tag, e := f.admin.Exec(ctx, "UPDATE devices SET group_id=$2 WHERE id=$1", seed.target, id); e != nil || tag.RowsAffected() != 1 {
			t.Fatal("device not assigned to "+seed.name, e)
		}
	}
	return second
}

func seedPrivacyCrossEvents(t *testing.T, f *observabilityFixture, device, second string, start time.Time) {
	t.Helper()
	ctx := context.Background()
	tx, e := tenantTx(ctx, f.a.db, f.org)
	if e != nil {
		t.Fatal(e)
	}
	ids := []string{}
	for i := 0; i < 5; i++ {
		s, e := f.a.associateIdentity(ctx, tx, f.org, fmt.Sprintf("cross-%d", i), fmt.Sprintf("cross-%d@example.test", i), "Synthetic cross member")
		if e != nil {
			t.Fatal(e)
		}
		ids = append(ids, s)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	for i, s := range ids {
		target := device
		if i >= 3 {
			target = second
		}
		addPrivacyEvent(t, f, s, target, start.Add(time.Hour), "cross.test")
	}
}

func testPrivacyHistoricReport(t *testing.T) {
	// A published report is never recomputed, so a historical week simply has no
	// group breakdown. Backfilling one would recount events that may already be
	// purged, and publish a smaller number as if it were the week's total.
	f, _, _ := privacyFixture(t)
	ctx := context.Background()
	old := weekStart(time.Now().UTC()).AddDate(0, 0, -70)
	stored := []byte(`{"cells": [], "suppressed": false}`)
	if _, e := f.admin.Exec(ctx, `INSERT INTO aggregate_reports(organization_id,week_start,configuration_revision,k,report,expires_at) VALUES($1,$2,1,5,$3,now()+interval '30 days')`, f.org, old, stored); e != nil {
		t.Fatal(e)
	}
	tx, e := tenantTx(ctx, f.a.db, f.org)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.a.buildAggregateReports(ctx, tx, f.org, time.Now().UTC()); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	w := f.call("GET", "/api/shadow/aggregate?week="+old.Format("2006-01-02"), nil, "")
	requireHTTP(t, w, 200)
	var out struct {
		Items []struct {
			Report map[string]json.RawMessage `json:"report"`
		} `json:"items"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil || len(out.Items) != 1 {
		t.Fatal("historical week not served", e, w.Body.String())
	}
	if _, present := out.Items[0].Report["group_cells"]; present {
		t.Fatal("a published week was rewritten with a breakdown it never had", w.Body.String())
	}
}

func testPrivacyBreakdownAvailability(t *testing.T) {
	f, subject, device := privacyFixture(t)
	ctx := context.Background()
	read := func() (bool, bool) {
		t.Helper()
		w := f.call("GET", "/api/shadow/aggregate", nil, "")
		requireHTTP(t, w, 200)
		var out struct {
			Teams  bool `json:"teams_available"`
			Groups bool `json:"groups_available"`
		}
		if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
			t.Fatal(e)
		}
		return out.Teams, out.Groups
	}
	if teams, groups := read(); teams || groups {
		t.Fatal("a breakdown announced with nothing configured", teams, groups)
	}
	config := readPrivacyTest(t, f).Config
	config.TeamClaim = "department"
	requireHTTP(t, putPrivacyTest(t, f, config), 200)
	// Configured is not served: until the identity provider actually carries the
	// claim, every row still reads "unassigned" and the breakdown teaches nothing.
	if teams, _ := read(); teams {
		t.Fatal("teams announced although the claim was never served")
	}
	if tag, e := f.admin.Exec(ctx, "UPDATE collaborators SET team='Synthetic team' WHERE id=$1", subject); e != nil || tag.RowsAffected() != 1 {
		t.Fatal(e)
	}
	if teams, _ := read(); !teams {
		t.Fatal("teams withheld although the claim is configured and served")
	}
	var group string
	if e := f.admin.QueryRow(ctx, "INSERT INTO device_groups(organization_id,name) VALUES($1,'Synthetic office') RETURNING id", f.org).Scan(&group); e != nil {
		t.Fatal(e)
	}
	if _, groups := read(); groups {
		t.Fatal("groups announced although no device carries one")
	}
	if tag, e := f.admin.Exec(ctx, "UPDATE devices SET group_id=$2 WHERE id=$1", device, group); e != nil || tag.RowsAffected() != 1 {
		t.Fatal(e)
	}
	if _, groups := read(); !groups {
		t.Fatal("groups withheld although a device carries one")
	}
}

func testPrivacyDefaults(t *testing.T) {
	// Decision of 2026-09-11: both defaults are 90 days, because detailed events
	// live at most min(retention, identity link) days; a 90-day link over a 30-day
	// retention would have been nominal.
	f, _, _ := privacyFixture(t)
	if p := readPrivacyTest(t, f); p.Config.IdentityDays != 90 {
		t.Fatal("identity link default", p.Config.IdentityDays)
	}
	w := f.call("GET", "/api/settings", nil, "")
	requireHTTP(t, w, 200)
	var settings struct {
		Days int `json:"event_retention_days"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &settings); e != nil {
		t.Fatal(e)
	}
	if settings.Days != 90 {
		t.Fatal("event retention default", settings.Days)
	}
}

func testPrivacyDeviceNames(t *testing.T) {
	f, subject, device := privacyFixture(t)
	ctx := context.Background()
	addPrivacyEvent(t, f, subject, device, time.Now(), "claude.ai")
	if _, e := f.admin.Exec(ctx, "INSERT INTO events(organization_id,device_id,id,occurred_at,provider,action,source,characters,labels) VALUES($1,$2,gen_random_uuid(),now(),'claude.ai','observed','browser',10,'[]')", f.org, device); e != nil {
		t.Fatal(e)
	}
	sealedUser, e := f.a.sealIdentity(f.org, "device-user:"+device, "synthetic-os-user")
	if e != nil {
		t.Fatal(e)
	}
	if tag, e := f.admin.Exec(ctx, "UPDATE devices SET os_user=$2 WHERE id=$1", device, sealedUser); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("os user fixture missing", e)
	}
	expect := func(t *testing.T, path string, status int, host, user bool) {
		t.Helper()
		w := f.call("GET", path, nil, "")
		requireHTTP(t, w, status)
		if strings.Contains(w.Body.String(), "synthetic-private-host") != host {
			t.Fatal("machine projection differs", path)
		}
		if strings.Contains(w.Body.String(), "synthetic-os-user") != user {
			t.Fatal("OS identity projection differs", path)
		}
		if status == 200 && !host && !strings.Contains(w.Body.String(), "Device ") {
			t.Fatal("alias missing", path)
		}
	}
	expect(t, "/api/devices", 200, true, false)
	expect(t, "/api/events", 200, true, false)
	cfg := defaultPrivacy()
	cfg.Pseudonymous = false
	requireHTTP(t, putPrivacyTest(t, f, cfg), 200)
	expect(t, "/api/devices", 200, true, true)
	expect(t, "/api/events", 200, true, false)
	expect(t, "/api/devices?identity=aliases", 200, false, false)
	expect(t, "/api/events?identity=aliases", 200, false, false)
	cfg.AggregateOnly = true
	requireHTTP(t, putPrivacyTest(t, f, cfg), 200)
	expect(t, "/api/devices", 200, true, false)
	expect(t, "/api/events", 403, false, false)
}

func testPrivacyTableRLS(t *testing.T) {
	f, _, _ := privacyFixture(t)
	for _, table := range []string{"privacy_settings", "identity_reveals", "subject_views", "aggregate_reports", "privacy_audit_outbox", "detector_health", "candidate_domains", "muted_platforms"} {
		var forced bool
		if e := f.admin.QueryRow(context.Background(), "SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE relname=$1", table).Scan(&forced); e != nil || !forced {
			t.Fatal("missing FORCE RLS", table, e)
		}
		var n int
		if e := f.a.db.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&n); e != nil || n != 0 {
			t.Fatal("unscoped rows", table, e)
		}
	}
}
