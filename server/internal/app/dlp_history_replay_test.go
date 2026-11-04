package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDLPHistoricalReplayCannotReplaceOrRecreateAttribution(t *testing.T) {
	f := newDLPFixtureWithoutDefaultRules(t)
	ctx := context.Background()
	secret := randomToken()
	var device string
	if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,kind,capabilities) VALUES($1,$2,'Replay fixture','test','0','approved','browser','["dlp-v1"]') RETURNING id`, f.org, hash(secret)).Scan(&device); err != nil {
		t.Fatal(err)
	}
	call := func(method, path string, body any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(method, path, bytes.NewReader(raw))
		r.Header.Set("Authorization", "Bearer "+secret)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.a.Handler().ServeHTTP(w, r)
		return w
	}
	get := func() DLPSettings {
		w := f.call("GET", "/api/dlp/settings", nil, "")
		requireHTTP(t, w, 200)
		var s DLPSettings
		_ = json.Unmarshal(w.Body.Bytes(), &s)
		return s
	}
	deliver := func() (DLPPolicy, string, int64) {
		w := call("GET", "/v4/policy", nil)
		requireHTTP(t, w, 200)
		var env map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &env)
		raw, err := base64.StdEncoding.DecodeString(env["payload"])
		if err != nil {
			t.Fatal(err)
		}
		var payload struct {
			Revision int64
			Config   struct {
				Policy      DLPPolicy `json:"dlp"`
				Fingerprint string    `json:"dlp_fingerprint"`
			}
		}
		if err = json.Unmarshal(raw, &payload); err != nil {
			t.Fatal(err)
		}
		return payload.Config.Policy, payload.Config.Fingerprint, payload.Revision
	}
	s := get()
	s.Policy.Inspection = true
	s.Policy.Rules = []DLPRule{{ID: "fixed-history", Revision: 1, Name: "Original attribution", Mode: "active", Priority: 1, Condition: dlpJSON(map[string]string{"op": "true"}), Scope: dlpJSON(map[string]string{"op": "eq", "field": "channel", "value": "browser"}), Consequence: dlpJSON(map[string]string{"action": "block"})}}
	requireHTTP(t, f.call("PUT", "/api/dlp/settings", map[string]any{"revision": s.Revision, "policy": s.Policy}, f.csrf), 200)
	policyA, fpA, revisionA := deliver()
	ruleA := policyA.Rules[0]
	at := time.Now().UTC().Add(-5 * time.Minute)
	event := V2Event{ID: "a02e7f6d-2d97-4e30-92aa-e78b5e36daba", Kind: "prompt", OccurredAt: at, Provider: "chatgpt.com", Source: "browser", Tool: "chrome", Action: "blocked", Characters: 6, Labels: []string{}, PolicyRevision: revisionA, DLP: &DLPTrace{Fingerprint: fpA, Action: "block", Delivery: "not_sent", Decisions: []DLPDecision{{RuleID: ruleA.ID, RuleRevision: ruleA.Revision, RuleName: ruleA.Name, Mode: "active", Consequence: "block", Condition: "true", Scope: "true", Outcome: "blocked"}}}}
	send := func(v V2Event) {
		t.Helper()
		requireHTTP(t, call("POST", "/v2/events", map[string]any{"events": []V2Event{v}}), 200)
	}
	send(event)
	send(event)
	unattributed := event
	unattributed.ID = "ceb82713-663f-4c79-a6ee-b0260cbe8ef0"
	unattributed.DLP = nil
	send(unattributed)
	s = get()
	s.Policy.Rules[0].Name = "Later attribution"
	requireHTTP(t, f.call("PUT", "/api/dlp/settings", map[string]any{"revision": s.Revision, "policy": s.Policy}, f.csrf), 200)
	policyB, fpB, revisionB := deliver()
	if fpA == fpB {
		t.Fatal("fixture did not create a second policy")
	}
	replay := event
	replay.OccurredAt = at.Add(-time.Minute)
	replay.PolicyRevision = revisionB
	trace := *event.DLP
	trace.Fingerprint = fpB
	trace.Decisions = append([]DLPDecision{}, trace.Decisions...)
	trace.Decisions[0].RuleRevision = policyB.Rules[0].Revision
	trace.Decisions[0].RuleName = policyB.Rules[0].Name
	replay.DLP = &trace
	send(replay)
	var count int
	var fingerprint string
	if err := f.admin.QueryRow(ctx, "SELECT count(*),min(policy_fingerprint) FROM dlp_decisions WHERE organization_id=$1 AND event_id=$2", f.org, event.ID).Scan(&count, &fingerprint); err != nil || count != 1 || fingerprint != fpA {
		t.Fatal("replay changed attribution", count, err)
	}
	replay.ID = unattributed.ID
	send(replay)
	if err := f.admin.QueryRow(ctx, "SELECT count(*) FROM dlp_decisions WHERE organization_id=$1 AND event_id=$2", f.org, unattributed.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("replay backfilled attribution", count, err)
	}
	if _, err := f.admin.Exec(ctx, "DELETE FROM dlp_decisions WHERE organization_id=$1 AND event_id=$2", f.org, event.ID); err != nil {
		t.Fatal(err)
	}
	send(event)
	if err := f.admin.QueryRow(ctx, "SELECT count(*) FROM dlp_decisions WHERE organization_id=$1 AND event_id=$2", f.org, event.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("replay recreated purged evidence", count, err)
	}
}
