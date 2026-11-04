package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDLPPolicyAndHistoricalAttribution(t *testing.T) {
	f := newDLPFixtureWithoutDefaultRules(t)
	credential := randomToken()
	var device string
	if err := f.admin.QueryRow(context.Background(), `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,kind,capabilities) VALUES($1,$2,'DLP fixture','test','0.7.0','approved','browser','["dlp-v1"]') RETURNING id`, f.org, hash(credential)).Scan(&device); err != nil {
		t.Fatal(err)
	}
	callDevice := func(method, path string, body any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(method, path, bytes.NewReader(raw))
		r.Header.Set("Authorization", "Bearer "+credential)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.a.Handler().ServeHTTP(w, r)
		return w
	}
	var settings DLPSettings
	get := f.call("GET", "/api/dlp/settings", nil, "")
	requireHTTP(t, get, 200)
	if err := json.Unmarshal(get.Body.Bytes(), &settings); err != nil {
		t.Fatal(err)
	}
	settings.Policy = defaultDLP("endpoint")
	settings.Policy.Inspection = true
	settings.Policy.Rules = []DLPRule{{ID: "fixture-rule", Revision: 1, Name: "Frozen rule name", Mode: "active", Priority: 10, Condition: dlpJSON(map[string]any{"op": "contains", "field": "prompt", "value": "synthetic-secret", "ignore_case": true, "whole_word": false}), Scope: dlpJSON(map[string]string{"op": "true"}), Consequence: dlpJSON(map[string]string{"action": "block"})}}
	settings.Policy.Rules = append(settings.Policy.Rules, DLPRule{ID: "prepared-rule", Revision: 1, Name: "Prepared rule name", Mode: "active", Priority: 11, Condition: dlpJSON(map[string]any{"op": "contains", "field": "prompt", "value": "Tomate", "ignore_case": false, "whole_word": false}), Scope: dlpJSON(map[string]string{"op": "true"}), Consequence: dlpJSON(map[string]any{"action": "replace", "value": "Tomate", "replacement": "Carotte", "ignore_case": false, "whole_word": false})})
	saved := f.call("PUT", "/api/dlp/settings", map[string]any{"revision": settings.Revision, "policy": settings.Policy, "inherited": false}, f.csrf)
	requireHTTP(t, saved, 200)
	if err := json.Unmarshal(saved.Body.Bytes(), &settings); err != nil {
		t.Fatal(err)
	}
	// A stale editor must not replace an independently changed DLP policy.
	requireHTTP(t, f.call("PUT", "/api/dlp/settings", map[string]any{"revision": settings.Revision - 1, "policy": settings.Policy, "inherited": false}, f.csrf), 409)
	signed := callDevice("GET", "/v4/policy", nil)
	requireHTTP(t, signed, 200)
	var envelope map[string]string
	if err := json.Unmarshal(signed.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(envelope["payload"])
	if err != nil {
		t.Fatal(err)
	}
	var delivered struct {
		Version  int                        `json:"version"`
		Revision int64                      `json:"revision"`
		Config   map[string]json.RawMessage `json:"config"`
	}
	if err = json.Unmarshal(raw, &delivered); err != nil {
		t.Fatal(err)
	}
	if delivered.Version != 4 || delivered.Revision < 1 {
		t.Fatal("missing v4 policy")
	}
	var fingerprint string
	_ = json.Unmarshal(delivered.Config["dlp_fingerprint"], &fingerprint)
	event := V2Event{ID: "bfe5640b-503d-4c3e-a15d-874091f833df", Kind: "prompt", OccurredAt: time.Now().UTC(), Provider: "claude.ai", Source: "browser", Tool: "chrome", Action: "blocked", Characters: 16, Labels: []string{}, PolicyRevision: delivered.Revision, DLP: &DLPTrace{Fingerprint: fingerprint, Action: "block", Delivery: "not_sent", Decisions: []DLPDecision{{RuleID: "fixture-rule", RuleRevision: 1, RuleName: "Frozen rule name", Mode: "active", Consequence: "block", Condition: "true", Scope: "true", Outcome: "blocked"}}}}
	requireHTTP(t, callDevice("POST", "/v2/events", map[string]any{"events": []V2Event{event}}), 200)
	// The retry is idempotent. No content is necessary for rule attribution.
	requireHTTP(t, callDevice("POST", "/v2/events", map[string]any{"events": []V2Event{event}}), 200)
	var count int
	if err = f.admin.QueryRow(context.Background(), `SELECT count(*) FROM dlp_decisions WHERE event_id=$1`, event.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("decision deduplication: %d %v", count, err)
	}
	detail := f.call("GET", "/api/shadow/events/"+event.ID+"?device_id="+device, nil, "")
	requireHTTP(t, detail, 200)
	if !strings.Contains(detail.Body.String(), "Frozen rule name") || strings.Contains(detail.Body.String(), "synthetic-secret") {
		t.Fatal("attribution missing or detector evidence leaked")
	}
	// Network completion advances an existing prepared trace and cannot fabricate
	// attribution or turn a blocked attempt into an observed transmission.
	completion := map[string]any{"completions": []V2Completion{{ID: event.ID, Model: "fixture-model"}}}
	requireHTTP(t, callDevice("POST", "/v2/events/complete", completion), 200)
	var delivery string
	if err = f.admin.QueryRow(context.Background(), `SELECT delivery FROM dlp_decisions WHERE event_id=$1`, event.ID).Scan(&delivery); err != nil || delivery != "not_sent" {
		t.Fatalf("blocked custody changed: %s %v", delivery, err)
	}
	prepared := event
	prepared.ID = "f692aa10-bf50-42d8-9699-4610463d8da7"
	prepared.Action = "observed"
	preparedTrace := *event.DLP
	preparedTrace.Delivery = "prepared"
	preparedTrace.Action = "transform"
	preparedTrace.Decisions = []DLPDecision{{RuleID: "prepared-rule", RuleRevision: 1, RuleName: "Prepared rule name", Mode: "active", Consequence: "replace", Condition: "true", Scope: "true", Outcome: "prepared", Occurrences: 1}}
	preparedTrace.Decisions[0].Outcome = "prepared"
	prepared.DLP = &preparedTrace
	requireHTTP(t, callDevice("POST", "/v2/events", map[string]any{"events": []V2Event{prepared}}), 200)
	completion = map[string]any{"completions": []V2Completion{{ID: prepared.ID, Model: "fixture-model"}}}
	for range 2 {
		requireHTTP(t, callDevice("POST", "/v2/events/complete", completion), 200)
	}
	var frozen string
	if err = f.admin.QueryRow(context.Background(), `SELECT delivery,decisions::text FROM dlp_decisions WHERE event_id=$1`, prepared.ID).Scan(&delivery, &frozen); err != nil || delivery != "observed" || !strings.Contains(frozen, `"outcome": "observed"`) || !strings.Contains(frozen, "Prepared rule name") {
		t.Fatalf("completion evidence: %s %s %v", delivery, frozen, err)
	}
	settings.Policy.Rules[0].Name = "Renamed rule"
	renamed := f.call("PUT", "/api/dlp/settings", map[string]any{"revision": settings.Revision, "policy": settings.Policy, "inherited": false}, f.csrf)
	requireHTTP(t, renamed, 200)
	detail = f.call("GET", "/api/shadow/events/"+event.ID+"?device_id="+device, nil, "")
	requireHTTP(t, detail, 200)
	if !strings.Contains(detail.Body.String(), "Frozen rule name") || strings.Contains(detail.Body.String(), "Renamed rule") {
		t.Fatal("historical attribution was rewritten")
	}
	forged := event
	forged.ID = "33de9629-c87c-4bd9-be65-14bfec8759a1"
	trace := *event.DLP
	trace.Decisions = append([]DLPDecision{}, trace.Decisions...)
	trace.Decisions[0].RuleName = "Forged rule"
	forged.DLP = &trace
	requireHTTP(t, callDevice("POST", "/v2/events", map[string]any{"events": []V2Event{forged}}), 400)
	list := f.call("GET", "/api/shadow/events?dlp_rule=fixture-rule", nil, "")
	requireHTTP(t, list, 200)
	if !strings.Contains(list.Body.String(), event.ID) {
		t.Fatal("rule filter omitted the blocked attempt")
	}
}
