package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"
)

func contextFixturePolicy() DLPPolicy {
	return DLPPolicy{SchemaVersion: 1, Domain: "endpoint", Inspection: true, Journal: true, Detectors: []DLPDetector{
		{ID: "terms", Name: "Terms", Definition: dlpJSON(map[string]any{"kind": "dictionary", "values": []string{"alpha", "beta"}, "exceptions": []string{}})},
		{ID: "context", Name: "Context", Definition: dlpJSON(map[string]any{"kind": "dictionary_context", "dictionary": "terms", "minimum": 2})},
	}, Rules: []DLPRule{{ID: "rule", Revision: 7, Name: "Context rule", Mode: "active", Priority: 100, Condition: dlpJSON(map[string]any{"op": "matches", "field": "prompt", "detector": "context", "minimum": 1}), Scope: dlpJSON(map[string]string{"op": "eq", "field": "provider", "value": "chatgpt"}), Consequence: dlpJSON(map[string]string{"action": "block"})}}}
}

func TestDLPContextDeliveryPrunesUnknownKindsAndPreservesCanonicalPolicy(t *testing.T) {
	original := contextFixturePolicy()
	before := string(dlpJSON(original))
	settings := DLPSettings{Policy: original, Fingerprint: dlpFingerprint(original)}
	current := dlpDeliverySettings(settings, []string{"dlp-v1", "dlp-contextual-v1"})
	if !reflect.DeepEqual(current, settings) {
		t.Fatal("qualified client changed canonical delivery")
	}
	legacy := dlpDeliverySettings(settings, []string{"dlp-v1"})
	if string(dlpJSON(original)) != before {
		t.Fatal("projection mutated canonical policy")
	}
	if bytes.Contains(dlpJSON(legacy.Policy), []byte("dictionary_context")) || legacy.Fingerprint == settings.Fingerprint {
		t.Fatal("unknown kind or canonical fingerprint escaped")
	}
	if len(legacy.Policy.Rules) != 1 || legacy.Policy.Rules[0].Revision != 7 || string(legacy.Policy.Rules[0].Scope) != string(original.Rules[0].Scope) {
		t.Fatal("fallback widened scope or changed rule identity")
	}
	if string(legacy.Policy.Rules[0].Condition) != string(dlpJSON(map[string]string{"op": "true"})) {
		t.Fatal("unsupported prevention did not close")
	}
	for _, mode := range []string{"simulation", "disabled"} {
		p := contextFixturePolicy()
		p.Rules[0].Mode = mode
		projected, _ := dlpContextDelivery(p, nil)
		if string(projected.Rules[0].Condition) != string(dlpJSON(map[string]any{"op": "not", "child": map[string]string{"op": "true"}})) {
			t.Fatal("unsupported simulation fabricated a match")
		}
	}
	p := contextFixturePolicy()
	p.Rules[0].Consequence = dlpJSON(map[string]string{"action": "observe"})
	projected, _ := dlpContextDelivery(p, nil)
	if bytes.Contains(projected.Rules[0].Condition, []byte("context")) || string(projected.Rules[0].Consequence) != string(p.Rules[0].Consequence) {
		t.Fatal("audit fallback changed sending behavior")
	}
}

func TestDLPContextHeartbeatIsDeviceBoundAndDowngradeClearsSupport(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	credential := randomToken()
	var device, other string
	insert := "INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,capabilities) VALUES($1,$2,'fixture','windows','0.7.0','approved','[\"browser.navigation\"]') RETURNING id"
	for _, target := range []*string{&device, &other} {
		token := randomToken()
		if target == &device {
			token = credential
		}
		if err := f.admin.QueryRow(ctx, insert, f.org, hash(token)).Scan(target); err != nil {
			t.Fatal(err)
		}
	}
	call := func(token string, body any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest("POST", "/v2/heartbeat", bytes.NewReader(raw))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.a.Handler().ServeHTTP(w, r)
		return w
	}
	caps := func(id string) []string {
		var result []string
		if err := f.admin.QueryRow(ctx, "SELECT capabilities FROM devices WHERE id=$1", id).Scan(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	requireHTTP(t, call("wrong", map[string]any{"dlp_engine": 3}), 401)
	requireHTTP(t, call(credential, map[string]any{"dlp_engine": 3}), 200)
	if !slices.Contains(caps(device), "dlp-contextual-v1") || slices.Contains(caps(other), "dlp-contextual-v1") {
		t.Fatal("context support was not authenticated/device-bound")
	}
	requireHTTP(t, call(credential, map[string]any{}), 200)
	if !slices.Contains(caps(device), "dlp-contextual-v1") {
		t.Fatal("omitted diagnostic erased support")
	}
	for _, body := range []any{map[string]any{"dlp_engine": true}, map[string]any{"dlp_engine": 4}, map[string]any{"dlp_engine": map[string]string{"image": "fixture"}}, map[string]any{"device_id": other, "dlp_engine": 3}} {
		requireHTTP(t, call(credential, body), 400)
	}
	if !slices.Contains(caps(device), "dlp-contextual-v1") {
		t.Fatal("invalid report changed support")
	}
	for _, body := range []any{map[string]any{"dlp_engine": 2}, map[string]any{"dlp_engine": 0}, map[string]any{"version": "0.7.0"}} {
		requireHTTP(t, call(credential, map[string]any{"dlp_engine": 3}), 200)
		requireHTTP(t, call(credential, body), 200)
		if slices.Contains(caps(device), "dlp-contextual-v1") || !slices.Contains(caps(device), "browser.navigation") {
			t.Fatal("downgrade retained support or removed unrelated capability")
		}
	}
}

func TestDLPContextActivationRequiresOnlyTargetedCurrentEngines(t *testing.T) {
	f := newDLPFixtureWithoutDefaultRules(t)
	ctx := context.Background()
	var target, legacy string
	for i, caps := range []string{`["dlp-v1","dlp-contextual-v1"]`, `["dlp-v1"]`} {
		var id string
		if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,kind,capabilities) VALUES($1,$2,'Context fixture','test','0','approved','browser',$3) RETURNING id`, f.org, hash(randomToken()), caps).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			target = id
		} else {
			legacy = id
		}
	}
	get := func() DLPSettings {
		w := f.call("GET", "/api/dlp/settings", nil, "")
		requireHTTP(t, w, 200)
		var s DLPSettings
		if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	initial := get()
	policy := contextFixturePolicy()
	policy.Rules[0].Application = &DLPApplication{Kind: "device", ID: target}
	// Ignore unrelated browser/native defaults in this isolated fixture.
	initial.Policy.Detectors = append(initial.Policy.Detectors, policy.Detectors...)
	initial.Policy.Rules = policy.Rules
	initial.Policy.Inspection = true
	save := func(s DLPSettings) *httptest.ResponseRecorder {
		return f.call("PUT", "/api/dlp/settings", map[string]any{"revision": s.Revision, "policy": s.Policy, "inherited": false}, f.csrf)
	}
	requireHTTP(t, save(initial), 200)
	saved := get()
	if len(dlpPolicyForDevice(saved.Policy, legacy, nil).Rules) != 0 {
		t.Fatal("context target widened")
	}
	saved.Policy.Rules[0].Application = &DLPApplication{Kind: "organization"}
	rejected := save(saved)
	requireHTTP(t, rejected, 409)
	if !bytes.Contains(rejected.Body.Bytes(), []byte("dlp_contextual_update_required")) {
		t.Fatal("wrong activation rejection")
	}
	after := get()
	if after.Fingerprint != saved.Fingerprint || after.Revision != saved.Revision {
		t.Fatal("rejected activation changed policy")
	}
	after.Policy.Rules[0].Mode = "simulation"
	after.Policy.Rules[0].Revision++
	requireHTTP(t, save(after), 200)
}
