package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestDLPConsequenceCompatibilityAndConfirmationDelivery(t *testing.T) {
	ctx := context.Background()
	var parsed struct {
		Rule DLPRule `json:"rule"`
	}
	if err := dlpEngine(ctx, map[string]any{"op": "parse", "source": `WHEN prompt CONTAINS "Tomate" SCOPE channel = "browser" THEN WARN MESSAGE "Check before sending."`}, &parsed); err != nil {
		t.Fatal(err)
	}
	policy := defaultDLP("endpoint")
	policy.Inspection = true
	parsed.Rule.Mode = "active"
	policy.Rules = []DLPRule{parsed.Rule}
	if err := validateDLPConsequenceChanges(ctx, defaultDLP("endpoint"), policy); err != nil {
		t.Fatal(err)
	}
	invalid := policy
	invalid.Rules = append([]DLPRule{}, policy.Rules...)
	invalid.Rules[0].Scope = dlpJSON(map[string]string{"op": "true"})
	if err := validateDLPConsequenceChanges(ctx, policy, invalid); err == nil {
		t.Fatal("native confirmation accepted")
	}
	invalid = policy
	invalid.Rules = append([]DLPRule{}, policy.Rules...)
	invalid.Rules[0].Condition = dlpJSON(map[string]string{"op": "upload"})
	invalid.Rules[0].Consequence = dlpJSON(map[string]any{"action": "replace", "value": "Tomate", "replacement": "Carotte", "ignore_case": false, "whole_word": false})
	if err := validateDLPConsequenceChanges(ctx, policy, invalid); err == nil {
		t.Fatal("upload silently allowed a text replacement")
	}
	settings := DLPSettings{Policy: policy, Fingerprint: dlpFingerprint(policy)}
	capable := dlpDeliverySettings(settings, []string{"dlp-v1", "dlp-confirm-v1"})
	old := dlpDeliverySettings(settings, []string{"dlp-v1"})
	if string(capable.Policy.Rules[0].Consequence) != string(parsed.Rule.Consequence) || !strings.Contains(string(old.Policy.Rules[0].Consequence), "block") || capable.Fingerprint == old.Fingerprint {
		t.Fatal("confirmation capability projection is unsafe")
	}
	if policy.Rules[0].ID != old.Policy.Rules[0].ID || old.Policy.Rules[0].Revision != parsed.Rule.Revision {
		t.Fatal("delivery rewrote rule identity")
	}
}
func TestDLPConfirmationActivationAndLegacyPoliciesFailClosed(t *testing.T) {
	f := newDLPFixtureWithoutDefaultRules(t)
	ctx := context.Background()
	get := func() DLPSettings {
		t.Helper()
		w := f.call("GET", "/api/dlp/settings", nil, "")
		requireHTTP(t, w, 200)
		var s DLPSettings
		if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	initial := get()
	var parsed struct {
		Rule DLPRule `json:"rule"`
	}
	if err := dlpEngine(ctx, map[string]any{"op": "parse", "source": `WHEN prompt CONTAINS "Tomate" SCOPE channel = "browser" THEN WARN MESSAGE "Check this submission."`}, &parsed); err != nil {
		t.Fatal(err)
	}
	parsed.Rule.Mode = "active"
	initial.Policy.Inspection = true
	initial.Policy.Rules = []DLPRule{parsed.Rule}
	secret := randomToken()
	var device string
	if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,kind,capabilities) VALUES($1,$2,'Warning fixture','test','0','approved','browser','["dlp-v1"]') RETURNING id`, f.org, hash(secret)).Scan(&device); err != nil {
		t.Fatal(err)
	}
	save := func(s DLPSettings) {
		t.Helper()
		requireHTTP(t, f.call("PUT", "/api/dlp/settings", map[string]any{"revision": s.Revision, "policy": s.Policy}, f.csrf), 200)
	}
	w := f.call("PUT", "/api/dlp/settings", map[string]any{"revision": initial.Revision, "policy": initial.Policy}, f.csrf)
	requireHTTP(t, w, 409)
	if !strings.Contains(w.Body.String(), "dlp_confirmation_update_required") {
		t.Fatal(w.Body.String())
	}
	if _, err := f.admin.Exec(ctx, `UPDATE devices SET capabilities='["dlp-v1","dlp-confirm-v1"]' WHERE id=$1`, device); err != nil {
		t.Fatal(err)
	}
	save(initial)
	request := func(path string) []byte {
		t.Helper()
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Authorization", "Bearer "+secret)
		w := httptest.NewRecorder()
		f.a.Handler().ServeHTTP(w, r)
		requireHTTP(t, w, 200)
		var env map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		raw, err := base64.StdEncoding.DecodeString(env["payload"])
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if !strings.Contains(string(request("/v4/policy")), `"action":"warn"`) {
		t.Fatal("capable agent lost warning")
	}
	for _, route := range []string{"/v1/policy", "/v2/policy", "/v3/policy"} {
		raw := request(route)
		if !strings.Contains(string(raw), `"block"`) {
			t.Fatalf("%s did not close legacy delivery", route)
		}
	}
	if _, err := f.admin.Exec(ctx, `UPDATE devices SET capabilities='["dlp-v1"]' WHERE id=$1`, device); err != nil {
		t.Fatal(err)
	}
	raw := request("/v4/policy")
	if strings.Contains(string(raw), `"action":"warn"`) || !strings.Contains(string(raw), `"action":"block"`) {
		t.Fatal("downgraded agent received unsupported warning")
	}
}

func TestDLPWarningIsAQueryableMonitoringConsequence(t *testing.T) {
	filter, err := parseShadowFilter(url.Values{"dlp_consequence": {"warn"}})
	if err != nil || !strings.Contains(filter.Where, "dlp") {
		t.Fatal("warning filter not accepted", err)
	}
	if _, err = parseShadowFilter(url.Values{"dlp_consequence": {"warn OR true"}}); err == nil {
		t.Fatal("unexpected consequence accepted")
	}
}
