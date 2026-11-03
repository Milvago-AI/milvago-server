package app

import (
	"context"
	"encoding/json"
	"testing"
)

func TestDLPRuleDeactivationSurvivesLegacyEnrollmentAndReactivationStillChecksCapabilities(t *testing.T) {
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
	policy := get()
	policy.Policy.Rules = []DLPRule{}
	for _, id := range []string{"first", "second"} {
		var parsed struct {
			Rule DLPRule `json:"rule"`
		}
		if err := dlpEngine(ctx, map[string]any{"op": "parse", "source": `WHEN prompt CONTAINS "fixture" SCOPE channel = "browser" THEN BLOCK`}, &parsed); err != nil {
			t.Fatal(err)
		}
		parsed.Rule.ID = id
		parsed.Rule.Mode = "active"
		policy.Policy.Rules = append(policy.Policy.Rules, parsed.Rule)
	}
	requireHTTP(t, f.call("PUT", "/api/dlp/settings", map[string]any{"revision": policy.Revision, "policy": policy.Policy}, f.csrf), 200)
	policy = get()
	if _, err := f.admin.Exec(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,kind,capabilities) VALUES($1,$2,'Activation fixture','test','0','approved','browser','[]')`, f.org, hash(randomToken())); err != nil {
		t.Fatal(err)
	}
	original := policy.Policy.Rules[0]
	policy.Policy.Rules[0].Mode = "disabled"
	requireHTTP(t, f.call("PUT", "/api/dlp/settings", map[string]any{"revision": policy.Revision, "policy": policy.Policy}, f.csrf), 200)
	disabled := get()
	if len(disabled.Policy.Rules) != 2 || disabled.Policy.Rules[0].ID != original.ID || disabled.Policy.Rules[0].Mode != "disabled" || disabled.Policy.Rules[0].Revision <= original.Revision || string(disabled.Policy.Rules[0].Condition) != string(original.Condition) {
		t.Fatal("deactivation lost rule identity, condition or revision")
	}
	reactivated := disabled
	reactivated.Policy.Rules = append([]DLPRule{}, disabled.Policy.Rules...)
	reactivated.Policy.Rules[0].Mode = "active"
	requireHTTP(t, f.call("PUT", "/api/dlp/settings", map[string]any{"revision": reactivated.Revision, "policy": reactivated.Policy}, f.csrf), 409)
	if current := get(); current.Fingerprint != disabled.Fingerprint || current.Policy.Rules[0].Mode != "disabled" {
		t.Fatal("refused reactivation altered stored policy")
	}
	disabled.Policy.Rules = disabled.Policy.Rules[1:]
	requireHTTP(t, f.call("PUT", "/api/dlp/settings", map[string]any{"revision": disabled.Revision, "policy": disabled.Policy}, f.csrf), 200)
	if current := get(); len(current.Policy.Rules) != 1 || current.Policy.Rules[0].ID != "second" || current.Policy.Rules[0].Mode != "active" {
		t.Fatal("deletion changed unrelated rule")
	}
}
