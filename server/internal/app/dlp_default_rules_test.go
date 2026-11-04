package app

import (
	"context"
	"encoding/json"
	"testing"
)

func TestDLPDefaultProtectionAndCustomDeletionAreAtomic(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	get := func() DLPSettings {
		w := f.call("GET", "/api/dlp/settings", nil, "")
		requireHTTP(t, w, 200)
		var s DLPSettings
		if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	put := func(s DLPSettings, status int) {
		requireHTTP(t, f.call("PUT", "/api/dlp/settings", map[string]any{"revision": s.Revision, "policy": s.Policy}, f.csrf), status)
	}
	original := get()
	if Edition == "commercial" && len(original.DefaultRuleIDs) != 11 {
		t.Fatal("default identities were not published")
	}
	if Edition != "commercial" && len(original.DefaultRuleIDs) != 0 {
		t.Fatal("Community acquired predefined objects")
	}
	custom := DLPRule{ID: "preset-mask-email-custom", Revision: 1, Name: "Synthetic custom", Mode: "disabled", Priority: 100, Condition: dlpJSON(map[string]string{"op": "true"}), Scope: dlpJSON(map[string]string{"op": "true"}), Consequence: dlpJSON(map[string]string{"action": "block"})}
	original.Policy.Rules = append(original.Policy.Rules, custom)
	put(original, 200)
	saved := get()
	if Edition == "commercial" {
		forged := saved
		forged.Policy.Rules = []DLPRule{}
		put(forged, 409)
		if get().Fingerprint != saved.Fingerprint {
			t.Fatal("mixed deletion partially committed")
		}
		renamed := saved
		renamed.Policy.Rules = append([]DLPRule{}, saved.Policy.Rules...)
		renamed.Policy.Rules[0].Name = "Renamed default"
		renamed.Policy.Rules[0].Consequence = dlpJSON(map[string]string{"action": "observe"})
		put(renamed, 200)
		changed := get()
		if len(changed.DefaultRuleIDs) != 11 {
			t.Fatal("editing removed provenance")
		}
		changed.Policy.Rules = changed.Policy.Rules[1:]
		put(changed, 409)
		requireHTTP(t, f.call("PUT", "/api/dlp/settings", map[string]any{"revision": get().Revision, "policy": get().Policy, "default_rule_ids": []string{}}, f.csrf), 400)
	}
	saved = get()
	kept := []DLPRule{}
	for _, r := range saved.Policy.Rules {
		if r.ID != custom.ID {
			kept = append(kept, r)
		}
	}
	saved.Policy.Rules = kept
	put(saved, 200)
	if len(get().Policy.Rules) != len(original.Policy.Rules)-1 {
		t.Fatal("custom deletion changed unrelated defaults")
	}
	pool, err := OpenDatabase(ctx, f.a.config)
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	if len(get().DefaultRuleIDs) != len(saved.DefaultRuleIDs) {
		t.Fatal("restart changed default identities")
	}
}
