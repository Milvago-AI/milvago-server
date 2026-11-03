package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDLPDictionaryPositiveListKeepsLegacyBehaviorAndFrozenSnapshots(t *testing.T) {
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
	legacy := initial.Policy
	legacy.Detectors = append(legacy.Detectors, DLPDetector{ID: "words", Name: "Project words", Definition: dlpJSON(map[string]any{"kind": "dictionary", "values": []string{"Tomate", "Carotte"}, "exceptions": []string{"ＣＡＲＯＴＴＥ"}})})
	var parsed struct {
		Rule DLPRule `json:"rule"`
	}
	if err := dlpEngine(ctx, map[string]any{"op": "parse", "source": `WHEN prompt MATCHES detector("words") SCOPE channel = "browser" THEN BLOCK`}, &parsed); err != nil {
		t.Fatal(err)
	}
	parsed.Rule.Mode = "active"
	legacy.Rules = []DLPRule{parsed.Rule}
	tx, err := tenantTx(ctx, f.a.db, f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err = ensureDLPSnapshot(ctx, tx, f.org, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE dlp_settings SET policy=$2,revision=nextval('shadow_revision') WHERE organization_id=$1`, f.org, dlpJSON(legacy)); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	before := get()
	check := func(policy DLPPolicy) {
		t.Helper()
		var d struct {
			Kind       string   `json:"kind"`
			Values     []string `json:"values"`
			Exceptions []string `json:"exceptions"`
		}
		for _, item := range policy.Detectors {
			if item.ID == "words" {
				if err := json.Unmarshal(item.Definition, &d); err != nil {
					t.Fatal(err)
				}
			}
		}
		if len(d.Values) != 1 || d.Values[0] != "Tomate" || len(d.Exceptions) != 0 {
			t.Fatal("legacy dictionary exclusions changed behavior")
		}
	}
	check(before.Policy)
	requireHTTP(t, f.call("PUT", "/api/dlp/settings", map[string]any{"revision": before.Revision, "policy": before.Policy}, f.csrf), 200)
	after := get()
	check(after.Policy)
	if before.Fingerprint != after.Fingerprint || before.Policy.Rules[0].Revision != after.Policy.Rules[0].Revision {
		t.Fatal("normalization caused a second behavior revision")
	}
	var frozen bool
	if err = f.admin.QueryRow(ctx, `SELECT policy=$2::jsonb FROM dlp_policy_snapshots WHERE organization_id=$1 AND fingerprint=$3`, f.org, dlpJSON(legacy), dlpFingerprint(legacy)).Scan(&frozen); err != nil || !frozen {
		t.Fatal("historical snapshot was rewritten", err)
	}
	secret := randomToken()
	if _, err = f.admin.Exec(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,kind,capabilities) VALUES($1,$2,'Dictionary fixture','test','0','approved','browser','["dlp-v1"]')`, f.org, hash(secret)); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/v4/policy", nil)
	r.Header.Set("Authorization", "Bearer "+secret)
	w := httptest.NewRecorder()
	f.a.Handler().ServeHTTP(w, r)
	requireHTTP(t, w, 200)
	var envelope map[string]string
	if err = json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(envelope["payload"])
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Config struct {
			DLP DLPPolicy `json:"dlp"`
		} `json:"config"`
	}
	if err = json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	check(payload.Config.DLP)
	if !strings.Contains(string(raw), `"exceptions":[]`) {
		t.Fatal("legacy engine wire field missing")
	}
}
