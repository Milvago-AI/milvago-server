package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDLPMultipleTargetsPersistAndSignCompatiblePolicy(t *testing.T) {
	f := newDLPFixtureWithoutDefaultRules(t)
	ctx := context.Background()
	groups := []string{}
	devices := []string{}
	credentials := []string{}
	for index := 0; index < 3; index++ {
		var group, device string
		if err := f.admin.QueryRow(ctx, `INSERT INTO device_groups(organization_id,name) VALUES($1,$2) RETURNING id`, f.org, "Multiple target fixture "+string(rune('A'+index))).Scan(&group); err != nil {
			t.Fatal(err)
		}
		caps := `["dlp-v1"]`
		if index == 2 {
			caps = `[]`
		}
		credential := randomToken()
		if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,kind,capabilities,group_id) VALUES($1,$2,'Multiple target fixture','test','0','approved','browser',$3,$4) RETURNING id`, f.org, hash(credential), caps, group).Scan(&device); err != nil {
			t.Fatal(err)
		}
		groups = append(groups, group)
		devices = append(devices, device)
		credentials = append(credentials, credential)
	}
	callDevice := func(index int, method, path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(method, path, bytes.NewReader(raw))
		r.Header.Set("Authorization", "Bearer "+credentials[index])
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.a.Handler().ServeHTTP(w, r)
		return w
	}
	current := f.call("GET", "/api/dlp/settings", nil, "")
	requireHTTP(t, current, 200)
	var settings DLPSettings
	if err := json.Unmarshal(current.Body.Bytes(), &settings); err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Rule DLPRule `json:"rule"`
	}
	if err := dlpEngine(ctx, map[string]any{"op": "parse", "source": `WHEN prompt CONTAINS "fixture" SCOPE channel = "browser" THEN BLOCK`}, &parsed); err != nil {
		t.Fatal(err)
	}
	parsed.Rule.Mode = "active"
	parsed.Rule.Application = &DLPApplication{Kind: "groups", IDs: groups[:2]}
	settings.Policy.Rules = []DLPRule{parsed.Rule}
	settings.Policy.Inspection = true
	saved := f.call("PUT", "/api/dlp/settings", map[string]any{"revision": settings.Revision, "policy": settings.Policy, "inherited": false}, f.csrf)
	requireHTTP(t, saved, 200)
	if err := json.Unmarshal(saved.Body.Bytes(), &settings); err != nil {
		t.Fatal(err)
	}
	if settings.Policy.Rules[0].Application.Kind != "groups" || len(settings.Policy.Rules[0].Application.IDs) != 2 {
		t.Fatal("multiple target metadata lost")
	}
	if len(dlpPolicyForDevice(settings.Policy, devices[2], &groups[2]).Rules) != 0 {
		t.Fatal("unrelated legacy device became a target")
	}
	signed := callDevice(0, "GET", "/v4/policy", nil)
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
		Revision int64                      `json:"revision"`
		Config   map[string]json.RawMessage `json:"config"`
	}
	if err = json.Unmarshal(raw, &delivered); err != nil {
		t.Fatal(err)
	}
	var wire DLPPolicy
	var fingerprint string
	if err = json.Unmarshal(delivered.Config["dlp"], &wire); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(delivered.Config["dlp_fingerprint"], &fingerprint); err != nil {
		t.Fatal(err)
	}
	if wire.Rules[0].Application != nil || strings.Contains(string(delivered.Config["dlp"]), `"ids"`) {
		t.Fatal("new metadata leaked into the legacy wire format")
	}
	if fingerprint == settings.Fingerprint || fingerprint != dlpFingerprint(wire) {
		t.Fatal("delivered fingerprint does not describe delivered policy")
	}
	if err = dlpEngine(ctx, map[string]any{"op": "validate", "policy": wire}, nil); err != nil {
		t.Fatal(err)
	}
	for _, group := range groups {
		input := DLPInput{Policy: wire, Texts: map[string][]string{"prompt": {"fixture"}}, Facts: map[string]string{"channel": "browser", "group_id": group}}
		var result struct {
			Result DLPOutput `json:"result"`
		}
		if err = dlpEngine(ctx, map[string]any{"op": "evaluate", "input": input}, &result); err != nil {
			t.Fatal(err)
		}
		expected := "block"
		if group == groups[2] {
			expected = "observe"
		}
		if result.Result.Action != expected || len(result.Result.Decisions) > 1 {
			t.Fatal("target union or single-evaluation invariant failed")
		}
	}
	report := map[string]string{"fingerprint": fingerprint, "channel": "browser", "tool": "chrome", "mechanism": "browser-engine", "status": "applied"}
	requireHTTP(t, callDevice(0, "POST", "/v4/dlp/enforcement", report), 200)
	report["fingerprint"] = settings.Fingerprint
	requireHTTP(t, callDevice(0, "POST", "/v4/dlp/enforcement", report), 409)
	status := f.call("GET", "/api/dlp/status?device_id="+devices[0], nil, "")
	requireHTTP(t, status, 200)
	var coverage struct {
		Items []struct {
			Expected string `json:"expected_fingerprint"`
			Applied  string `json:"applied_fingerprint"`
			Status   string `json:"status"`
		} `json:"items"`
	}
	if err = json.Unmarshal(status.Body.Bytes(), &coverage); err != nil {
		t.Fatal(err)
	}
	if len(coverage.Items) != 1 || coverage.Items[0].Expected != fingerprint || coverage.Items[0].Applied != fingerprint || coverage.Items[0].Status != "applied" {
		t.Fatalf("coverage disagrees with signed delivery: %s", status.Body.String())
	}
	var count int
	if err = f.admin.QueryRow(ctx, `SELECT count(*) FROM dlp_device_policy_history WHERE device_id=$1 AND fingerprint=$2 AND revision=$3`, devices[0], fingerprint, delivered.Revision).Scan(&count); err != nil || count != 1 {
		t.Fatal("missing delivered custody history", err)
	}
}
