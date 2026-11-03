package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestDLPNewOrganizationDefaultsPreserveSavedAndLegacyConsent(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	get := func() DLPSettings {
		t.Helper()
		w := f.call("GET", "/api/dlp/settings", nil, "")
		requireHTTP(t, w, 200)
		var settings DLPSettings
		if err := json.Unmarshal(w.Body.Bytes(), &settings); err != nil {
			t.Fatal(err)
		}
		return settings
	}
	initial := get()
	if !initial.Policy.Inspection || !initial.Policy.Journal || initial.Policy.NativeInspection != (Edition == "commercial") {
		t.Fatal("new organization inspection/journal defaults were not seeded")
	}
	expected := 0
	if Edition == "commercial" {
		expected = 11
	}
	if len(initial.Policy.Rules) != expected {
		t.Fatal("unexpected default rule count")
	}
	for _, rule := range initial.Policy.Rules {
		if rule.Mode != "disabled" {
			t.Fatal("default rule activated protection")
		}
	}
	initial.Policy.Inspection = false
	initial.Policy.NativeInspection = false
	initial.Policy.Journal = false
	requireHTTP(t, f.call("PUT", "/api/dlp/settings", map[string]any{"revision": initial.Revision, "policy": initial.Policy}, f.csrf), 200)
	saved := get()
	pool, err := OpenDatabase(ctx, f.a.config)
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	if current := get(); current.Fingerprint != saved.Fingerprint || current.Policy.Inspection || current.Policy.NativeInspection || current.Policy.Journal {
		t.Fatal("startup replaced saved inspection consent")
	}
	if _, err = f.admin.Exec(ctx, `DELETE FROM dlp_settings WHERE organization_id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	pool, err = OpenDatabase(ctx, f.a.config)
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	if current := get(); current.Policy.Inspection || current.Policy.NativeInspection {
		t.Fatal("upgrade activated inspection in an unconfigured legacy organization")
	}
}

func TestDLPDeploymentHostnamesRespectDeviceReadAliasesAndAggregate(t *testing.T) {
	p := newProjectionFixture(t)
	read := func(path string) string {
		t.Helper()
		w := p.as("owner", "GET", path, nil)
		requireHTTP(t, w, 200)
		return w.Body.String()
	}
	if !strings.Contains(read("/api/dlp/status"), p.s.host) {
		t.Fatal("deployment omitted authorized device hostname")
	}
	if strings.Contains(read("/api/dlp/status?identity=aliases"), p.s.host) {
		t.Fatal("deployment ignored alias-only identity preference")
	}
	w := p.as("owner", "POST", "/api/profile/api-keys", map[string]any{"name": "DLP status fixture", "expires_in_days": 30, "permissions": []string{permPolicyManage}})
	requireHTTP(t, w, 201)
	var key struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &key); err != nil {
		t.Fatal(err)
	}
	p.key = key.Secret
	w = p.as("key", "GET", "/api/dlp/status", nil)
	requireHTTP(t, w, 200)
	if strings.Contains(w.Body.String(), p.s.host) || strings.Contains(w.Body.String(), `"hostname"`) {
		t.Fatal("policy-only key obtained a device name")
	}
	cfg := defaultPrivacy()
	cfg.AggregateOnly = true
	requireHTTP(t, putPrivacyTest(t, p.observabilityFixture, cfg), 200)
	body := read("/api/dlp/status")
	if strings.Contains(body, p.s.host) || strings.Contains(body, p.device) || !strings.Contains(body, `"items":[]`) {
		t.Fatal("aggregate status leaked a device identity")
	}
}
