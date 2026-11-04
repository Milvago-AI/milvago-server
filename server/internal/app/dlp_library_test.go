package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestDLPLibraryEditionCollisionAndIdempotence(t *testing.T) {
	p := defaultDLP("endpoint")
	p.Detectors = []DLPDetector{{ID: "builtin-email", Name: "Custom fixture", Definition: dlpJSON(map[string]any{"kind": "literal", "value": "fixture", "ignore_case": true, "whole_word": false, "unicode": true})}}
	seeded := withDefaultDLPDetectors(p)
	if seeded.Inspection || seeded.NativeInspection || len(seeded.Rules) != 0 {
		t.Fatal("library activated inspection or rules")
	}
	if seeded.Detectors[0].Name != "Custom fixture" {
		t.Fatal("custom collision overwritten")
	}
	if Edition == "commercial" {
		if len(seeded.Detectors) != 13 {
			t.Fatalf("missing default categories: %d", len(seeded.Detectors))
		}
		if err := validateDLPEdition(seeded); err != nil {
			t.Fatal(err)
		}
		if err := dlpEngine(context.Background(), map[string]any{"op": "validate", "policy": seeded}, nil); err != nil {
			t.Fatal(err)
		}
	} else {
		if len(seeded.Detectors) != 1 {
			t.Fatal("Community seeded default detectors")
		}
		hostile := p
		hostile.Detectors = []DLPDetector{{ID: "fixture", Name: "Fixture", Definition: dlpJSON(map[string]string{"kind": "builtin", "category": "ca_sin"})}}
		if validateDLPEdition(hostile) == nil {
			t.Fatal("Community accepted a predefined detector")
		}
	}
	if string(dlpJSON(seeded)) != string(dlpJSON(withDefaultDLPDetectors(seeded))) {
		t.Fatal("seeding is not idempotent")
	}
}

func TestDLPRuleApplicationRESTAndEditionBoundary(t *testing.T) {
	f := newDLPFixtureWithoutDefaultRules(t)
	ctx := context.Background()
	var group, device string
	if err := f.admin.QueryRow(ctx, `INSERT INTO device_groups(organization_id,name) VALUES($1,'Application fixture') RETURNING id`, f.org).Scan(&group); err != nil {
		t.Fatal(err)
	}
	if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,kind,capabilities) VALUES($1,$2,'Application fixture','test','0','approved','browser','["dlp-v1"]') RETURNING id`, f.org, hash(randomToken())).Scan(&device); err != nil {
		t.Fatal(err)
	}
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
	s := get()
	if Edition != "commercial" && len(s.Policy.Detectors) != 0 {
		t.Fatal("Community API exposed predefined detectors")
	}
	if Edition == "commercial" && len(s.Policy.Detectors) < 11 {
		t.Fatal("Enterprise API omitted predefined detectors")
	}
	for _, target := range []*DLPApplication{{Kind: "group", ID: strings.ToUpper(group)}, {Kind: "device", ID: strings.ToUpper(device)}, {Kind: "organization"}} {
		var parsed struct {
			Rule DLPRule `json:"rule"`
		}
		if err := dlpEngine(ctx, map[string]any{"op": "parse", "source": `WHEN prompt CONTAINS "fixture" SCOPE TRUE THEN BLOCK`}, &parsed); err != nil {
			t.Fatal(err)
		}
		if len(s.Policy.Rules) > 0 {
			parsed.Rule.Revision = s.Policy.Rules[0].Revision
		}
		parsed.Rule.Application = target
		s.Policy.Rules = []DLPRule{parsed.Rule}
		requireHTTP(t, f.call("PUT", "/api/dlp/settings", map[string]any{"revision": s.Revision, "policy": s.Policy, "inherited": false}, f.csrf), 200)
		s = get()
		if s.Policy.Rules[0].Application == nil || s.Policy.Rules[0].Application.Kind != target.Kind || s.Policy.Rules[0].Application.ID != strings.ToLower(target.ID) {
			t.Fatal("rule application lost")
		}
	}
	before := s.Fingerprint
	s.Policy.Rules[0].Application = &DLPApplication{Kind: "device", ID: "00000000-0000-4000-8000-000000000001"}
	requireHTTP(t, f.call("PUT", "/api/dlp/settings", map[string]any{"revision": s.Revision, "policy": s.Policy, "inherited": false}, f.csrf), 404)
	if get().Fingerprint != before {
		t.Fatal("invalid target changed policy")
	}
	requireHTTP(t, f.call("GET", "/api/dlp/settings?domain=server", nil, ""), 400)
	s = get()
	s.Policy.Domain = "server"
	requireHTTP(t, f.call("POST", "/api/dlp/evaluate", DLPInput{Policy: s.Policy, Texts: map[string][]string{"prompt": {"fixture"}}, Facts: map[string]string{"channel": "browser"}}, f.csrf), 400)
	if Edition != "commercial" {
		s = get()
		s.Policy.Detectors = append(s.Policy.Detectors, DLPDetector{ID: "predefined-fixture", Name: "Fixture", Definition: dlpJSON(map[string]string{"kind": "builtin", "category": "email"})})
		w := f.call("PUT", "/api/dlp/settings", map[string]any{"revision": s.Revision, "policy": s.Policy, "inherited": false}, f.csrf)
		requireHTTP(t, w, 409)
		if !strings.Contains(w.Body.String(), "capability_unavailable") {
			t.Fatal("wrong edition rejection")
		}
	}
}

func TestDLPActivationIgnoresDevicesOutsideRuleApplication(t *testing.T) {
	f := newDLPFixtureWithoutDefaultRules(t)
	ctx := context.Background()
	var target, legacy string
	for index, caps := range []string{`["dlp-v1"]`, `[]`} {
		var id string
		if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,kind,capabilities) VALUES($1,$2,'Target fixture','test','0','approved','browser',$3) RETURNING id`, f.org, hash(randomToken()), caps).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			target = id
		} else {
			legacy = id
		}
	}
	w := f.call("GET", "/api/dlp/settings", nil, "")
	requireHTTP(t, w, 200)
	var s DLPSettings
	if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Rule DLPRule `json:"rule"`
	}
	if err := dlpEngine(ctx, map[string]any{"op": "parse", "source": `WHEN prompt CONTAINS "fixture" SCOPE channel = "browser" THEN BLOCK`}, &parsed); err != nil {
		t.Fatal(err)
	}
	parsed.Rule.Mode = "active"
	parsed.Rule.Application = &DLPApplication{Kind: "device", ID: target}
	s.Policy.Inspection = true
	s.Policy.Rules = []DLPRule{parsed.Rule}
	w = f.call("PUT", "/api/dlp/settings", map[string]any{"revision": s.Revision, "policy": s.Policy, "inherited": false}, f.csrf)
	requireHTTP(t, w, 200)
	if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	if len(dlpPolicyForDevice(s.Policy, legacy, nil).Rules) != 0 {
		t.Fatal("legacy compatibility widened a targeted rule")
	}
	if len(dlpPolicyForDevice(s.Policy, target, nil).Rules) != 1 {
		t.Fatal("targeted rule lost")
	}
	s.Policy.Rules[0].Application = &DLPApplication{Kind: "organization"}
	requireHTTP(t, f.call("PUT", "/api/dlp/settings", map[string]any{"revision": s.Revision, "policy": s.Policy, "inherited": false}, f.csrf), 409)
}

func TestDLPNativeQualificationUsesOnlyRelevantRuleApplications(t *testing.T) {
	p := defaultDLP("endpoint")
	p.Inspection = true
	p.NativeInspection = true
	for _, channel := range []string{"browser", "native"} {
		var parsed struct {
			Rule DLPRule `json:"rule"`
		}
		if err := dlpEngine(context.Background(), map[string]any{"op": "parse", "source": `WHEN TRUE SCOPE channel = "` + channel + `" THEN BLOCK`}, &parsed); err != nil {
			t.Fatal(err)
		}
		parsed.Rule.ID = channel
		parsed.Rule.Mode = "active"
		parsed.Rule.Application = &DLPApplication{Kind: "device", ID: "00000000-0000-4000-8000-000000000001"}
		p.Rules = append(p.Rules, parsed.Rule)
	}
	relevant, err := nativeDLPProtection(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if len(relevant.Rules) != 1 || relevant.Rules[0].ID != "native" || relevant.Rules[0].Application == nil {
		t.Fatal("qualification lost a target or included a browser-only rule")
	}
	required, err := requiresNativeDLPSupport(context.Background(), dlpPolicyForDevice(p, "00000000-0000-4000-8000-000000000002", nil))
	if err != nil || required {
		t.Fatal("unrelated device inherited native qualification requirement", err)
	}
}
