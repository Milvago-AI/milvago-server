package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAIGovernanceUUIDCasePreservesScopeAndExceptions(t *testing.T) {
	now := time.Now()
	device := "abcdef12-abcd-4abc-8abc-abcdef123456"
	group := "fedcba12-abcd-4abc-8abc-abcdef123456"
	rule := AIGovernanceRule{ID: "uuid-case", Application: "fixture", Activity: "execution", Scope: "device", Target: strings.ToUpper(device), Decision: "deny", AllowExceptions: true, Owner: "Security", Purpose: "UUID scope regression", ReviewDue: now.Add(time.Hour)}
	for _, scope := range []string{"device", "group"} {
		r := rule
		r.Scope = scope
		if scope == "group" {
			r.Target = strings.ToUpper(group)
		}
		layer := aiGovernanceLayer{Organization: "o", Revision: 7, Document: AIGovernanceDocument{Version: 1, Rules: []AIGovernanceRule{r}}}
		got := evaluateAIGovernance([]aiGovernanceLayer{layer}, nil, "o", device, group, "fixture", "execution", true, now)
		if got.Status != "deviation" || got.Rule != rule.ID {
			t.Fatalf("%s UUID spelling lost scope: %+v", scope, got)
		}
		exception := aiGovernanceException{ID: "exception", Device: device, Rule: rule.ID, Revision: 7, ExpiresAt: now.Add(time.Minute)}
		got = evaluateAIGovernance([]aiGovernanceLayer{layer}, []aiGovernanceException{exception}, "o", strings.ToUpper(device), strings.ToUpper(group), "fixture", "execution", true, now)
		if got.Status != "allowed" || got.Exception != exception.ID {
			t.Fatalf("%s UUID spelling lost exception: %+v", scope, got)
		}
		duplicate := r
		duplicate.ID = "duplicate"
		duplicate.Target = strings.ToLower(r.Target)
		if (AIGovernanceDocument{Version: 1, Rules: []AIGovernanceRule{r, duplicate}}).validate(now) == nil {
			t.Fatal("same UUID scope accepted twice with different spelling")
		}
	}
}

func TestAIGovernanceUUIDCaseAPI(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	device := "abcdef12-abcd-4abc-8abc-abcdef123456"
	if _, err := f.admin.Exec(ctx, `INSERT INTO devices(organization_id,id,credential_hash,hostname,platform,version,status) VALUES($1,$2,$3,'UUID fixture','test','0.7.0','approved')`, f.org, device, hash(randomToken())); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `UPDATE sessions SET mfa_verified_at=now() WHERE user_id=$1`, f.user); err != nil {
		t.Fatal(err)
	}
	rule := AIGovernanceRule{ID: "uuid-case", Application: "fixture", Activity: "execution", Scope: "device", Target: strings.ToUpper(device), Decision: "deny", AllowExceptions: true, Owner: "Security", Purpose: "UUID API regression", ReviewDue: time.Now().Add(time.Hour)}
	response := f.call("PUT", "/api/ai-governance/policy", map[string]any{"revision": 0, "document": AIGovernanceDocument{Version: 1, Rules: []AIGovernanceRule{rule}}, "reason": "Case insensitive device target"}, f.csrf)
	requireHTTP(t, response, 200)
	var published struct {
		Revision int64                `json:"revision"`
		Document AIGovernanceDocument `json:"document"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &published); err != nil {
		t.Fatal(err)
	}
	if len(published.Document.Rules) != 1 || published.Document.Rules[0].Target != device {
		t.Fatal("published UUID was not canonical for the target picker")
	}
	policy := f.call("GET", "/api/ai-governance/policy", nil, "")
	requireHTTP(t, policy, 200)
	var stored aiGovernanceLayer
	if err := json.Unmarshal(policy.Body.Bytes(), &stored); err != nil || len(stored.Document.Rules) != 1 || stored.Document.Rules[0].Target != device {
		t.Fatal("policy target spelling changed", err)
	}
	raw, err := json.Marshal(AIGovernanceDocument{Version: 1, Rules: []AIGovernanceRule{rule}})
	if err != nil {
		t.Fatal(err)
	}
	preview := f.call("POST", "/api/ai-governance/validate", map[string]string{"source": string(raw)}, f.csrf)
	requireHTTP(t, preview, 200)
	var validated struct {
		Document AIGovernanceDocument `json:"document"`
	}
	if err := json.Unmarshal(preview.Body.Bytes(), &validated); err != nil || len(validated.Document.Rules) != 1 || validated.Document.Rules[0].Target != device {
		t.Fatal("preview UUID was not canonical for the target picker", err)
	}
	check := func(decision string, exception bool) {
		t.Helper()
		for _, spelling := range []string{device, strings.ToUpper(device)} {
			url := "/api/ai-governance/effective?application_id=fixture&device_id=" + spelling
			result := f.call("GET", url, nil, "")
			requireHTTP(t, result, 200)
			var body struct {
				Device     string `json:"device_id"`
				Governance struct {
					Execution aiGovernanceAssessment `json:"execution"`
				} `json:"governance"`
			}
			if err := json.Unmarshal(result.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			assessment := body.Governance.Execution
			if body.Device != device || assessment.Rule != rule.ID || assessment.Decision != decision || (assessment.Exception != "") != exception || assessment.Status != "insufficient_evidence" {
				t.Fatalf("UUID request changed authorization or invented evidence: %+v", body)
			}
		}
	}
	check("deny", false)
	options := f.call("GET", "/api/ai-governance/approval-options?application_id=fixture&device_id="+strings.ToUpper(device), nil, "")
	requireHTTP(t, options, 200)
	var choices struct {
		Rules []AIGovernanceRule `json:"rules"`
	}
	if err := json.Unmarshal(options.Body.Bytes(), &choices); err != nil || len(choices.Rules) != 1 {
		t.Fatal("case changed approval options", err, options.Body.String())
	}
	requireHTTP(t, f.call("POST", "/api/ai-governance/exceptions", map[string]any{"device_id": strings.ToUpper(device), "rule_id": rule.ID, "revision": published.Revision, "reason": "Approved UUID case regression", "expires_at": time.Now().Add(time.Minute)}, f.csrf), 201)
	check("allow", true)
}

func TestAIGovernanceScopeEvidenceAndExceptionScenarios(t *testing.T) {
	now := time.Now().UTC()
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)
	rule := func(id, scope, target, decision string) AIGovernanceRule {
		return AIGovernanceRule{ID: id, Application: "fixture", Activity: "execution", Scope: scope, Target: target, Decision: decision, Owner: "Security", Purpose: "Approved test purpose", ReviewDue: future}
	}
	org := rule("org", "organization", "", "deny")
	group := rule("group", "group", "g", "allow")
	device := rule("device", "device", "d", "deny")
	layer := func(rules ...AIGovernanceRule) aiGovernanceLayer {
		return aiGovernanceLayer{Organization: "o", Revision: 7, Document: AIGovernanceDocument{Version: 1, Rules: rules}}
	}
	mandatory := org
	mandatory.Mandatory = true
	exceptional := mandatory
	exceptional.AllowExceptions = true
	expired := device
	expired.ValidUntil = &past
	overdue := group
	overdue.ReviewDue = past
	wildcard := org
	wildcard.Application = "*"
	allow := group
	allow.ID = "specific"
	allow.Scope = "organization"
	allow.Target = ""
	exception := aiGovernanceException{ID: "e", Device: "d", Rule: "org", Revision: 7, ExpiresAt: future}
	tests := []struct {
		name                    string
		layers                  []aiGovernanceLayer
		exceptions              []aiGovernanceException
		device, group, activity string
		proven                  bool
		status, decision, rule  string
	}{
		{"no policy", nil, nil, "d", "g", "execution", true, "no_rule", "", ""},
		{"organization denial", []aiGovernanceLayer{layer(org)}, nil, "d", "g", "execution", true, "deviation", "deny", "org"},
		{"group permission", []aiGovernanceLayer{layer(org, group)}, nil, "d", "g", "execution", true, "allowed", "allow", "group"},
		{"device override", []aiGovernanceLayer{layer(org, group, device)}, nil, "d", "g", "execution", true, "deviation", "deny", "device"},
		{"another device", []aiGovernanceLayer{layer(org, group, device)}, nil, "other", "g", "execution", true, "allowed", "allow", "group"},
		{"changed group", []aiGovernanceLayer{layer(org, group)}, nil, "d", "other", "execution", true, "deviation", "deny", "org"},
		{"mandatory cannot relax", []aiGovernanceLayer{layer(mandatory, group)}, nil, "d", "g", "execution", true, "deviation", "deny", "org"},
		{"approved exception", []aiGovernanceLayer{layer(exceptional)}, []aiGovernanceException{exception}, "d", "g", "execution", true, "allowed", "allow", "org"},
		{"exception forbidden", []aiGovernanceLayer{layer(mandatory)}, []aiGovernanceException{exception}, "d", "g", "execution", true, "deviation", "deny", "org"},
		{"exception other device", []aiGovernanceLayer{layer(exceptional)}, []aiGovernanceException{exception}, "other", "g", "execution", true, "deviation", "deny", "org"},
		{"presence never execution", []aiGovernanceLayer{layer(org)}, nil, "d", "g", "execution", false, "insufficient_evidence", "deny", "org"},
		{"opaque VM no software rule inference", []aiGovernanceLayer{layer(org)}, nil, "d", "g", "presence", false, "no_rule", "", ""},
		{"expired rule", []aiGovernanceLayer{layer(org, expired)}, nil, "d", "g", "execution", true, "deviation", "deny", "org"},
		{"overdue permission", []aiGovernanceLayer{layer(overdue)}, nil, "d", "g", "execution", true, "review_due", "allow", "group"},
		{"specific application", []aiGovernanceLayer{layer(wildcard, allow)}, nil, "d", "g", "execution", true, "allowed", "allow", "specific"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := evaluateAIGovernance(tc.layers, tc.exceptions, "o", tc.device, tc.group, "fixture", tc.activity, tc.proven, now)
			if got.Status != tc.status || got.Decision != tc.decision || got.Rule != tc.rule || got.Enforcement != "detection_only" {
				t.Fatalf("assessment %+v", got)
			}
		})
	}
	for _, kind := range []string{"expired", "revoked", "old revision"} {
		t.Run(kind+" exception", func(t *testing.T) {
			e := exception
			switch kind {
			case "expired":
				e.ExpiresAt = past
			case "revoked":
				e.RevokedAt = &past
			case "old revision":
				e.Revision--
			}
			got := evaluateAIGovernance([]aiGovernanceLayer{layer(exceptional)}, []aiGovernanceException{e}, "o", "d", "g", "fixture", "execution", true, now)
			if got.Status != "deviation" {
				t.Fatal(got)
			}
		})
	}
	parent := layer(mandatory)
	allowedDevice := device
	allowedDevice.Decision = "allow"
	if got := evaluateAIGovernance([]aiGovernanceLayer{layer(exceptional, allowedDevice)}, []aiGovernanceException{exception}, "o", "d", "g", "fixture", "execution", true, now); got.Status != "allowed" || got.Rule != "device" || got.Exception != "e" || len(got.Exceptions) != 1 {
		t.Fatal("mandatory exception provenance lost behind a specific permission", got)
	}
	parent.Organization = "parent"
	if got := evaluateAIGovernance([]aiGovernanceLayer{parent, layer(group)}, nil, "o", "d", "g", "fixture", "execution", true, now); got.Status != "deviation" || got.Organization != "parent" {
		t.Fatal("parent restriction relaxed", got)
	}
	parent.Document.Rules = []AIGovernanceRule{exceptional}
	if got := evaluateAIGovernance([]aiGovernanceLayer{parent, layer(group)}, []aiGovernanceException{exception}, "o", "d", "g", "fixture", "execution", true, now); got.Status != "deviation" {
		t.Fatal("descendant approved parent exception", got)
	}
}

func TestAIGovernancePolicyAndExceptionsAPI(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	device := "00000000-0000-4000-8000-000000000001"
	if _, err := f.admin.Exec(ctx, `INSERT INTO devices(organization_id,id,credential_hash,hostname,platform,version,status) VALUES($1,$2,$3,'Fixture','test','0.7.0','approved')`, f.org, device, hash(randomToken())); err != nil {
		t.Fatal(err)
	}
	rule := AIGovernanceRule{ID: "execution-denial", Application: "fixture", Activity: "execution", Scope: "organization", Decision: "deny", Mandatory: true, AllowExceptions: true, Owner: "Security", Purpose: "Approved test purpose", ReviewDue: time.Now().Add(24 * time.Hour)}
	body := map[string]any{"revision": 0, "document": AIGovernanceDocument{Version: 1, Rules: []AIGovernanceRule{rule}}, "reason": "Test organization policy"}
	requireHTTP(t, f.call("PUT", "/api/ai-governance/policy", body, f.csrf), 403)
	if _, err := f.admin.Exec(ctx, `UPDATE sessions SET mfa_verified_at=now() WHERE user_id=$1`, f.user); err != nil {
		t.Fatal(err)
	}
	published := f.call("PUT", "/api/ai-governance/policy", body, f.csrf)
	requireHTTP(t, published, 200)
	var result struct {
		Revision int64 `json:"revision"`
	}
	if err := json.Unmarshal(published.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	requireHTTP(t, f.call("PUT", "/api/ai-governance/policy", body, f.csrf), 409)
	effective := f.call("GET", "/api/ai-governance/effective?application_id=fixture&device_id="+device, nil, "")
	requireHTTP(t, effective, 200)

	// Inspect a typed subobject: other governance metadata is not an assessment.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(effective.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	var g map[string]json.RawMessage
	_ = json.Unmarshal(raw["governance"], &g)
	var exec aiGovernanceAssessment
	_ = json.Unmarshal(g["execution"], &exec)
	if exec.Status != "insufficient_evidence" {
		t.Fatal("missing observations treated as compliance", exec)
	}
	exception := map[string]any{"device_id": device, "rule_id": rule.ID, "revision": result.Revision, "reason": "Temporary approved work", "expires_at": time.Now().Add(time.Hour)}
	approved := f.call("POST", "/api/ai-governance/exceptions", exception, f.csrf)
	requireHTTP(t, approved, 201)
	requireHTTP(t, f.call("POST", "/api/ai-governance/exceptions", exception, f.csrf), 409)
	var identity struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(approved.Body.Bytes(), &identity)
	requireHTTP(t, f.call("GET", "/api/ai-governance/exceptions?device_id="+device, nil, ""), 200)
	requireHTTP(t, f.call("POST", "/api/ai-governance/exceptions/"+identity.ID+"/revoke", map[string]string{"reason": "Temporary work completed"}, f.csrf), 200)
	requireHTTP(t, f.call("POST", "/api/ai-governance/exceptions/"+identity.ID+"/revoke", map[string]string{"reason": "Repeated revocation attempt"}, f.csrf), 404)
	history := f.call("GET", "/api/ai-governance/history?limit=1", nil, "")
	requireHTTP(t, history, 200)
	var page struct {
		Items []map[string]any `json:"items"`
		Next  string           `json:"next_cursor"`
	}
	_ = json.Unmarshal(history.Body.Bytes(), &page)
	if len(page.Items) != 1 || page.Next == "" {
		t.Fatal("missing paginated history", history.Body.String())
	}
	requireHTTP(t, f.call("GET", "/api/ai-governance/framework", nil, ""), 200)
	for _, doc := range []any{map[string]any{"version": 1, "rules": "data:image/png"}, map[string]any{"version": 1, "rules": nil}} {
		body["document"] = doc
		body["revision"] = result.Revision
		requireHTTP(t, f.call("PUT", "/api/ai-governance/policy", body, f.csrf), 400)
	}
	for _, source := range []any{map[string]string{"image": "data:image/png"}, "version: 1\nrules: []\nunknown: true", "version: 1\nrules: []\n---\nversion: 1\nrules: []"} {
		requireHTTP(t, f.call("POST", "/api/ai-governance/validate", map[string]any{"source": source}, f.csrf), 400)
	}
	requireHTTP(t, f.call("POST", "/api/ai-governance/validate", map[string]any{"source": "version: 1\nrules: []"}, f.csrf), 200)
	// Ordinary discovery management must not grant business policy publication.
	if _, err := f.admin.Exec(ctx, `INSERT INTO roles(organization_id,name,permissions) VALUES($1,'discovery-only',ARRAY['discovery.read','discovery.manage','devices.read'])`, f.org); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `UPDATE memberships SET role='discovery-only' WHERE organization_id=$1 AND user_id=$2`, f.org, f.user); err != nil {
		t.Fatal(err)
	}
	requireHTTP(t, f.call("GET", "/api/ai-governance/policy", nil, ""), 403)
	requireHTTP(t, f.call("PUT", "/api/ai-governance/policy", body, f.csrf), 403)
	requireHTTP(t, f.call("POST", "/api/ai-governance/exceptions", exception, f.csrf), 403)
	requireHTTP(t, f.call("GET", "/api/ai-governance/effective?application_id=fixture&device_id="+device, nil, ""), 200)
	requireHTTP(t, f.call("GET", "/api/ai-governance/approval-options?application_id=fixture&device_id="+device, nil, ""), 403)
	if _, err := f.admin.Exec(ctx, `INSERT INTO roles(organization_id,name,permissions) VALUES($1,'approver',ARRAY['discovery.read','devices.read','ai.governance.approve'])`, f.org); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `UPDATE memberships SET role='approver' WHERE organization_id=$1 AND user_id=$2`, f.org, f.user); err != nil {
		t.Fatal(err)
	}
	requireHTTP(t, f.call("GET", "/api/ai-governance/approval-options?application_id=fixture&device_id="+device, nil, ""), 200)
	requireHTTP(t, f.call("GET", "/api/ai-governance/policy", nil, ""), 403)
	requireHTTP(t, f.call("PUT", "/api/ai-governance/policy", body, f.csrf), 403)
	requireHTTP(t, f.call("POST", "/api/ai-governance/exceptions", exception, f.csrf), 201)
	requireHTTP(t, f.call("GET", "/api/ai-governance/exceptions?device_id="+device, nil, ""), 200)
}

func TestAIGovernanceValidationLimits(t *testing.T) {
	now := time.Now()
	base := AIGovernanceRule{ID: "fixture", Application: "fixture", Activity: "execution", Scope: "organization", Decision: "allow", Owner: "Owner", Purpose: "Valid test purpose", ReviewDue: now.Add(time.Hour)}
	for _, tc := range []struct {
		name   string
		change func(*AIGovernanceRule)
	}{
		{"mandatory allow", func(r *AIGovernanceRule) { r.Mandatory = true }},
		{"allow exceptions on permission", func(r *AIGovernanceRule) { r.AllowExceptions = true }},
		{"script activity", func(r *AIGovernanceRule) { r.Activity = "exec(script)" }},
		{"invalid group", func(r *AIGovernanceRule) { r.Scope = "group"; r.Target = "data:image/png" }},
		{"org target injection", func(r *AIGovernanceRule) { r.Target = "another-org" }},
		{"expired validity", func(r *AIGovernanceRule) { past := now.Add(-time.Hour); r.ValidUntil = &past }},
		{"unbounded owner", func(r *AIGovernanceRule) { r.Owner = string(make([]byte, 201)) }},
		{"nul owner", func(r *AIGovernanceRule) { r.Owner = "Security\x00Owner" }},
		{"control purpose", func(r *AIGovernanceRule) { r.Purpose = "Unsafe\x1bpurpose" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			tc.change(&r)
			if (AIGovernanceDocument{Version: 1, Rules: []AIGovernanceRule{r}}).validate(now) == nil {
				t.Fatal("invalid rule accepted")
			}
		})
	}
	if (AIGovernanceDocument{Version: 1, Rules: []AIGovernanceRule{base, base}}).validate(now) == nil {
		t.Fatal("duplicate accepted")
	}
	if (AIGovernanceDocument{Version: 1, Rules: make([]AIGovernanceRule, 257)}).validate(now) == nil {
		t.Fatal("unbounded rule count")
	}
}
