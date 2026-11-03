package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func declaredSystemFixture() AIDeclaredSystem {
	return AIDeclaredSystem{ID: "synthetic-use", Name: "Synthetic engineering assistant", Owner: "Engineering", Purpose: "Internal test documentation assistance", Scope: "organization", Applications: []string{"ollama"}, Providers: []string{"openai"}, Models: []string{"Synthetic model"}, DataCategories: []string{"internal"}, RiskLevel: "unassessed", Status: "review", ReviewDue: time.Now().Add(24 * time.Hour)}
}

func TestAIGovernanceRegistryValidation(t *testing.T) {
	now := time.Now()
	for _, test := range []struct {
		name   string
		change func(*AIDeclaredSystem)
	}{
		{"missing owner", func(s *AIDeclaredSystem) { s.Owner = " " }},
		{"image in text field", func(s *AIDeclaredSystem) { s.Purpose = string([]byte{0xff, 0xfe}) }},
		{"control character", func(s *AIDeclaredSystem) { s.Name = "bad\x00name" }},
		{"scope", func(s *AIDeclaredSystem) { s.Scope = "all-tenants" }},
		{"foreign organization selector", func(s *AIDeclaredSystem) { s.Target = "00000000-0000-4000-8000-000000000001" }},
		{"untyped target", func(s *AIDeclaredSystem) { s.Scope = "device"; s.Target = "data:image/png" }},
		{"unknown risk", func(s *AIDeclaredSystem) { s.RiskLevel = "certified" }},
		{"unknown status", func(s *AIDeclaredSystem) { s.Status = "authorized" }},
		{"missing date", func(s *AIDeclaredSystem) { s.ReviewDue = time.Time{} }},
		{"distant date", func(s *AIDeclaredSystem) { s.ReviewDue = now.AddDate(3, 0, 0) }},
		{"unbounded list", func(s *AIDeclaredSystem) { s.Models = make([]string, 17) }},
		{"duplicate provider", func(s *AIDeclaredSystem) { s.Providers = []string{"openai", " openai "} }},
		{"unknown data category", func(s *AIDeclaredSystem) { s.DataCategories = []string{"actual customer records"} }},
		{"unbounded text", func(s *AIDeclaredSystem) { s.Safeguards = strings.Repeat("x", 2001) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			system := declaredSystemFixture()
			test.change(&system)
			d := AIDeclaredSystems{Version: 1, Systems: []AIDeclaredSystem{system}}
			d.normalize()
			if d.validate(now) == nil {
				t.Fatal("invalid declaration accepted")
			}
		})
	}
	valid := declaredSystemFixture()
	if err := (AIDeclaredSystems{Version: 1, Systems: []AIDeclaredSystem{valid}}).validate(now); err != nil {
		t.Fatal(err)
	}
	if (AIDeclaredSystems{Version: 1, Systems: []AIDeclaredSystem{valid, valid}}).validate(now) == nil {
		t.Fatal("duplicate IDs accepted")
	}
	if (AIDeclaredSystems{Version: 1, Systems: make([]AIDeclaredSystem, 129)}).validate(now) == nil {
		t.Fatal("unbounded registry accepted")
	}
	if (AIDeclaredSystems{Version: 1}).validate(now) == nil {
		t.Fatal("null list accepted")
	}
	large := AIDeclaredSystems{Version: 1, Systems: []AIDeclaredSystem{}}
	for n := 0; n < 128; n++ {
		s := declaredSystemFixture()
		s.ID = fmt.Sprintf("use-%d", n)
		s.RiskSummary = strings.Repeat("x", 2000)
		s.Safeguards = s.RiskSummary
		large.Systems = append(large.Systems, s)
	}
	if large.validate(now) == nil {
		t.Fatal("aggregate document size was not bounded")
	}
}

func TestAIGovernanceRegistryAPIAndIndependentRevision(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	system := declaredSystemFixture()
	document := AIDeclaredSystems{Version: 1, Systems: []AIDeclaredSystem{system}}
	body := map[string]any{"revision": 0, "document": document, "reason": "Document a synthetic business use"}
	requireHTTP(t, f.call("GET", "/api/ai-governance/systems", nil, ""), 200)
	requireHTTP(t, f.call("PUT", "/api/ai-governance/systems", body, f.csrf), 403)
	if _, err := f.admin.Exec(ctx, `UPDATE sessions SET mfa_verified_at=now() WHERE user_id=$1`, f.user); err != nil {
		t.Fatal(err)
	}
	device := "00000000-0000-4000-8000-abcdefabcdef"
	if _, err := f.admin.Exec(ctx, `INSERT INTO devices(organization_id,id,credential_hash,hostname,platform,version,status) VALUES($1,$2,$3,'Synthetic','test','0.7.0','approved')`, f.org, device, hash(randomToken())); err != nil {
		t.Fatal(err)
	}
	rule := AIGovernanceRule{ID: "execution", Application: "ollama", Activity: "execution", Scope: "organization", Decision: "deny", AllowExceptions: true, Owner: "Engineering", Purpose: "Synthetic governance qualification", ReviewDue: time.Now().Add(time.Hour)}
	policy := f.call("PUT", "/api/ai-governance/policy", map[string]any{"revision": 0, "document": AIGovernanceDocument{Version: 1, Rules: []AIGovernanceRule{rule}}, "reason": "Synthetic authorization baseline"}, f.csrf)
	requireHTTP(t, policy, 200)
	var policyReply struct {
		Revision int64 `json:"revision"`
	}
	if err := json.Unmarshal(policy.Body.Bytes(), &policyReply); err != nil {
		t.Fatal(err)
	}
	exception := f.call("POST", "/api/ai-governance/exceptions", map[string]any{"device_id": device, "rule_id": rule.ID, "revision": policyReply.Revision, "reason": "Temporary synthetic work", "expires_at": time.Now().Add(time.Hour)}, f.csrf)
	requireHTTP(t, exception, 201)
	var approved struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(exception.Body.Bytes(), &approved)
	system.Scope = "device"
	system.Target = strings.ToUpper(device)
	document.Systems[0] = system
	body["document"] = document
	saved := f.call("PUT", "/api/ai-governance/systems", body, f.csrf)
	requireHTTP(t, saved, 200)
	var result struct {
		Revision int64             `json:"revision"`
		Document AIDeclaredSystems `json:"document"`
	}
	if err := json.Unmarshal(saved.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Revision == 0 || len(result.Document.Systems) != 1 || result.Document.Systems[0].Target != device {
		t.Fatal("missing canonical persisted declaration", result)
	}
	requireHTTP(t, f.call("PUT", "/api/ai-governance/systems", body, f.csrf), 409)
	current := f.call("GET", "/api/ai-governance/systems", nil, "")
	requireHTTP(t, current, 200)
	if !strings.Contains(current.Body.String(), system.Name) {
		t.Fatal("saved declaration missing")
	}
	var unchanged int64
	if err := f.admin.QueryRow(ctx, `SELECT revision FROM ai_governance_policies WHERE organization_id=$1`, f.org).Scan(&unchanged); err != nil || unchanged != policyReply.Revision {
		t.Fatal("business context changed authorization revision", err)
	}
	exceptions := f.call("GET", "/api/ai-governance/exceptions?device_id="+device, nil, "")
	requireHTTP(t, exceptions, 200)
	if approved.ID == "" || !strings.Contains(exceptions.Body.String(), approved.ID) {
		t.Fatal("declaration invalidated an authorization exception")
	}
	body["revision"] = result.Revision
	document.Systems[0].Target = "00000000-0000-4000-8000-000000000099"
	body["document"] = document
	requireHTTP(t, f.call("PUT", "/api/ai-governance/systems", body, f.csrf), 400)
	for _, value := range []any{map[string]any{"version": 1, "systems": "data:image/png"}, map[string]any{"version": 1, "systems": nil}, map[string]any{"version": 1, "systems": []any{}, "store_content": true}} {
		body["document"] = value
		requireHTTP(t, f.call("PUT", "/api/ai-governance/systems", body, f.csrf), 400)
	}
	for _, value := range []any{map[string]string{"image": "data:image/png"}, "version: 1\nsystems: []\ncommand: ignored", "version: 1\nsystems: []\n---\nversion: 1\nsystems: []"} {
		requireHTTP(t, f.call("POST", "/api/ai-governance/systems/validate", map[string]any{"source": value}, f.csrf), 400)
	}
	requireHTTP(t, f.call("POST", "/api/ai-governance/systems/validate", map[string]string{"source": "version: 1\nsystems: []"}, f.csrf), 200)
	// RLS must protect the registry even when the runtime omits a WHERE clause.
	tx, err := f.a.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT set_config('milvago.organization_id','00000000-0000-4000-8000-000000000099',true)`); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM ai_governance_registry`).Scan(&count); err != nil || count != 0 {
		t.Fatal("registry leaked across tenant RLS", count, err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO ai_governance_registry(organization_id) VALUES($1)`, f.org)
	var denied *pgconn.PgError
	if !errors.As(err, &denied) || denied.Code != "42501" {
		t.Fatal("cross-tenant registry write not rejected by RLS", err)
	}
	_ = tx.Rollback(ctx)
	if _, err := f.admin.Exec(ctx, `INSERT INTO roles(organization_id,name,permissions) VALUES($1,'discovery-reader',ARRAY['discovery.read','devices.read'])`, f.org); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `UPDATE memberships SET role='discovery-reader' WHERE organization_id=$1 AND user_id=$2`, f.org, f.user); err != nil {
		t.Fatal(err)
	}
	requireHTTP(t, f.call("GET", "/api/ai-governance/systems", nil, ""), 403)
	requireHTTP(t, f.call("PUT", "/api/ai-governance/systems", body, f.csrf), 403)
	requireHTTP(t, f.call("POST", "/api/ai-governance/systems/validate", map[string]string{"source": "version: 1\nsystems: []"}, f.csrf), 403)
}
