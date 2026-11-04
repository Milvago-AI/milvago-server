package app

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestDLPInheritanceCannotBypassActivationAndLegacyNamespaces(t *testing.T) {
	f := newDLPFixtureWithoutDefaultRules(t)
	ctx := context.Background()
	get := func(path string) DLPSettings {
		t.Helper()
		w := f.call("GET", path, nil, "")
		requireHTTP(t, w, 200)
		var s DLPSettings
		if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	policy := defaultDLP("endpoint")
	policy.Inspection = true
	policy.Rules = []DLPRule{{ID: "parent-rule", Revision: 1, Name: "Parent rule", Mode: "active", Priority: 1, Condition: dlpJSON(map[string]any{"op": "contains", "field": "prompt", "value": "fixture-secret", "ignore_case": false, "whole_word": false}), Scope: dlpJSON(map[string]string{"op": "true"}), Consequence: dlpJSON(map[string]string{"action": "block"})}}
	current := get("/api/dlp/settings")
	requireHTTP(t, f.call("PUT", "/api/dlp/settings", map[string]any{"revision": current.Revision, "policy": policy, "inherited": false}, f.csrf), 200)
	var group, device string
	if err := f.admin.QueryRow(ctx, `INSERT INTO device_groups(organization_id,name) VALUES($1,'DLP group') RETURNING id`, f.org).Scan(&group); err != nil {
		t.Fatal(err)
	}
	if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,kind,capabilities,group_id) VALUES($1,$2,'DLP legacy target','test','0.1.0','approved','browser','[]',$3) RETURNING id`, f.org, hash(randomToken()), group).Scan(&device); err != nil {
		t.Fatal(err)
	}
	path := "/api/groups/" + group + "/dlp"
	local := get(path)
	local.Policy = defaultDLP("endpoint")
	requireHTTP(t, f.call("PUT", path, map[string]any{"revision": local.Revision, "policy": local.Policy, "inherited": false}, f.csrf), 200)
	local = get(path)
	// The supplied disabled draft cannot hide the active inherited parent from the
	// capability gate. The rejected transaction must retain the previous override.
	w := f.call("PUT", path, map[string]any{"revision": local.Revision, "policy": local.Policy, "inherited": true}, f.csrf)
	requireHTTP(t, w, 409)
	if !strings.Contains(w.Body.String(), "dlp_update_required") {
		t.Fatal(w.Body.String())
	}
	unchanged := get(path)
	if unchanged.Inherited || unchanged.Policy.Inspection {
		t.Fatal("rejected inheritance changed the local policy")
	}
	if _, err := f.admin.Exec(ctx, `UPDATE devices SET capabilities='["dlp-v1"]' WHERE id=$1`, device); err != nil {
		t.Fatal(err)
	}
	requireHTTP(t, f.call("PUT", path, map[string]any{"revision": unchanged.Revision, "policy": unchanged.Policy, "inherited": true}, f.csrf), 200)
	if adopted := get(path); !adopted.Inherited || adopted.Policy.Rules[0].ID != "parent-rule" {
		t.Fatal("parent adoption did not resolve")
	}
	// Before explicit DLP adoption, a legacy section override forms its own complete
	// policy. It must not be combined with a parent's custom detector namespace.
	if _, err := f.admin.Exec(ctx, `DELETE FROM dlp_settings WHERE scope_kind='group' AND scope_id=$1`, group); err != nil {
		t.Fatal(err)
	}
	legacy := dlpJSON(map[string]any{"protection": map[string]any{"keywords": []string{"group-secret"}, "exceptions": []string{}, "exact": "block", "unicode": "off", "fuzzy": "off"}})
	if _, err := f.admin.Exec(ctx, `INSERT INTO shadow_group_overrides(organization_id,group_id,configuration) VALUES($1,$2,$3)`, f.org, group, legacy); err != nil {
		t.Fatal(err)
	}
	migrated := get(path)
	if migrated.Inherited || !strings.HasPrefix(migrated.InheritedFrom, "legacy:group:") {
		t.Fatalf("legacy override lost: %+v", migrated)
	}
	encoded := string(dlpJSON(migrated.Policy))
	if strings.Contains(encoded, "parent-rule") || !strings.Contains(encoded, "group-secret") {
		t.Fatal("legacy and parent detector namespaces were mixed")
	}
}

func TestDLPDeploymentRespectsPrivacyAndLegacyDeviceDefaults(t *testing.T) {
	p := newProjectionFixture(t)
	var logs bytes.Buffer
	p.a.log = slog.New(slog.NewTextHandler(&logs, nil))
	w := p.as("owner", "GET", "/api/dlp/status", nil)
	if w.Code != 200 {
		t.Fatalf("deployment status: %d %s %s", w.Code, w.Body.String(), logs.String())
	}
	p.scan(t, "DLP deployment", w.Body.Bytes(), p.s.host)
}

func TestDLPSnapshotArchiveRejectsNewVersionsWithoutBreakingAnExistingPolicy(t *testing.T) {
	f := newDLPFixtureWithoutDefaultRules(t)
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
	save := func(s DLPSettings, status int) {
		t.Helper()
		requireHTTP(t, f.call("PUT", "/api/dlp/settings", map[string]any{"revision": s.Revision, "policy": s.Policy, "inherited": false}, f.csrf), status)
	}
	current := get()
	save(current, 200)
	current = get()
	if _, err := f.admin.Exec(ctx, `INSERT INTO dlp_policy_snapshots(organization_id,fingerprint,policy) SELECT $1,lpad(to_hex(i),64,'0'),'{}'::jsonb FROM generate_series(1,$2::integer) i`, f.org, dlpSnapshotLimit-1); err != nil {
		t.Fatal(err)
	}
	next := current
	next.Policy.Journal = !next.Policy.Journal
	save(next, 409)
	unchanged := get()
	if unchanged.Revision != current.Revision || unchanged.Fingerprint != current.Fingerprint {
		t.Fatal("archive capacity changed the active policy")
	}
	save(current, 200)
}

func TestDLPAggregateDeploymentHonorsDistinctDeviceThreshold(t *testing.T){
 p:=newProjectionFixture(t);ctx:=context.Background()
 for _,tool:=range []string{"chrome","firefox","edge"}{
  if _,err:=p.admin.Exec(ctx,`INSERT INTO dlp_enforcement(organization_id,device_id,channel,tool,mechanism,fingerprint,status) VALUES($1,$2,'browser',$3,'browser-engine',$4,'applied')`,p.org,p.device,tool,strings.Repeat("a",64));err!=nil{t.Fatal(err)}
 }
 get:=func()map[string]int{t.Helper();w:=p.as("owner","GET","/api/dlp/status?device_id="+p.device,nil);requireHTTP(t,w,200);var body struct{Items []json.RawMessage;Counts map[string]int};if err:=json.Unmarshal(w.Body.Bytes(),&body);err!=nil{t.Fatal(err)};if len(body.Items)!=0{t.Fatal("aggregate status exposed individual rows")};return body.Counts}
 privacy:=defaultPrivacy();privacy.AggregateOnly=true;privacy.K=1;requireHTTP(t,putPrivacyTest(t,p.observabilityFixture,privacy),200)
 counts:=get();if len(counts)==0{t.Fatal("valid aggregate omitted")};for _,count:=range counts{if count!=1{t.Fatal("components inflated a distinct-device count",counts)}}
 privacy.K=2;requireHTTP(t,putPrivacyTest(t,p.observabilityFixture,privacy),200)
 if counts=get();len(counts)!=0{t.Fatal("deployment diagnostics disclosed a cell below k",counts)}
}
