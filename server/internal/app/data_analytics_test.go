package app

import (
	"context"
	"encoding/json"
	"testing"
)

func TestDataReadGroupsSingleFleetPass(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	if _, err := f.admin.Exec(ctx, `INSERT INTO device_groups(organization_id,id,name) SELECT $1,md5('read-group-'||n)::uuid,'Synthetic group '||n FROM generate_series(1,200)n`, f.org); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO devices(organization_id,id,credential_hash,hostname,platform,version,status,group_id)
	 SELECT $1,md5('group-device-'||n)::uuid,decode(md5('group-secret-'||n)||md5('group-secret-'||n),'hex'),'Synthetic','test','test','approved',md5('read-group-'||((n-1)%200+1))::uuid FROM generate_series(1,10000)n`, f.org); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `ANALYZE devices`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `ANALYZE device_groups`); err != nil {
		t.Fatal(err)
	}
	tx, err := tenantTx(ctx, f.a.db, f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var raw []byte
	if err = tx.QueryRow(ctx, `EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) `+deviceGroupsQuery).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var plan []struct {
		Plan readPlan
		Time float64 `json:"Execution Time"`
	}
	if err = json.Unmarshal(raw, &plan); err != nil || len(plan) != 1 {
		t.Fatal("missing group read plan")
	}
	scans := 0
	var visit func(readPlan)
	visit = func(node readPlan) {
		if node.Relation == "devices" {
			scans++
			if node.Loops != 1 || node.Rows > 10000 {
				t.Error("fleet rescanned once per group")
			}
		}
		for _, child := range node.Children {
			visit(child)
		}
	}
	visit(plan[0].Plan)
	if scans != 1 {
		t.Fatalf("expected a single fleet scan, got%d", scans)
	}
	if err = tx.QueryRow(ctx, deviceGroupsQuery).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Items []struct {
			Count int `json:"device_count"`
		}
	}
	if err = json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Items) != 200 {
		t.Fatal("group list incomplete")
	}
	for _, group := range result.Items {
		if group.Count != 50 {
			t.Fatal("group device count changed")
		}
	}
	t.Logf("group inventory: devices=10000 groups=200 fleet_scans=%d SQL=%.3fms", scans, plan[0].Time)
}
