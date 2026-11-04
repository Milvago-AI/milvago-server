package app

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"
)

type policyCountingTx struct {
	pgx.Tx
	calls int
}

func (tx *policyCountingTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	tx.calls++
	return tx.Tx.Query(ctx, sql, args...)
}
func (tx *policyCountingTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	tx.calls++
	return tx.Tx.QueryRow(ctx, sql, args...)
}

func TestDataReadOverlayDoesNotMutateParent(t *testing.T) {
	base := defaultShadowConfig()
	before, _ := json.Marshal(base)
	raw := map[string]json.RawMessage{"protection": json.RawMessage(`{"keywords":["changed"],"exact":"block"}`)}
	over, err := overlayShadow(base, raw)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(base)
	if string(after) != string(before) {
		t.Fatal("overlay modified the parent")
	}
	over.Services[0].Domains[0] = "changed.example"
	over.Classification.Browser = append(over.Classification.Browser, "changed")
	after, _ = json.Marshal(base)
	if string(after) != string(before) {
		t.Fatal("overlay returned aliased parent slices")
	}
}

func TestDataReadBatchedPolicyParityAndTenantIsolation(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	var group string
	if err := f.admin.QueryRow(ctx, `INSERT INTO device_groups(organization_id,name) VALUES($1,'Batch group') RETURNING id`, f.org).Scan(&group); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO shadow_group_overrides(organization_id,group_id,revision,configuration) VALUES($1,$2,23,'{"protection":{"keywords":["group"],"exact":"block"}}')`, f.org, group); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO devices(organization_id,id,credential_hash,hostname,platform,version,status,group_id,group_revision)
 SELECT $1,md5('policy-page-'||n)::uuid,decode(md5('policy-secret-'||n)||md5('policy-secret-'||n),'hex'),'Synthetic','test','0.7.28','approved',CASE WHEN n%2=0 THEN $2::uuid END,CASE WHEN n%2=0 THEN 31 ELSE 0 END FROM generate_series(1,100)n`, f.org, group); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO shadow_device_overrides(organization_id,device_id,revision,configuration) SELECT $1,id,41,'{"protection":{"keywords":["device"],"exact":"observe"}}' FROM devices WHERE group_id=$2`, f.org, group); err != nil {
		t.Fatal(err)
	}
	tx, err := tenantTx(ctx, f.a.db, f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT id FROM devices ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	counted := &policyCountingTx{Tx: tx}
	batch, err := f.a.effectiveShadowBatch(ctx, counted, f.org, ids)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch) != 100 || counted.calls > 20 {
		t.Fatalf("batch=%d read queries=%d; expected bounded setup, not one policy read per device", len(batch), counted.calls)
	}
	for _, id := range ids {
		single, err := f.a.effectiveShadow(ctx, tx, f.org, id)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := json.Marshal(single)
		b, _ := json.Marshal(batch[id])
		if string(a) != string(b) {
			t.Fatalf("single/batch policy mismatch: %s / %s", a, b)
		}
	}
	a, b := batch[ids[0]], batch[ids[1]]
	saved, _ := json.Marshal(b)
	a.Config.Services[0].Domains[0] = "changed.example"
	a.Capabilities["changed"] = true
	a.InheritedFrom["changed"] = InheritedFrom{Name: "changed"}
	after, _ := json.Marshal(b)
	if string(after) != string(saved) {
		t.Fatal("device policies share mutable storage")
	}
	if _, err = f.a.effectiveShadowBatch(ctx, tx, f.org, append(ids, ids[0])); err == nil {
		t.Fatal("oversized batch accepted")
	}
	// A valid UUID outside the visible organization cannot retrieve a policy row.
	other, err := f.a.effectiveShadowBatch(ctx, tx, f.org, []string{missingGroupID})
	if err != nil || len(other) != 0 {
		t.Fatal("missing/foreign device was resolved", err)
	}
	t.Logf("100 effective policies use %d SQL reads", counted.calls)
}
