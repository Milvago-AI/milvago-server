package app

import (
	"context"
	"encoding/json"
	"testing"
)

// Exercise the real runtime role and FORCE RLS, repeatedly reusing the same
// connection/prepared statements while the batch changes the tenant context.
func TestPrivacyReadLevelBatchesTenantSwitchBeforeRLSAndKeepsFreshPolicy(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	var child string
	if err := f.admin.QueryRow(ctx, `INSERT INTO organizations(name,parent_id) VALUES('Synthetic privacy level child',$1) RETURNING id`, f.org).Scan(&child); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `UPDATE privacy_settings SET revision=11,configuration='{"pseudonymous":true,"k_anonymity":5}' WHERE organization_id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	admin, err := tenantTx(ctx, f.admin, child)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = admin.Exec(ctx, `INSERT INTO privacy_settings(organization_id,revision,configuration) VALUES($1,73,'{"pseudonymous":false,"k_anonymity":11}')`, child); err != nil {
		admin.Rollback(ctx)
		t.Fatal(err)
	}
	if err = admin.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	tx, err := tenantTx(ctx, f.a.db, f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	check := func(organization, other string, revision int64, pseudonymous bool) {
		t.Helper()
		raw, gotRevision, err := readPrivacyLevel(ctx, tx, organization)
		var configuration struct {
			Pseudonymous bool `json:"pseudonymous"`
		}
		if err != nil || json.Unmarshal(raw, &configuration) != nil || gotRevision != revision || configuration.Pseudonymous != pseudonymous {
			t.Fatal("batch used a stale/wrong organization policy", gotRevision, err)
		}
		var current string
		var foreign int
		if err = tx.QueryRow(ctx, `SELECT current_setting('milvago.organization_id'),(SELECT count(*) FROM privacy_settings WHERE organization_id=$1)`, other).Scan(&current, &foreign); err != nil || current != organization || foreign != 0 {
			t.Fatal("privacy batch bypassed or leaked its tenant context", foreign, err)
		}
	}
	for range 3 {
		check(child, f.org, 73, false)
		check(f.org, child, 11, true)
	}
	admin, err = tenantTx(ctx, f.admin, child)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = admin.Exec(ctx, `UPDATE privacy_settings SET revision=74,configuration='{"pseudonymous":true,"k_anonymity":9}' WHERE organization_id=$1`, child); err != nil {
		admin.Rollback(ctx)
		t.Fatal(err)
	}
	if err = admin.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	check(child, f.org, 74, true)
	// A current malformed policy must still fail, then readPrivacy must restore
	// the requested caller tenant before returning; no prior successful read wins.
	admin, err = tenantTx(ctx, f.admin, child)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = admin.Exec(ctx, `UPDATE privacy_settings SET configuration='{"k_anonymity":"synthetic invalid number"}' WHERE organization_id=$1`, child); err != nil {
		admin.Rollback(ctx)
		t.Fatal(err)
	}
	if err = admin.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = f.a.readPrivacy(ctx, tx, child); err == nil {
		t.Fatal("malformed current policy was hidden")
	}
	var current string
	if err = tx.QueryRow(ctx, `SELECT current_setting('milvago.organization_id')`).Scan(&current); err != nil || current != child {
		t.Fatal("privacy error did not restore caller context", err)
	}
	view, err := f.a.readPrivacy(ctx, tx, f.org)
	if err != nil || view.Revision != 11 || !view.Config.Pseudonymous {
		t.Fatal("privacy read after a decode failure changed", err)
	}
	// Missing policy keeps the historical default and revision, and still leaves
	// the batch fully drained so a following statement can use this connection.
	admin, err = tenantTx(ctx, f.admin, child)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = admin.Exec(ctx, `DELETE FROM privacy_settings WHERE organization_id=$1`, child); err != nil {
		admin.Rollback(ctx)
		t.Fatal(err)
	}
	if err = admin.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	raw, revision, err := readPrivacyLevel(ctx, tx, child)
	if err != nil || revision != 1 || string(raw) != "{}" {
		t.Fatal("missing privacy policy did not preserve defaults", revision, err)
	}
	if err = tx.QueryRow(ctx, `SELECT current_setting('milvago.organization_id')`).Scan(&current); err != nil || current != child {
		t.Fatal("missing-row batch was not drained", err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
}
