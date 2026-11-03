package app

import (
	"context"
	"testing"
	"time"
)

func TestAIGovernanceRetentionPreservesActiveAndDropsOnlyOldInactive(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	var device string
	if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status) VALUES($1,$2,'Retention fixture','test','0.7.0','approved') RETURNING id::text`, f.org, hash(randomToken())).Scan(&device); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO ai_governance_policies(organization_id,revision) VALUES($1,1)`, f.org); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `UPDATE settings SET retention_days=30 WHERE organization_id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO ai_governance_exceptions(organization_id,device_id,rule_id,policy_revision,reason,approved_by,approved_at,expires_at,revoked_at) VALUES
 ($1,$2,'active',1,'Active approved work',$3,now()-interval '60 days',now()+interval '1 hour',NULL),
 ($1,$2,'expired',1,'Expired approved work',$3,now()-interval '60 days',now()-interval '1 hour',NULL),
 ($1,$2,'obsolete',0,'Replaced policy revision',$3,now()-interval '60 days',now()+interval '1 hour',NULL),
 ($1,$2,'recent',1,'Recently revoked work',$3,now()-interval '1 hour',now()+interval '1 hour',now())`, f.org, device, f.user); err != nil {
		t.Fatal(err)
	}
	tx, err := tenantTx(ctx, f.a.db, f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	active, err := readAIGovernanceExceptions(ctx, tx, f.org, []string{device})
	if err != nil || len(active) != 1 || active[0].Rule != "active" {
		t.Fatal("obsolete, revoked or expired exception was exposed as active", active, err)
	}
	if err = f.a.maintainPrivacy(ctx, tx, f.org, time.Now()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM ai_governance_exceptions WHERE organization_id=$1 AND rule_id IN ('active','recent')`, f.org).Scan(&count); err != nil || count != 2 {
		t.Fatal("active or recent decision deleted", count, err)
	}
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM ai_governance_exceptions WHERE organization_id=$1`, f.org).Scan(&count); err != nil || count != 2 {
		t.Fatal("old inactive exceptions retained", count, err)
	}
}
