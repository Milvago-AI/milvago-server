package app

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"io"
	"log/slog"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

type retentionPurgeFixture struct {
	admin, db                       *pgxpool.Pool
	a                               *App
	org                             string
	user, device                    string
	oldAudit, recentAudit           string
	oldEnrollment, freshEnrollment  string
	oldEvent, freshEvent            string
	oldKey, liveKey, retiredProfile string
}

func newRetentionPurgeFixture(t *testing.T) *retentionPurgeFixture {
	runtimeURL, migrationURL := os.Getenv("TEST_DATABASE_URL"), os.Getenv("TEST_MIGRATION_DATABASE_URL")
	if runtimeURL == "" || migrationURL == "" {
		t.Skip("retention purge integration requires disposable milvago_test database")
	}
	for _, raw := range []string{runtimeURL, migrationURL} {
		u, e := url.Parse(raw)
		if e != nil || u.Path != "/milvago_test" {
			t.Fatal("retention purge tests require disposable database named milvago_test")
		}
	}
	ctx := context.Background()
	admin, e := pgxpool.New(ctx, migrationURL)
	if e != nil {
		t.Fatal(e)
	}
	// Registered first so it runs last: setTenant's restore needs a live pool.
	t.Cleanup(func() { admin.Close() })
	if _, e = admin.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); e != nil {
		t.Fatal(e)
	}
	identity := identityProvider(t)
	block, _ := aes.NewCipher(make([]byte, 32))
	gcm, _ := cipher.NewGCM(block)
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	config := Config{DatabaseURL: runtimeURL, MigrationURL: migrationURL, RuntimeRole: "milvago_runtime", OrganizationName: "Retention test organization", BootstrapEmail: "retention@example.test", AppURL: "http://localhost:4021", Issuer: identity.server.URL, ClientID: "test-console", ClientSecret: "synthetic-secret", SessionCipher: gcm, ContentKeys: testContentKeys(), ContentVersion: 1, SigningKey: key, UpdatePublicKey: key.Public().(ed25519.PublicKey)}
	db, e := OpenDatabase(ctx, config)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	a, e := New(ctx, config, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if e != nil {
		t.Fatal(e)
	}
	var org string
	if e = admin.QueryRow(ctx, `SELECT id FROM organizations LIMIT 1`).Scan(&org); e != nil {
		t.Fatal(e)
	}
	setTenant(t, admin, org)

	return &retentionPurgeFixture{admin: admin, db: db, a: a, org: org}
}

func seedRetentionBasicRows(t *testing.T, f *retentionPurgeFixture) {
	ctx, admin, org := context.Background(), f.admin, f.org
	var e error

	var user, device string
	if e = admin.QueryRow(ctx, `INSERT INTO users(subject,email,display_name) VALUES('retention-user','retention@example.test','Synthetic retention account') RETURNING id`).Scan(&user); e != nil {
		t.Fatal(e)
	}
	if e = admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status) VALUES($1,$2,'retention-device','test','0.5.0','approved') RETURNING id`, org, hash(randomToken())).Scan(&device); e != nil {
		t.Fatal(e)
	}
	// One audit row beyond the 730-day floor, one inside it.
	var oldAudit, recentAudit string
	if e = admin.QueryRow(ctx, `INSERT INTO audit(organization_id,actor,action,target,occurred_at) VALUES($1,'retention-user','device.enroll','old',now()-interval '731 days') RETURNING id`, org).Scan(&oldAudit); e != nil {
		t.Fatal(e)
	}
	if e = admin.QueryRow(ctx, `INSERT INTO audit(organization_id,actor,action,target) VALUES($1,'retention-user','device.enroll','recent') RETURNING id`, org).Scan(&recentAudit); e != nil {
		t.Fatal(e)
	}
	// One stale enrollment, one still usable.
	var oldEnrollment, freshEnrollment string
	if e = admin.QueryRow(ctx, `INSERT INTO enrollments(organization_id,token_hash,label,expires_at) VALUES($1,$2,'old',now()-interval '2 days') RETURNING id`, org, hash(randomToken())).Scan(&oldEnrollment); e != nil {
		t.Fatal(e)
	}
	if e = admin.QueryRow(ctx, `INSERT INTO enrollments(organization_id,token_hash,label,expires_at) VALUES($1,$2,'fresh',now()+interval '1 day') RETURNING id`, org, hash(randomToken())).Scan(&freshEnrollment); e != nil {
		t.Fatal(e)
	}
	f.user, f.device = user, device
	f.oldAudit, f.recentAudit = oldAudit, recentAudit
	f.oldEnrollment, f.freshEnrollment = oldEnrollment, freshEnrollment
}

func seedRetentionShadowRows(t *testing.T, f *retentionPurgeFixture) {
	ctx, admin, org, device := context.Background(), f.admin, f.org, f.device
	var e error

	// One event past the default 90-day retention, one recent. The old event
	// carries still-valid content, which only the cascade may remove; the recent
	// event carries expired content, which the direct purge must remove.
	var oldEvent, freshEvent string
	if e = admin.QueryRow(ctx, `INSERT INTO shadow_events(organization_id,device_id,id,occurred_at,kind,provider,tool,source,action,policy_revision,characters,sensitivity) VALUES($1,$2,gen_random_uuid(),now()-interval '100 days','navigation','chatgpt.com','chrome','browser','observed',1,0,'normal') RETURNING id`, org, device).Scan(&oldEvent); e != nil {
		t.Fatal(e)
	}
	if e = admin.QueryRow(ctx, `INSERT INTO shadow_events(organization_id,device_id,id,occurred_at,kind,provider,tool,source,action,policy_revision,characters,sensitivity) VALUES($1,$2,gen_random_uuid(),now(),'navigation','chatgpt.com','chrome','browser','observed',1,0,'normal') RETURNING id`, org, device).Scan(&freshEvent); e != nil {
		t.Fatal(e)
	}
	if tag, e := admin.Exec(ctx, `INSERT INTO shadow_content(organization_id,device_id,event_id,encrypted,expires_at) VALUES($1,$2,$3,'\x0102'::bytea,now()+interval '1 day')`, org, device, oldEvent); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("old event content fixture missing", e)
	}
	if tag, e := admin.Exec(ctx, `INSERT INTO shadow_content(organization_id,device_id,event_id,encrypted,expires_at) VALUES($1,$2,$3,'\x0102'::bytea,now()-interval '1 hour')`, org, device, freshEvent); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("expired content fixture missing", e)
	}
	f.oldEvent, f.freshEvent = oldEvent, freshEvent
}

func seedRetentionKeyRows(t *testing.T, f *retentionPurgeFixture) {
	ctx, admin, org, user := context.Background(), f.admin, f.org, f.user
	var e error

	// One API key retired ninety-one days ago, one live.
	var oldKey, liveKey string
	if e = admin.QueryRow(ctx, `INSERT INTO api_keys(organization_id,user_id,name,secret_hash,permissions,expires_at,revoked_at) VALUES($1,$2,'old',$3,'{events.read}',now()+interval '10 days',now()-interval '91 days') RETURNING id`, org, user, hash(randomToken())).Scan(&oldKey); e != nil {
		t.Fatal(e)
	}
	if e = admin.QueryRow(ctx, `INSERT INTO api_keys(organization_id,user_id,name,secret_hash,permissions,expires_at) VALUES($1,$2,'live',$3,'{events.read}',now()+interval '10 days') RETURNING id`, org, user, hash(randomToken())).Scan(&liveKey); e != nil {
		t.Fatal(e)
	}
	// One deployment key retired thirty-one days ago. The live key is the one the
	// organization opened with: a second active durable key would violate the
	// one-active-key index, and the purge must leave that row alone anyway.
	var retiredProfile string
	if e = admin.QueryRow(ctx, `INSERT INTO installer_profiles(organization_id,secret_hash,secret_ciphertext,edition,platform,version,created_at,expires_at,max_uses,revoked,revoked_at) VALUES($1,$2,'sealed',$3,NULL,'0.5.0',now()-interval '40 days',now()-interval '10 days',10000,true,now()-interval '31 days') RETURNING id`, org, hash(randomToken()), Edition).Scan(&retiredProfile); e != nil {
		t.Fatal(e)
	}

	f.oldKey, f.liveKey, f.retiredProfile = oldKey, liveKey, retiredProfile
}

func assertRetentionRows(t *testing.T, f *retentionPurgeFixture) {
	ctx, admin, org := context.Background(), f.admin, f.org
	oldAudit, recentAudit := f.oldAudit, f.recentAudit
	oldEnrollment, freshEnrollment := f.oldEnrollment, f.freshEnrollment
	oldEvent, freshEvent := f.oldEvent, f.freshEvent
	oldKey, liveKey, retiredProfile := f.oldKey, f.liveKey, f.retiredProfile

	count := func(query string, args ...any) int {
		t.Helper()
		var n int
		if e := admin.QueryRow(ctx, query, args...).Scan(&n); e != nil {
			t.Fatal(e)
		}
		return n
	}
	if count(`SELECT count(*) FROM audit WHERE id=$1`, oldAudit) != 0 {
		t.Fatal("audit row beyond the 730-day floor survived the purge")
	}
	if count(`SELECT count(*) FROM audit WHERE id=$1`, recentAudit) != 1 {
		t.Fatal("recent audit row was purged")
	}
	if count(`SELECT count(*) FROM enrollments WHERE id=$1`, oldEnrollment) != 0 {
		t.Fatal("stale enrollment survived the purge")
	}
	if count(`SELECT count(*) FROM enrollments WHERE id=$1`, freshEnrollment) != 1 {
		t.Fatal("usable enrollment was purged")
	}
	if count(`SELECT count(*) FROM shadow_events WHERE id=$1`, oldEvent) != 0 {
		t.Fatal("event past retention survived the purge")
	}
	if count(`SELECT count(*) FROM shadow_events WHERE id=$1`, freshEvent) != 1 {
		t.Fatal("recent event was purged")
	}
	if count(`SELECT count(*) FROM shadow_content WHERE event_id=$1`, oldEvent) != 0 {
		t.Fatal("event deletion did not cascade only to its content")
	}
	if count(`SELECT count(*) FROM shadow_content WHERE event_id=$1`, freshEvent) != 0 {
		t.Fatal("expired content survived the purge")
	}
	if count(`SELECT count(*) FROM api_keys WHERE id=$1`, oldKey) != 0 {
		t.Fatal("long-retired API key survived the purge")
	}
	if count(`SELECT count(*) FROM api_keys WHERE id=$1`, liveKey) != 1 {
		t.Fatal("live API key was purged")
	}
	if count(`SELECT count(*) FROM installer_profiles WHERE id=$1`, retiredProfile) != 0 {
		t.Fatal("long-retired deployment key survived the purge")
	}
	if count(`SELECT count(*) FROM installer_profiles WHERE organization_id=$1 AND NOT revoked`, org) != 1 {
		t.Fatal("the organization's live deployment key was purged")
	}

}

func assertRetentionAuditGuards(t *testing.T, f *retentionPurgeFixture) {
	ctx, admin, db, org, recentAudit := context.Background(), f.admin, f.db, f.org, f.recentAudit
	var e error

	// The grant opens the purge, nothing else: without the transaction-local
	// flag the trigger refuses the DELETE, even on a row old enough.
	tx, e := tenantTx(ctx, db, org)
	if e != nil {
		t.Fatal(e)
	}
	_, direct := tx.Exec(ctx, `DELETE FROM audit WHERE id=$1`, recentAudit)
	tx.Rollback(ctx)
	if direct == nil {
		t.Fatal("audit DELETE without the purge flag succeeded under the runtime role")
	}
	// A forged flag does not help against a recent row: the 730-day floor is in
	// the trigger, not in the caller.
	tx, e = tenantTx(ctx, db, org)
	if e != nil {
		t.Fatal(e)
	}
	_, forged := tx.Exec(ctx, `SELECT set_config('milvago.purge_audit_before',(now()+interval '1 day')::text,true); DELETE FROM audit WHERE id=$1`, recentAudit)
	tx.Rollback(ctx)
	if forged == nil {
		t.Fatal("audit DELETE with a forged purge flag deleted a recent row")
	}
	// UPDATE is never allowed: the runtime role has no grant for it, and the
	// trigger refuses it even for the table owner.
	tx, e = tenantTx(ctx, db, org)
	if e != nil {
		t.Fatal(e)
	}
	_, updated := tx.Exec(ctx, `UPDATE audit SET action='tampered' WHERE id=$1`, recentAudit)
	tx.Rollback(ctx)
	if updated == nil {
		t.Fatal("audit UPDATE succeeded under the runtime role")
	}
	if _, e = admin.Exec(ctx, `UPDATE audit SET action='tampered' WHERE id=$1`, recentAudit); e == nil {
		t.Fatal("audit UPDATE succeeded for the table owner")
	}
	var action string
	if e = admin.QueryRow(ctx, `SELECT action FROM audit WHERE id=$1`, recentAudit).Scan(&action); e != nil || action != "device.enroll" {
		t.Fatal("the recent audit row did not survive the attacks untouched", e)
	}
}

// TestRetentionPurge proves the hourly retention maintenance actually deletes:
// the runtime role holds DELETE on audit (granted at boot), so purgeOrgRetention
// commits every purge in one transaction — and the append-only trigger remains
// the only authority on what may leave the audit table. Fixtures are written
// through the admin pool; the purge and the attacks run through the runtime
// pool, the one the grant decision concerns.
func TestRetentionPurge(t *testing.T) {
	f := newRetentionPurgeFixture(t)
	seedRetentionBasicRows(t, f)
	seedRetentionShadowRows(t, f)
	seedRetentionKeyRows(t, f)
	if e := f.a.purgeOrgRetention(context.Background(), f.org); e != nil {
		t.Fatal("retention purge failed:", e)
	}
	assertRetentionRows(t, f)
	assertRetentionAuditGuards(t, f)
}
