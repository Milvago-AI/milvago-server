package app

import (
	"context"
	"testing"
)

func TestDiscoveryAuthorizationHonorsGlobalCollectionAndNeverRollsBack(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	var device string
	if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status) VALUES($1,$2,'Discovery authorization fixture','test','0.7.0','approved') RETURNING id`, f.org, hash(randomToken())).Scan(&device); err != nil {
		t.Fatal(err)
	}
	configuration := DiscoverySettings{Host: true, IntervalSeconds: 300}
	catalog := discoveryFactory
	tx, err := tenantTx(ctx, f.a.db, f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	cfg, fingerprint, err := f.a.effectiveDiscovery(ctx, tx, f.org, device, 700, configuration, catalog)
	if err != nil || !cfg.Host {
		t.Fatal("initial discovery opt-in missing", cfg, err)
	}
	first, err := discoveryDeliveryRevision(ctx, tx, f.org, device, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	same, err := discoveryDeliveryRevision(ctx, tx, f.org, device, fingerprint)
	if err != nil || same != first {
		t.Fatal("stable policy changed its authorization revision")
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(ctx, `INSERT INTO shadow_settings(organization_id,revision,configuration) VALUES($1,1,'{"collection":{"enabled":false}}') ON CONFLICT(organization_id) DO UPDATE SET configuration=shadow_settings.configuration||'{"collection":{"enabled":false}}'::jsonb,revision=1`, f.org); err != nil {
		t.Fatal(err)
	}
	tx, err = tenantTx(ctx, f.a.db, f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	cfg, fingerprint, err = f.a.effectiveDiscovery(ctx, tx, f.org, device, 700, configuration, catalog)
	if err != nil || cfg.Host {
		t.Fatal("source opt-in bypassed global collection withdrawal", cfg, err)
	}
	second, err := discoveryDeliveryRevision(ctx, tx, f.org, device, fingerprint)
	if err != nil || second <= first {
		t.Fatal("authorization revision rolled backwards", first, second, err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(ctx, `UPDATE shadow_settings SET configuration=configuration||'{"collection":{"enabled":true}}'::jsonb,revision=1 WHERE organization_id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	tx, err = tenantTx(ctx, f.a.db, f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	cfg, fingerprint, err = f.a.effectiveDiscovery(ctx, tx, f.org, device, 700, configuration, catalog)
	if err != nil || !cfg.Host {
		t.Fatal("explicit collection resumption was not applied", cfg, err)
	}
	third, err := discoveryDeliveryRevision(ctx, tx, f.org, device, fingerprint)
	if err != nil || third <= second {
		t.Fatal("resumed policy reused old authorization", third, second, err)
	}
}
