package app

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"
)

func TestSQLAccessHealthWindowAvoidsUnrelatedHistory(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	var device string
	if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status) VALUES($1,$2,'synthetic-window','test','0.7.0','approved') RETURNING id`, f.org, hash(randomToken())).Scan(&device); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO detector_health(organization_id,device_id,id,payload)
	 SELECT $1,$2,gen_random_uuid(),jsonb_build_object('window_start',now()-make_interval(hours=>n+1),'window_end',now()-make_interval(hours=>n),'providers','[]'::jsonb)
	 FROM generate_series(0,10000) n`, f.org, device); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `ANALYZE detector_health`); err != nil {
		t.Fatal(err)
	}
	tx, err := tenantTx(ctx, f.a.db, f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var raw []byte
	if err = tx.QueryRow(ctx, `EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) SELECT count(*) FROM detector_health WHERE window_end>now()-interval '30 minutes'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var plans []struct{ Plan readPlan }
	if err = json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 {
		t.Fatal("invalid health plan", err)
	}
	found := false
	var visit func(readPlan)
	visit = func(node readPlan) {
		if node.Index == "detector_health_window_lookup" {
			found = true
			if node.Rows*node.Loops > 1 || node.Hit+node.Read > 12 {
				t.Errorf("health window read unrelated history: rows=%v blocks=%v", node.Rows*node.Loops, node.Hit+node.Read)
			}
		}
		for _, child := range node.Children {
			visit(child)
		}
	}
	visit(plans[0].Plan)
	if !found {
		t.Fatal("observation window has no indexed access path")
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM detector_health WHERE window_end>now()-interval '30 minutes'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("observation window changed", count, err)
	}
}

func TestSQLAccessMigrationBackfillsTenantsWithoutRewritingOnRestart(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	var neighbor string
	if err := f.admin.QueryRow(ctx, `INSERT INTO organizations(name,parent_id) VALUES('Synthetic health neighbor',$1) RETURNING id`, f.org).Scan(&neighbor); err != nil {
		t.Fatal(err)
	}
	tx, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `ALTER TABLE detector_health DISABLE TRIGGER detector_health_window_times; DELETE FROM schema_migrations WHERE version=2026110202`); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{f.org, neighbor} {
		if _, err = tx.Exec(ctx, `SELECT set_config('milvago.organization_id',$1,true)`, tenant); err != nil {
			t.Fatal(err)
		}
		var device string
		if err = tx.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status) VALUES($1,$2,'synthetic-health','test','0.7.0','approved') RETURNING id`, tenant, hash(randomToken())).Scan(&device); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO detector_health(organization_id,device_id,id,payload) VALUES($1,$2,gen_random_uuid(),jsonb_build_object('window_start','2026-01-01T10:00:00+04:00','window_end','2026-01-01T10:15:00+04:00','providers','[]'::jsonb))`, tenant, device); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = tx.Exec(ctx, `ALTER TABLE detector_health ENABLE TRIGGER detector_health_window_times; SET LOCAL lock_timeout='150ms'; SET LOCAL statement_timeout='5s'`); err != nil {
		t.Fatal(err)
	}
	if err = initializeSQLAccessIndexes(ctx, tx); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{f.org, neighbor} {
		if _, err = tx.Exec(ctx, `SELECT set_config('milvago.organization_id',$1,true)`, tenant); err != nil {
			t.Fatal(err)
		}
		var start, end time.Time
		var rowVersion string
		if err = tx.QueryRow(ctx, `SELECT window_start,window_end,ctid::text FROM detector_health`).Scan(&start, &end, &rowVersion); err != nil {
			t.Fatal(err)
		}
		if !start.Equal(time.Date(2026, 1, 1, 6, 0, 0, 0, time.UTC)) || !end.Equal(start.Add(15*time.Minute)) {
			t.Fatal("migration changed the observation window")
		}
		if err = initializeSQLAccessIndexes(ctx, tx); err != nil {
			t.Fatal(err)
		}
		var currentTenant, currentVersion, lock, statement string
		if err = tx.QueryRow(ctx, `SELECT current_setting('milvago.organization_id'),ctid::text,current_setting('lock_timeout'),current_setting('statement_timeout') FROM detector_health`).Scan(&currentTenant, &currentVersion, &lock, &statement); err != nil {
			t.Fatal(err)
		}
		if currentTenant != tenant || rowVersion != currentVersion || lock != "150ms" || statement != "5s" {
			t.Fatal("restart rewrote a health report or changed caller scope/limits")
		}
	}
}

func TestSQLAccessVacuumDefaultsKeepOperatorSettings(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	var vacuum, inserted, analyze string
	err := f.admin.QueryRow(ctx, `SELECT
	 (SELECT option_value FROM pg_options_to_table(c.reloptions) WHERE option_name='autovacuum_vacuum_scale_factor'),
	 (SELECT option_value FROM pg_options_to_table(c.reloptions) WHERE option_name='autovacuum_vacuum_insert_scale_factor'),
	 (SELECT option_value FROM pg_options_to_table(c.reloptions) WHERE option_name='autovacuum_analyze_scale_factor')
	 FROM pg_class c WHERE c.oid='public.shadow_events'::regclass`).Scan(&vacuum, &inserted, &analyze)
	if err != nil || vacuum != "0.005" || inserted != "0.001" || analyze != "0.005" {
		t.Fatalf("missing event visibility defaults: %s/%s/%s (%v)", vacuum, inserted, analyze, err)
	}
	tx, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `ALTER TABLE shadow_events SET(autovacuum_enabled=false,autovacuum_vacuum_scale_factor=0.0001,autovacuum_vacuum_insert_scale_factor=0.02,autovacuum_analyze_scale_factor=0.0002)`); err != nil {
		t.Fatal(err)
	}
	var before, after []string
	if err = tx.QueryRow(ctx, `SELECT reloptions FROM pg_class WHERE oid='public.shadow_events'::regclass`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err = initializeSQLAccessIndexes(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err = tx.QueryRow(ctx, `SELECT reloptions FROM pg_class WHERE oid='public.shadow_events'::regclass`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(before, after) {
		t.Fatal("migration replaced an explicit operator choice")
	}
}
