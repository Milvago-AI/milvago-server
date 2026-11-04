package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestDiscoveryAuthorityInputsBatchMissingRowsCatalogAndTenantScope(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	const device = "00000000-0000-4000-8000-000000000001"
	check := func(org string, missing bool, expected json.RawMessage) {
		t.Helper()
		tx, err := tenantTx(ctx, f.a.db, f.org)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		revision, configuration, catalog, err := readDiscoveryReportInputs(ctx, tx, org, device)
		if missing {
			var denied apiError
			if !errors.As(err, &denied) || denied.status != 409 || denied.code != "discovery_disabled" {
				t.Fatal("missing or foreign settings changed its refusal", err)
			}
		} else if err != nil || revision != 700 || !configuration.Host || !bytes.Equal(catalog, expected) {
			t.Fatal("fresh settings or exact current catalog changed", err)
		}
		// A missing row is not a SQL error: all unread results must be drained
		// before the caller can issue another query on this same connection.
		var ready int
		if err = tx.QueryRow(ctx, `SELECT 1`).Scan(&ready); err != nil || ready != 1 {
			t.Fatal("authority batch left an unread result or busy connection", err)
		}
		if err = tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	}
	check(f.org, true, nil)
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_settings(organization_id,revision,configuration) VALUES($1,700,'{"host":true,"interval_seconds":300}')`, f.org); err != nil {
		t.Fatal(err)
	}
	check(f.org, false, discoveryFactory)
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_catalogs(organization_id,content) VALUES($1,$2)`, f.org, discoveryFactory); err != nil {
		t.Fatal(err)
	}
	var stored json.RawMessage
	if err := f.admin.QueryRow(ctx, `SELECT content FROM discovery_catalogs WHERE organization_id=$1`, f.org).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	check(f.org, false, stored)

	// Changing the explicit SQL organization cannot escape the runtime tenant.
	var foreign string
	if err := f.admin.QueryRow(ctx, `INSERT INTO organizations(name,parent_id) VALUES('Synthetic authority tenant',$1) RETURNING id`, f.org).Scan(&foreign); err != nil {
		t.Fatal(err)
	}
	foreignTx, err := tenantTx(ctx, f.admin, foreign)
	if err != nil {
		t.Fatal(err)
	}
	defer foreignTx.Rollback(ctx)
	if _, err = foreignTx.Exec(ctx, `INSERT INTO discovery_settings(organization_id,revision,configuration) VALUES($1,900,'{"host":true,"interval_seconds":300}')`, foreign); err != nil {
		t.Fatal(err)
	}
	if _, err = foreignTx.Exec(ctx, `INSERT INTO discovery_catalogs(organization_id,content) VALUES($1,$2)`, foreign, discoveryFactory); err != nil {
		t.Fatal(err)
	}
	if err = foreignTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	check(foreign, true, nil)

	tx, err := tenantTx(ctx, f.a.db, f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, _, _, err = readDiscoveryReportInputs(ctx, tx, f.org, device); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"discovery_settings", "discovery_catalogs"} {
		probe, err := f.admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, queryErr := probe.Exec(ctx, "SELECT organization_id FROM "+table+" WHERE organization_id=$1 FOR UPDATE NOWAIT", f.org)
		rollbackErr := probe.Rollback(ctx)
		var locked *pgconn.PgError
		if !errors.As(queryErr, &locked) || locked.Code != "55P03" || rollbackErr != nil {
			t.Fatal("authority batch did not retain its configuration share lock", table, queryErr, rollbackErr)
		}
	}
	var free bool
	if err = f.admin.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1,713905))`, f.org+"/"+device).Scan(&free); err != nil || free {
		t.Fatal("authority batch did not retain the per-device lock", free, err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err = f.admin.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1,713905))`, f.org+"/"+device).Scan(&free); err != nil || !free {
		t.Fatal("authority transaction did not release its per-device lock", free, err)
	}
}

type discoveryInputsLateFailureTx struct{ pgx.Tx }

func (tx *discoveryInputsLateFailureTx) SendBatch(ctx context.Context, batch *pgx.Batch) pgx.BatchResults {
	// These stable calls prevent a constant-folded preparation error. The
	// fourth statement fails after the real authority results have been read.
	batch.Queue(`SELECT 1 / (pg_backend_pid() - pg_backend_pid())`)
	return tx.Tx.SendBatch(ctx, batch)
}

func TestDiscoveryAuthorityInputsBatchReturnsLateServerDrainError(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_settings(organization_id,revision,configuration) VALUES($1,700,'{"host":true,"interval_seconds":300}')`, f.org); err != nil {
		t.Fatal(err)
	}
	tx, err := tenantTx(ctx, f.a.db, f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	revision, configuration, catalog, err := readDiscoveryReportInputs(ctx, &discoveryInputsLateFailureTx{Tx: tx}, f.org, "00000000-0000-4000-8000-000000000001")
	var failure *pgconn.PgError
	if !errors.As(err, &failure) || failure.Code != "22012" {
		t.Fatal("late server error was not returned before authority handoff", err)
	}
	if revision != 700 || !configuration.Host || !bytes.Equal(catalog, discoveryFactory) {
		t.Fatal("failure occurred before all real authority inputs were read")
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if f.a.db.Stat().AcquiredConns() != 0 {
		t.Fatal("failed authority batch retained its runtime connection")
	}
}
