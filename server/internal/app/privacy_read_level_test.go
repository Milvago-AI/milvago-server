package app

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type privacyLevelRow func(...any) error

func (row privacyLevelRow) Scan(dest ...any) error { return row(dest...) }

type privacyLevelResults struct {
	pgx.BatchResults
	execErr, rowErr, closeErr error
	raw                       []byte
	execs, rows, closes       int
}

func (results *privacyLevelResults) Exec() (pgconn.CommandTag, error) {
	results.execs++
	return pgconn.NewCommandTag("SELECT 1"), results.execErr
}
func (results *privacyLevelResults) QueryRow() pgx.Row {
	results.rows++
	return privacyLevelRow(func(dest ...any) error {
		if results.rowErr != nil {
			return results.rowErr
		}
		*dest[0].(*[]byte) = append([]byte(nil), results.raw...)
		*dest[1].(*int64) = 73
		return nil
	})
}
func (results *privacyLevelResults) Close() error { results.closes++; return results.closeErr }

type privacyLevelTx struct {
	pgx.Tx
	results *privacyLevelResults
	queued  []*pgx.QueuedQuery
	ctx     context.Context
}

func (tx *privacyLevelTx) SendBatch(ctx context.Context, batch *pgx.Batch) pgx.BatchResults {
	tx.ctx = ctx
	tx.queued = append([]*pgx.QueuedQuery(nil), batch.QueuedQueries...)
	return tx.results
}

func TestPrivacyReadLevelKeepsTenantOrderDefaultsAndCheckedDrain(t *testing.T) {
	queryFailure := errors.New("synthetic privacy read failure")
	closeFailure := errors.New("synthetic privacy drain failure")
	for _, scenario := range []struct {
		name                      string
		execErr, rowErr, closeErr error
		wantRows                  int
		wantError                 error
	}{
		{name: "exact_raw", wantRows: 1},
		{name: "missing_policy_defaults", rowErr: pgx.ErrNoRows, wantRows: 1},
		{name: "tenant_switch_error", execErr: queryFailure, closeErr: queryFailure, wantError: queryFailure},
		{name: "policy_read_error", rowErr: queryFailure, wantRows: 1, wantError: queryFailure},
		{name: "late_close_error", closeErr: closeFailure, wantRows: 1, wantError: closeFailure},
		{name: "missing_policy_and_close_error", rowErr: pgx.ErrNoRows, closeErr: closeFailure, wantRows: 1, wantError: closeFailure},
		{name: "query_and_distinct_close_error", rowErr: queryFailure, closeErr: closeFailure, wantRows: 1, wantError: queryFailure},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			results := &privacyLevelResults{execErr: scenario.execErr, rowErr: scenario.rowErr, closeErr: scenario.closeErr, raw: []byte(` {"pseudonymous":true,"k_anonymity":11} `)}
			tx := &privacyLevelTx{results: results}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			raw, revision, err := readPrivacyLevel(ctx, tx, "synthetic-tenant")
			if results.execs != 1 || results.rows != scenario.wantRows || results.closes != 1 {
				t.Fatal("batch did not check exactly one complete drain", results.execs, results.rows, results.closes)
			}
			if tx.ctx != ctx || len(tx.queued) != 2 || tx.queued[0].SQL != sqlSetOrganizationContext || tx.queued[1].SQL != "SELECT configuration,revision FROM privacy_settings WHERE organization_id=$1" {
				t.Fatal("tenant context/read SQL ordering changed")
			}
			for _, query := range tx.queued {
				if len(query.Arguments) != 1 || query.Arguments[0] != "synthetic-tenant" {
					t.Fatal("privacy level did not bind its organization")
				}
			}
			if scenario.wantError != nil {
				if !errors.Is(err, scenario.wantError) {
					t.Fatal("query/drain failure lost", err)
				}
				if scenario.closeErr != nil && !errors.Is(err, scenario.closeErr) {
					t.Fatal("distinct close failure lost", err)
				}
				return
			}
			wantRaw, wantRevision := results.raw, int64(73)
			if errors.Is(scenario.rowErr, pgx.ErrNoRows) {
				wantRaw, wantRevision = []byte("{}"), 1
			}
			if err != nil || revision != wantRevision || !bytes.Equal(raw, wantRaw) {
				t.Fatal("privacy bytes or missing-row defaults changed", revision, err)
			}
		})
	}
}
