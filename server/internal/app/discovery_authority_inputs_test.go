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

type discoveryInputsRow func(...any) error

func (row discoveryInputsRow) Scan(dest ...any) error { return row(dest...) }

type discoveryInputsBatch struct {
	pgx.BatchResults
	execErr, settingsErr, catalogErr, closeErr error
	settings, catalog                          []byte
	execs, rows, closes                        int
}

func (batch *discoveryInputsBatch) Exec() (pgconn.CommandTag, error) {
	batch.execs++
	return pgconn.NewCommandTag("SELECT 1"), batch.execErr
}
func (batch *discoveryInputsBatch) QueryRow() pgx.Row {
	index := batch.rows
	batch.rows++
	return discoveryInputsRow(func(dest ...any) error {
		switch index {
		case 0:
			if batch.settingsErr != nil {
				return batch.settingsErr
			}
			*dest[0].(*int64) = 700
			*dest[1].(*[]byte) = append([]byte(nil), batch.settings...)
			return nil
		case 1:
			if batch.catalogErr != nil {
				return batch.catalogErr
			}
			*dest[0].(*json.RawMessage) = append(json.RawMessage(nil), batch.catalog...)
			return nil
		default:
			return errors.New("unexpected authority result")
		}
	})
}
func (batch *discoveryInputsBatch) Close() error {
	batch.closes++
	return batch.closeErr
}

type discoveryInputsTx struct {
	pgx.Tx
	results *discoveryInputsBatch
	queued  []*pgx.QueuedQuery
}

func (tx *discoveryInputsTx) SendBatch(_ context.Context, batch *pgx.Batch) pgx.BatchResults {
	tx.queued = append([]*pgx.QueuedQuery(nil), batch.QueuedQueries...)
	return tx.results
}

func TestDiscoveryAuthorityInputsBatchKeepsOrderErrorsAndCheckedDrain(t *testing.T) {
	queryFailure := errors.New("synthetic authority query failure")
	closeFailure := errors.New("synthetic authority drain failure")
	for _, scenario := range []struct {
		name                                       string
		execErr, settingsErr, catalogErr, closeErr error
		malformed, factory                         bool
		wantStatus, wantRows                       int
		wantError                                  error
	}{
		{name: "exact_catalog", wantRows: 2},
		{name: "factory_fallback", catalogErr: pgx.ErrNoRows, factory: true, wantRows: 2},
		{name: "missing_settings", settingsErr: pgx.ErrNoRows, wantStatus: 409, wantRows: 1},
		{name: "invalid_stored_settings", malformed: true, wantRows: 1},
		{name: "advisory_error", execErr: queryFailure, closeErr: queryFailure, wantError: queryFailure},
		{name: "settings_error", settingsErr: queryFailure, wantRows: 1, wantError: queryFailure},
		{name: "catalog_error", catalogErr: queryFailure, wantRows: 2, wantError: queryFailure},
		{name: "late_drain_error", closeErr: closeFailure, wantRows: 2, wantError: closeFailure},
		{name: "missing_settings_and_drain_error", settingsErr: pgx.ErrNoRows, closeErr: closeFailure, wantStatus: 409, wantRows: 1, wantError: closeFailure},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			results := &discoveryInputsBatch{
				execErr: scenario.execErr, settingsErr: scenario.settingsErr, catalogErr: scenario.catalogErr, closeErr: scenario.closeErr,
				settings: []byte(`{"host":true,"interval_seconds":300}`), catalog: []byte(` {"revision":7, "name":"Synthetic catalog"} `),
			}
			if scenario.malformed {
				results.settings = []byte(`{"host":"synthetic invalid boolean"}`)
			}
			tx := &discoveryInputsTx{results: results}
			revision, configuration, catalog, err := readDiscoveryReportInputs(context.Background(), tx, "tenant-a", "device-a")
			if results.closes != 1 || results.execs != 1 || results.rows != scenario.wantRows {
				t.Fatal("batch was not completely closed before returning", results.closes, results.execs, results.rows)
			}
			wantSQL := []string{
				`SELECT pg_advisory_xact_lock(hashtextextended($1,713905))`,
				`SELECT revision,configuration FROM discovery_settings WHERE organization_id=$1 FOR SHARE`,
				`SELECT content FROM discovery_catalogs WHERE organization_id=$1 FOR SHARE`,
			}
			if len(tx.queued) != len(wantSQL) {
				t.Fatal("authority batch changed its bounded statement count")
			}
			for index, query := range tx.queued {
				argument := "tenant-a"
				if index == 0 {
					argument += "/device-a"
				}
				if query.SQL != wantSQL[index] || len(query.Arguments) != 1 || query.Arguments[0] != argument {
					t.Fatal("authority SQL order or tenant/device arguments changed", index)
				}
			}
			if scenario.wantStatus != 0 {
				var denied apiError
				if !errors.As(err, &denied) || denied.status != 409 || denied.code != "discovery_disabled" || denied.message != "Discovery is disabled." {
					t.Fatal("missing settings changed its refusal", err)
				}
			}
			if scenario.wantError != nil && !errors.Is(err, scenario.wantError) {
				t.Fatal("query or drain failure was lost", err)
			}
			if scenario.malformed && (err == nil || err.Error() != "invalid stored discovery settings") {
				t.Fatal("invalid settings changed its error", err)
			}
			if scenario.wantStatus != 0 || scenario.wantError != nil || scenario.malformed {
				return
			}
			wantCatalog := results.catalog
			if scenario.factory {
				wantCatalog = discoveryFactory
			}
			if err != nil || revision != 700 || !configuration.Host || configuration.IntervalSeconds != 300 || !bytes.Equal(catalog, wantCatalog) {
				t.Fatal("successful authority inputs or exact catalog bytes changed", err)
			}
		})
	}
}
