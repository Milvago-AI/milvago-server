package app

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// Keep the tenant switch and its dependent policy read as separate, ordered SQL
// statements. Sending them together changes neither RLS nor the per-statement
// READ COMMITTED snapshots. The caller still restores its own tenant context.
func readPrivacyLevel(ctx context.Context, tx pgx.Tx, organization string) (raw []byte, revision int64, err error) {
	var batch pgx.Batch
	batch.Queue(sqlSetOrganizationContext, organization)
	batch.Queue("SELECT configuration,revision FROM privacy_settings WHERE organization_id=$1", organization)
	results := tx.SendBatch(ctx, &batch)
	defer func() {
		// Drain and check before decoding, visiting another ancestor, or restoring
		// the tenant. A missing row must not mask a later protocol/server error.
		if closeErr := results.Close(); closeErr != nil && !errors.Is(err, closeErr) {
			err = errors.Join(err, closeErr)
		}
	}()
	if _, err = results.Exec(); err != nil {
		return
	}
	err = results.QueryRow().Scan(&raw, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		raw, revision, err = []byte("{}"), 1, nil
	}
	return
}
