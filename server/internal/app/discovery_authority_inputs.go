package app

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
)

// The caller already holds the current device, privacy and policy authority
// locks. Ordered reads are sent together, never an authorization cache.
func readDiscoveryReportInputs(ctx context.Context, tx pgx.Tx, org, device string) (revision int64, configuration DiscoverySettings, catalog json.RawMessage, err error) {
	var batch pgx.Batch
	// One device cannot race several scopes to bypass per-device storage admission.
	batch.Queue(`SELECT pg_advisory_xact_lock(hashtextextended($1,713905))`, org+"/"+device)
	batch.Queue(`SELECT revision,configuration FROM discovery_settings WHERE organization_id=$1 FOR SHARE`, org)
	batch.Queue(`SELECT content FROM discovery_catalogs WHERE organization_id=$1 FOR SHARE`, org)
	results := tx.SendBatch(ctx, &batch)
	defer func() {
		// Drain on every return, including a missing row or Go decode error.
		// No caller may use these values before all server results are checked.
		if closeErr := results.Close(); closeErr != nil && !errors.Is(err, closeErr) {
			err = errors.Join(err, closeErr)
		}
	}()
	if _, err = results.Exec(); err != nil {
		return
	}
	var settingsRaw []byte
	err = results.QueryRow().Scan(&revision, &settingsRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		err = apiError{409, "discovery_disabled", "Discovery is disabled."}
		return
	}
	if err != nil {
		return
	}
	if json.Unmarshal(settingsRaw, &configuration) != nil {
		err = errors.New("invalid stored discovery settings")
		return
	}
	err = results.QueryRow().Scan(&catalog)
	if errors.Is(err, pgx.ErrNoRows) {
		catalog, err = discoveryFactory, nil
	}
	return
}
