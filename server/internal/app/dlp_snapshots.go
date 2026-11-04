package app

import (
	"context"
	"github.com/jackc/pgx/v5"
)

const dlpSnapshotLimit = 10000

// A bounded archive preserves immutable evidence without letting policy edits
// grow storage indefinitely during the historical retention window.
func ensureDLPSnapshot(ctx context.Context, tx pgx.Tx, org string, policy DLPPolicy) error {
	fingerprint := dlpFingerprint(policy)
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM dlp_policy_snapshots WHERE organization_id=$1 AND fingerprint=$2)`, org, fingerprint).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,73))`, org); err != nil {
		return err
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM dlp_policy_snapshots WHERE organization_id=$1 AND fingerprint<>$2`, org, fingerprint).Scan(&count); err != nil {
		return err
	}
	if count >= dlpSnapshotLimit {
		return apiError{409, "dlp_archive_capacity", "The DLP policy archive is full. Wait for historical retention cleanup before creating another revision."}
	}
	_, err := tx.Exec(ctx, `INSERT INTO dlp_policy_snapshots(organization_id,fingerprint,policy) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, org, fingerprint, dlpJSON(policy))
	return err
}
