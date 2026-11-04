package app

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// Retain only the full opaque event key across erasure. Removing the event row
// must not turn an unacknowledged, still admissible retry into a new record.
func initializeErasedEvents(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS shadow_erased_events (
 organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
 device_id uuid NOT NULL,
 event_id uuid NOT NULL,
 expires_at timestamptz NOT NULL,
 PRIMARY KEY(organization_id,device_id,event_id),
 FOREIGN KEY(organization_id,device_id) REFERENCES devices(organization_id,id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS shadow_erased_events_expiry ON shadow_erased_events(organization_id,expires_at);
ALTER TABLE shadow_erased_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE shadow_erased_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant ON shadow_erased_events;
CREATE POLICY tenant ON shadow_erased_events
 USING(current_user<>'milvago_lookup' AND organization_id=nullif(current_setting('milvago.organization_id',true),'')::uuid)
 WITH CHECK(current_user<>'milvago_lookup' AND organization_id=nullif(current_setting('milvago.organization_id',true),'')::uuid);`)
	return err
}

func (a *App) purgeErasedEvents(ctx context.Context, org string) error {
	tx, err := tenantTx(ctx, a.db, org)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	chain, err := barrierChain(ctx, tx, org)
	if err != nil {
		return err
	}
	// Ingestion validates age after taking the shared barrier. Do not remove a
	// marker while an already-admitted retry can still use that earlier time.
	for i, id := range chain {
		query := `SELECT pg_advisory_xact_lock_shared(` + barrierKeySQL + `)`
		if i == len(chain)-1 {
			query = `SELECT pg_advisory_xact_lock(` + barrierKeySQL + `)`
		}
		if _, err = tx.Exec(ctx, query, id); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `DELETE FROM shadow_erased_events WHERE organization_id=$1 AND expires_at<now()`, org); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
