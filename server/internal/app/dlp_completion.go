package app

import (
	"github.com/jackc/pgx/v5"
	"net/http"
)

// A completion can advance existing custody evidence, never supply rule identity
// or turn a prevented/cancelled attempt into a successful transmission.
func completeDLPObservation(r *http.Request, tx pgx.Tx, org, device, event string) error {
	_, err := tx.Exec(r.Context(), `UPDATE dlp_decisions d SET delivery='observed',
        decisions=(SELECT jsonb_agg(CASE WHEN item->>'outcome'='prepared' THEN jsonb_set(item,'{outcome}','"observed"'::jsonb) ELSE item END ORDER BY ordinal)
                   FROM jsonb_array_elements(d.decisions) WITH ORDINALITY AS entry(item,ordinal))
        WHERE d.organization_id=$1 AND d.device_id=$2 AND d.event_id=$3 AND d.delivery='prepared'
        AND d.channel='browser' AND EXISTS(SELECT 1 FROM shadow_events e WHERE e.organization_id=d.organization_id AND e.device_id=d.device_id AND e.id=d.event_id AND e.kind='prompt' AND e.action='observed')`, org, device, event)
	return err
}
