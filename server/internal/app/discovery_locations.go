package app

import (
	"github.com/jackc/pgx/v5"
	"net/http"
)

// Qualify UUID sort keys: an unqualified output name selects its text cast,
// forcing a fleet-wide sort before LIMIT instead of using the UUID index.
// Page complete device groups, not raw proof rows: a device with many signals
// must never be split into misleading duplicate locations across page boundaries.
func (a *App) discoveryLocations(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if err := discoveryDetails(r, s); err != nil {
		return err
	}
	id := r.PathValue("id")
	if !discoveryID(id) {
		return bad("Invalid application.")
	}
	limit, cursor, err := discoveryPage(r)
	if err != nil {
		return err
	}
	after := ""
	if len(cursor) > 0 {
		if len(cursor) != 1 || !uuidPattern.MatchString(cursor[0]) {
			return bad("Invalid location cursor.")
		}
		after = cursor[0]
	}
	rows, err := tx.Query(r.Context(), `SELECT device_id::text,count(*) observations,min(first_seen),max(last_seen),
 array_remove(ARRAY[CASE WHEN bool_or(state='executed') THEN 'executed' END,CASE WHEN bool_or(state='indication') THEN 'indication' END,CASE WHEN bool_or(state='installed') THEN 'installed' END,CASE WHEN bool_or(state='interface_recognized') THEN 'interface_recognized' END],NULL)
 FROM `+discoveryInventorySource(s)+` WHERE organization_id=$1 AND application_id=$2 AND expires_at>now()
 AND device_id>coalesce(nullif($3,'')::uuid,'00000000-0000-0000-0000-000000000000'::uuid)
 GROUP BY device_id ORDER BY discovery_identifications.device_id LIMIT $4`, s.OrganizationID, id, after, limit+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var device string
		var count int
		var first, last any
		var states []string
		if err = rows.Scan(&device, &count, &first, &last, &states); err != nil {
			return err
		}
		items = append(items, map[string]any{"device_id": device, "observations": count, "first_seen": first, "last_seen": last, "states": states})
	}
	if err = rows.Err(); err != nil {
		return err
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		next = discoveryCursor(items[len(items)-1]["device_id"].(string))
	}
	if err = a.governanceForLocations(r, tx, s, id, items); err != nil {
		return err
	}
	if err = a.discoveryDeviceNames(r, tx, s, items); err != nil {
		return err
	}
	reply(w, 200, map[string]any{"items": items, "next_cursor": next})
	return nil
}
