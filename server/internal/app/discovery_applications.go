package app

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
)

// The background path owns a fresh tenant transaction. Its arguments contain
// only a bounded aggregate key and an edition-selected constant SQL fragment.
func (a *App) refreshDiscoveryApplications(ctx context.Context, key discoveryReadKey, additional string) (json.RawMessage, error) {
	tx, err := a.db.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT set_config('milvago.organization_id',$1,true)`, key.organization); err != nil {
		return nil, err
	}
	return readDiscoveryApplications(ctx, tx, key, additional)
}

func readDiscoveryApplications(ctx context.Context, tx pgx.Tx, key discoveryReadKey, additional string) (json.RawMessage, error) {
	// Seek distinct application keys without rereading every identification.
	// Deduplicate entities within each indexed device/scope group so dense
	// fleets never produce an intermediate aggregate row for every entity.
	rows, err := tx.Query(ctx, `WITH RECURSIVE identification_keys AS (
 (SELECT application_id,1 ordinal FROM discovery_identifications
 WHERE organization_id=$1 AND expires_at>now() AND application_id>$2 AND strpos(lower(application_id),lower($3))>0
 ORDER BY application_id LIMIT 1)
 UNION ALL
 SELECT next.application_id,previous.ordinal+1 FROM identification_keys previous CROSS JOIN LATERAL (
 SELECT application_id FROM discovery_identifications WHERE organization_id=$1 AND expires_at>now()
 AND application_id>previous.application_id AND strpos(lower(application_id),lower($3))>0
 ORDER BY application_id LIMIT 1) next WHERE previous.ordinal<$4
 ), page_keys AS MATERIALIZED (
 SELECT application_id FROM (
 SELECT application_id FROM identification_keys
 UNION `+discoveryAdditionalInventoryKeys(key.inventory)+`
 ) selected ORDER BY application_id LIMIT $4), scopes AS (
 SELECT application_id,device_id,scope,count(DISTINCT entity_id) instances,min(first_seen) first_seen,max(last_seen) last_seen,
 bool_or(state='executed') executed,bool_or(state='indication') indication,bool_or(state='installed') installed,bool_or(state='interface_recognized') interface
 FROM discovery_identifications WHERE organization_id=$1 AND expires_at>now() AND application_id IN (SELECT application_id FROM page_keys)
 GROUP BY application_id,device_id,scope),
 base_devices AS (
 SELECT application_id,device_id,sum(instances) instances,min(first_seen) first_seen,max(last_seen) last_seen,
 bool_or(executed) executed,bool_or(indication) indication,bool_or(installed) installed,bool_or(interface) interface
 FROM scopes GROUP BY application_id,device_id),
 additional_devices AS (SELECT * FROM (`+additional+`) selected WHERE application_id IN (SELECT application_id FROM page_keys)),
 devices AS (
 SELECT application_id,device_id,sum(instances) instances,min(first_seen) first_seen,max(last_seen) last_seen,
 bool_or(executed) executed,bool_or(indication) indication,bool_or(installed) installed,bool_or(interface) interface
 FROM (SELECT * FROM base_devices UNION ALL SELECT * FROM additional_devices) merged GROUP BY application_id,device_id),
 applications AS (
 SELECT application_id,count(*) devices,sum(instances) instances,min(first_seen) first_seen,max(last_seen) last_seen,
 array_remove(ARRAY[CASE WHEN bool_or(executed) THEN 'executed' END,CASE WHEN bool_or(indication) THEN 'indication' END,CASE WHEN bool_or(installed) THEN 'installed' END,CASE WHEN bool_or(interface) THEN 'interface_recognized' END],NULL) states
 FROM devices GROUP BY application_id)
 SELECT a.application_id,a.devices,a.instances,a.states,a.first_seen,a.last_seen,coalesce(v.status,'review') FROM applications a LEFT JOIN discovery_reviews v ON v.organization_id=$1 AND v.application_id=a.application_id ORDER BY a.application_id LIMIT $4`, key.organization, key.after, key.query, key.limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, status string
		var devices, instances int
		var states []string
		var first, last any
		if err = rows.Scan(&id, &devices, &instances, &states, &first, &last, &status); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "devices": devices, "instances": instances, "states": states, "first_seen": first, "last_seen": last, "review": status})
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	next := ""
	if len(items) > key.limit {
		items = items[:key.limit]
		next = discoveryCursor(items[len(items)-1]["id"].(string))
	}
	discoveryInventoryMetadata("", items)
	return json.Marshal(map[string]any{"items": items, "next_cursor": next})
}
