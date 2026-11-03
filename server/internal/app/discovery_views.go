package app

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func discoveryDetails(r *http.Request, s *Session) error {
	if err := requireIndividual(r); err != nil {
		return err
	}
	if !hasPermission(s.Permissions, permDevicesRead) {
		return forbidden()
	}
	return nil
}
func (a *App) discoveryEnvironments(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if err := discoveryDetails(r, s); err != nil {
		return err
	}
	limit, cursor, err := discoveryPage(r)
	if err != nil {
		return err
	}
	device, scope, id := "", "", ""
	if len(cursor) > 0 {
		if len(cursor) != 3 || !uuidPattern.MatchString(cursor[0]) || !discoveryID(cursor[1]) || !discoveryID(cursor[2]) {
			return bad("Invalid environment cursor.")
		}
		device, scope, id = cursor[0], cursor[1], cursor[2]
	}
	kind := r.URL.Query().Get("kind")
	if kind != "" && !strings.Contains("|host|vm|wsl|runtime|container|endpoint|", "|"+kind+"|") {
		return bad("Invalid environment kind.")
	}
	rows, err := tx.Query(r.Context(), `SELECT device_id::text,scope,id,kind,first_seen,last_seen,display FROM discovery_entities WHERE organization_id=$1 AND kind<>'process' AND expires_at>now() AND ($2='' OR kind=$2) AND (device_id,scope,id)>(coalesce(nullif($3,'')::uuid,'00000000-0000-0000-0000-000000000000'::uuid),$4,$5) ORDER BY discovery_entities.device_id,scope,id LIMIT $6`, s.OrganizationID, kind, device, scope, id, limit+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var device, scope, id, kind string
		var first, last any
		var display json.RawMessage
		if err = rows.Scan(&device, &scope, &id, &kind, &first, &last, &display); err != nil {
			return err
		}
		items = append(items, map[string]any{"device_id": device, "scope": scope, "id": id, "kind": kind, "first_seen": first, "last_seen": last, "display": display})
	}
	if err = rows.Err(); err != nil {
		return err
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1]
		next = discoveryCursor(last["device_id"].(string), last["scope"].(string), last["id"].(string))
	}
	if err := a.discoveryDeviceNames(r, tx, s, items); err != nil {
		return err
	}
	reply(w, 200, map[string]any{"items": items, "next_cursor": next})
	return nil
}
func (a *App) discoveryEnvironment(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if err := discoveryDetails(r, s); err != nil {
		return err
	}
	id := r.PathValue("id")
	device := r.URL.Query().Get("device_id")
	requestedScope := r.URL.Query().Get("scope")
	if !discoveryID(id) || !uuidPattern.MatchString(device) || requestedScope != "" && !discoveryID(requestedScope) {
		return bad("An environment and device are required.")
	}
	limit, cursor, err := discoveryPage(r)
	if err != nil {
		return err
	}
	from, to, relationKind := "", "", ""
	if len(cursor) > 0 {
		if len(cursor) != 3 || !discoveryID(cursor[0]) || !discoveryID(cursor[1]) || !discoveryID(cursor[2]) {
			return bad("Invalid relationship cursor.")
		}
		from, to, relationKind = cursor[0], cursor[1], cursor[2]
	}
	var kind, scope string
	var seen any
	var display json.RawMessage
	if err := tx.QueryRow(r.Context(), `SELECT kind,scope,last_seen,display FROM discovery_entities WHERE organization_id=$1 AND device_id=$2 AND id=$3 AND ($4='' OR scope=$4) AND expires_at>now() ORDER BY last_seen DESC LIMIT 1`, s.OrganizationID, device, id, requestedScope).Scan(&kind, &scope, &seen, &display); err != nil {
		if err == pgx.ErrNoRows {
			return apiError{404, "not_found", "Environment not found."}
		}
		return err
	}
	rows, err := tx.Query(r.Context(), `SELECT source_id,target_id,kind,source FROM discovery_relations WHERE organization_id=$1 AND device_id=$2 AND scope=$3 AND (source_id=$4 OR target_id=$4) AND expires_at>now() AND (source_id,target_id,kind)>($5,$6,$7) ORDER BY source_id,target_id,kind LIMIT $8`, s.OrganizationID, device, scope, id, from, to, relationKind, limit+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	relations := []map[string]string{}
	for rows.Next() {
		var from, to, kind, source string
		if err = rows.Scan(&from, &to, &kind, &source); err != nil {
			return err
		}
		relations = append(relations, map[string]string{"from": from, "to": to, "kind": kind, "source": source})
	}
	if err = rows.Err(); err != nil {
		return err
	}
	truncated := len(relations) > limit
	next := ""
	if truncated {
		relations = relations[:limit]
		last := relations[len(relations)-1]
		next = discoveryCursor(last["from"], last["to"], last["kind"])
	}
	value := map[string]any{"id": id, "device_id": device, "scope": scope, "kind": kind, "last_seen": seen, "display": display, "relations": relations, "relations_truncated": truncated, "relations_next_cursor": next}
	if err := a.discoveryDeviceNames(r, tx, s, []map[string]any{value}); err != nil {
		return err
	}
	reply(w, 200, value)
	return nil
}
func (a *App) discoveryCoverage(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if err := discoveryDetails(r, s); err != nil {
		return err
	}
	limit, cursor, err := discoveryPage(r)
	if err != nil {
		return err
	}
	selectedDevice := strings.ToLower(r.URL.Query().Get("device_id"))
	if selectedDevice != "" && !uuidPattern.MatchString(selectedDevice) {
		return bad("Invalid device filter.")
	}
	device, scope, adapter := "", "", ""
	if len(cursor) > 0 {
		if len(cursor) != 3 || !uuidPattern.MatchString(cursor[0]) || !discoveryID(cursor[1]) || !discoveryID(cursor[2]) {
			return bad("Invalid coverage cursor.")
		}
		device, scope, adapter = strings.ToLower(cursor[0]), cursor[1], cursor[2]
		if selectedDevice != "" && device != selectedDevice {
			return bad("Coverage cursor belongs to another device.")
		}
	}
	filter := ""
	args := []any{s.OrganizationID, device, scope, adapter, limit + 1}
	if selectedDevice != "" {
		filter = " AND device_id=$6::uuid"
		args = append(args, selectedDevice)
	}
	rows, err := tx.Query(r.Context(), `WITH visible AS (
 SELECT device_id,scope,adapter,status,complete,checked_at,''::text reason,scope='server' server_assessed
 FROM discovery_coverage WHERE organization_id=$1 AND expires_at>now()
 UNION ALL
 SELECT d.id,'server',CASE WHEN d.capabilities ? 'discovery-v1' THEN 'report-reception' ELSE 'agent-capability' END,
 'unavailable',false,now(),CASE WHEN d.capabilities ? 'discovery-v1' THEN 'source_coverage_missing' ELSE 'agent_capability_missing' END,true
 FROM devices d WHERE d.organization_id=$1 AND d.status='approved'
 AND NOT EXISTS(SELECT 1 FROM discovery_coverage c WHERE c.organization_id=$1 AND c.device_id=d.id AND c.expires_at>now())
 ) SELECT device_id::text,scope,adapter,status,complete,checked_at,reason,server_assessed FROM visible
 WHERE (device_id,scope,adapter)>(coalesce(nullif($2,'')::uuid,'00000000-0000-0000-0000-000000000000'::uuid),$3,$4)
 `+filter+` ORDER BY visible.device_id,scope,adapter LIMIT $5`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var device, scope, adapter, status string
		var complete, serverAssessed bool
		var reason string
		var checked any
		if err = rows.Scan(&device, &scope, &adapter, &status, &complete, &checked, &reason, &serverAssessed); err != nil {
			return err
		}
		items = append(items, map[string]any{"device_id": device, "scope": scope, "adapter": adapter, "status": status, "complete": complete, "checked_at": checked, "reason": reason, "server_assessed": serverAssessed})
	}
	if err = rows.Err(); err != nil {
		return err
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1]
		next = discoveryCursor(last["device_id"].(string), last["scope"].(string), last["adapter"].(string))
	}
	if err := a.discoveryDeviceNames(r, tx, s, items); err != nil {
		return err
	}
	reply(w, 200, map[string]any{"items": items, "next_cursor": next})
	return nil
}
func (a *App) discoveryEvents(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if err := discoveryDetails(r, s); err != nil {
		return err
	}
	limit, cursor, err := discoveryPage(r)
	if err != nil {
		return err
	}
	var after *time.Time
	afterID := ""
	if len(cursor) > 0 {
		if len(cursor) != 2 || !uuidPattern.MatchString(cursor[1]) {
			return bad("Invalid event cursor.")
		}
		parsed, e := time.Parse(time.RFC3339Nano, cursor[0])
		if e != nil {
			return bad("Invalid event cursor.")
		}
		after = &parsed
		afterID = cursor[1]
	}
	application := r.URL.Query().Get("application_id")
	if application != "" && !discoveryID(application) {
		return bad("Invalid application.")
	}
	device, scope, entity := r.URL.Query().Get("device_id"), r.URL.Query().Get("scope"), r.URL.Query().Get("entity_id")
	if device != "" && !uuidPattern.MatchString(device) || scope != "" && !discoveryID(scope) || entity != "" && !discoveryID(entity) {
		return bad("Invalid environment event filter.")
	}
	rows, err := tx.Query(r.Context(), `SELECT id::text,device_id::text,entity_id,kind,application_id,occurred_at FROM discovery_events WHERE organization_id=$1 AND expires_at>now() AND ($2::timestamptz IS NULL OR (occurred_at,id)<($2::timestamptz,nullif($3,'')::uuid)) AND ($4='' OR application_id=$4) AND ($5='' OR device_id=nullif($5,'')::uuid) AND ($6='' OR scope=$6) AND ($7='' OR entity_id=$7) ORDER BY occurred_at DESC,discovery_events.id DESC LIMIT $8`, s.OrganizationID, after, afterID, application, device, scope, entity, limit+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, device, entity, kind, app string
		var when time.Time
		if err = rows.Scan(&id, &device, &entity, &kind, &app, &when); err != nil {
			return err
		}
		items = append(items, map[string]any{"id": id, "device_id": device, "entity_id": entity, "kind": kind, "application_id": app, "occurred_at": when})
	}
	if err = rows.Err(); err != nil {
		return err
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1]
		next = discoveryCursor(last["occurred_at"].(time.Time).UTC().Format(time.RFC3339Nano), last["id"].(string))
	}
	if err := a.discoveryDeviceNames(r, tx, s, items); err != nil {
		return err
	}
	reply(w, 200, map[string]any{"items": items, "next_cursor": next})
	return nil
}
func (a *App) discoveryEvidence(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if err := discoveryDetails(r, s); err != nil {
		return err
	}
	id := r.PathValue("id")
	if !uuidPattern.MatchString(id) {
		return bad("Invalid evidence identifier.")
	}
	var proof json.RawMessage
	if err := tx.QueryRow(r.Context(), `SELECT evidence FROM discovery_events WHERE organization_id=$1 AND id=$2 AND expires_at>now()`, s.OrganizationID, id).Scan(&proof); err != nil {
		if err == pgx.ErrNoRows {
			return apiError{404, "not_found", "Evidence not found."}
		}
		return err
	}
	reply(w, 200, map[string]any{"id": id, "evidence": proof})
	return nil
}
