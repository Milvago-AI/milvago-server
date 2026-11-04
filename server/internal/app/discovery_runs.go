package app

import (
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
)

func (a *App) startDiscoveryRun(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if err := discoveryDetails(r, s); err != nil {
		return err
	}
	var body struct {
		DeviceID string `json:"device_id"`
	}
	if err := decode(w, r, &body); err != nil {
		return err
	}
	if !uuidPattern.MatchString(body.DeviceID) {
		return bad("Invalid device.")
	}
	sourceRevision, configuration, err := readDiscoverySettings(r.Context(), tx, s.OrganizationID)
	if err != nil {
		return err
	}
	catalog, err := currentDiscoveryCatalog(r.Context(), tx, s.OrganizationID)
	if err != nil {
		return err
	}
	configuration, _, err = a.effectiveDiscovery(r.Context(), tx, s.OrganizationID, body.DeviceID, sourceRevision, configuration, catalog)
	if err != nil {
		return err
	}
	if !configuration.Host && !configuration.Containers && !configuration.VirtualMachines && !configuration.Network {
		return apiError{409, "discovery_disabled", "Activate a discovery source before requesting a collection."}
	}
	var capable bool
	if err = tx.QueryRow(r.Context(), `SELECT capabilities ? 'discovery-v1' FROM devices WHERE organization_id=$1 AND id=$2`, s.OrganizationID, body.DeviceID).Scan(&capable); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return apiError{404, "not_found", "Device not found."}
		}
		return err
	}
	if !capable {
		return apiError{409, "agent_update_required", "This agent does not advertise discovery support."}
	}
	if _, err = tx.Exec(r.Context(), `UPDATE discovery_runs SET status='expired' WHERE organization_id=$1 AND device_id=$2 AND status IN ('pending','running') AND expires_at<=now()`, s.OrganizationID, body.DeviceID); err != nil {
		return err
	}
	var id string
	err = tx.QueryRow(r.Context(), `INSERT INTO discovery_runs(organization_id,device_id,status) VALUES($1,$2,'pending') ON CONFLICT(organization_id,device_id) WHERE status IN ('pending','running') DO UPDATE SET device_id=excluded.device_id RETURNING id::text`, s.OrganizationID, body.DeviceID).Scan(&id)
	if err != nil {
		return err
	}
	if err = audit(r.Context(), tx, s.OrganizationID, s.UserID, "discovery.run.request", body.DeviceID); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	reply(w, 202, map[string]any{"id": id, "status": "pending"})
	return nil
}
func (a *App) discoveryRuns(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if err := discoveryDetails(r, s); err != nil {
		return err
	}
	limit, cursor, err := discoveryPage(r)
	if err != nil {
		return err
	}
	after := ""
	if len(cursor) > 0 {
		if len(cursor) != 1 || !uuidPattern.MatchString(cursor[0]) {
			return bad("Invalid run cursor.")
		}
		after = cursor[0]
	}
	rows, err := tx.Query(r.Context(), `SELECT id::text,device_id::text,CASE WHEN status IN ('pending','running') AND expires_at<=now() THEN 'expired' ELSE status END,created_at,expires_at FROM discovery_runs WHERE organization_id=$1 AND id>coalesce(nullif($2,'')::uuid,'00000000-0000-0000-0000-000000000000'::uuid) ORDER BY discovery_runs.id LIMIT $3`, s.OrganizationID, after, limit+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, device, status string
		var created, expires any
		if err = rows.Scan(&id, &device, &status, &created, &expires); err != nil {
			return err
		}
		items = append(items, map[string]any{"id": id, "device_id": device, "status": status, "created_at": created, "expires_at": expires})
	}
	if err = rows.Err(); err != nil {
		return err
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		next = discoveryCursor(items[len(items)-1]["id"].(string))
	}
	if err := a.discoveryDeviceNames(r, tx, s, items); err != nil {
		return err
	}
	reply(w, 200, map[string]any{"items": items, "next_cursor": next})
	return nil
}
func (a *App) discoveryRun(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if err := discoveryDetails(r, s); err != nil {
		return err
	}
	id := r.PathValue("id")
	if !uuidPattern.MatchString(id) {
		return bad("Invalid run.")
	}
	var device, status string
	var created, expires any
	if err := tx.QueryRow(r.Context(), `SELECT device_id::text,CASE WHEN status IN ('pending','running') AND expires_at<=now() THEN 'expired' ELSE status END,created_at,expires_at FROM discovery_runs WHERE organization_id=$1 AND id=$2`, s.OrganizationID, id).Scan(&device, &status, &created, &expires); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return apiError{404, "not_found", "Run not found."}
		}
		return err
	}
	reply(w, 200, map[string]any{"id": id, "device_id": device, "status": status, "created_at": created, "expires_at": expires})
	return nil
}
func (a *App) cancelDiscoveryRun(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if err := discoveryDetails(r, s); err != nil {
		return err
	}
	id := r.PathValue("id")
	if !uuidPattern.MatchString(id) {
		return bad("Invalid run.")
	}
	tag, err := tx.Exec(r.Context(), `UPDATE discovery_runs SET status='cancelled' WHERE organization_id=$1 AND id=$2 AND status IN ('pending','running') AND expires_at>now()`, s.OrganizationID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return apiError{409, "run_not_active", "This collection is no longer active."}
	}
	if err = audit(r.Context(), tx, s.OrganizationID, s.UserID, "discovery.run.cancel", id); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	reply(w, 200, map[string]bool{"ok": true})
	return nil
}
