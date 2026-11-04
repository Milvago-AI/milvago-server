package app

import (
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5"
)

func (a *App) discoveryEnvironmentEvidence(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if err := discoveryDetails(r, s); err != nil {
		return err
	}
	id, device, scope := r.PathValue("id"), r.URL.Query().Get("device_id"), r.URL.Query().Get("scope")
	if !discoveryID(id) || !uuidPattern.MatchString(device) || !discoveryID(scope) {
		return bad("An environment, device and scope are required.")
	}
	limit, cursor, err := discoveryPage(r)
	if err != nil {
		return err
	}
	afterKind, afterID := "", ""
	if len(cursor) > 0 {
		if len(cursor) != 2 || (cursor[0] != "identification" && cursor[0] != "communication") || !discoveryID(cursor[1]) {
			return bad("Invalid environment evidence cursor.")
		}
		afterKind, afterID = cursor[0], cursor[1]
	}
	var exists bool
	if err := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM discovery_entities WHERE organization_id=$1 AND device_id=$2 AND scope=$3 AND id=$4 AND expires_at>now())`, s.OrganizationID, device, scope, id).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return apiError{404, "not_found", "Environment not found."}
	}
	rows, err := tx.Query(r.Context(), `WITH proofs AS (
 SELECT 'identification' kind,signature_id id,application_id,state,'' provider,evidence,last_seen
 FROM discovery_identifications WHERE organization_id=$1 AND device_id=$2 AND scope=$3 AND entity_id=$4 AND expires_at>now()
 UNION ALL
 SELECT 'communication',provider,'','',provider,evidence,last_seen
 FROM discovery_communications WHERE organization_id=$1 AND device_id=$2 AND scope=$3 AND entity_id=$4 AND expires_at>now()
 ) SELECT kind,id,application_id,state,provider,evidence,last_seen FROM proofs
 WHERE (kind,id)>($5,$6) ORDER BY kind,id LIMIT $7`, s.OrganizationID, device, scope, id, afterKind, afterID, limit+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var kind, proofID, application, state, provider string
		var evidence json.RawMessage
		var seen any
		if err := rows.Scan(&kind, &proofID, &application, &state, &provider, &evidence, &seen); err != nil {
			return err
		}
		items = append(items, map[string]any{"kind": kind, "id": proofID, "application_id": application, "state": state, "provider": provider, "evidence": evidence, "last_seen": seen})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1]
		next = discoveryCursor(last["kind"].(string), last["id"].(string))
	}
	reply(w, 200, map[string]any{"items": items, "next_cursor": next})
	return nil
}
