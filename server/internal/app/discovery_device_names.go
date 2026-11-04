package app

import (
	"net/http"

	"github.com/jackc/pgx/v5"
)

// Reuse the existing inventory projection; discovery must not invent another
// decryption or identity-reveal path. Only bounded detail pages call this helper.
func (a *App) discoveryDeviceNames(r *http.Request, tx pgx.Tx, s *Session, items []map[string]any) error {
	if err := discoveryDetails(r, s); err != nil {
		return err
	}
	ids := []string{}
	seen := map[string]bool{}
	for _, item := range items {
		id, _ := item["device_id"].(string)
		if uuidPattern.MatchString(id) && !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}
	if len(ids) == 0 {
		return nil
	}
	if len(ids) > 100 {
		return bad("Device name page exceeds its limit.")
	}
	rows, err := tx.Query(r.Context(), `SELECT id::text,hostname_ciphertext,platform FROM devices WHERE organization_id=$1 AND id=ANY($2::uuid[])`, s.OrganizationID, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	names := map[string]string{}
	platforms := map[string]string{}
	for rows.Next() {
		var id, cipher, platform string
		if err = rows.Scan(&id, &cipher, &platform); err != nil {
			return err
		}
		name, err := a.machineName(r, s.OrganizationID, id, cipher)
		if err != nil {
			return err
		}
		if name == "" {
			name = deviceAlias(id)
		}
		names[id] = name
		platforms[id] = platform
	}
	if err = rows.Err(); err != nil {
		return err
	}
	for _, item := range items {
		if id, ok := item["device_id"].(string); ok {
			item["device_name"] = names[id]
			item["device_platform"] = platforms[id]
		}
	}
	return nil
}
