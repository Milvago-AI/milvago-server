package app

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
)

func (a *App) discoverySystemBinding(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if err := discoveryDetails(r, s); err != nil {
		return err
	}
	if !hasPermission(s.Permissions, permDiscoveryManage) {
		return forbidden()
	}
	device := strings.ToLower(r.PathValue("id"))
	if !uuidPattern.MatchString(device) {
		return bad("A device identifier is required.")
	}
	var platform string
	if err := tx.QueryRow(r.Context(), `SELECT platform FROM devices WHERE organization_id=$1 AND id=$2 AND status='approved'`, s.OrganizationID, device).Scan(&platform); err != nil {
		if err == pgx.ErrNoRows {
			return apiError{404, "not_found", "Device not found."}
		}
		return err
	}
	if platform != "linux" && platform != "windows" {
		return apiError{409, "system_binding_unavailable", "This binding is available for Linux and Windows endpoints only."}
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="milvago-`+platform+`-binding.json"`)
	// Public trust material only. The local administrator's protected profile
	// supplies the OS account; exporting this file neither collects nor opts in.
	reply(w, 200, map[string]any{"version": 1, "device_id": device, "server_url": a.publicOriginIn(r.Context(), tx),
		"public_key": base64.StdEncoding.EncodeToString(a.policyKey(s.OrganizationID).Public().(ed25519.PublicKey))})
	return nil
}
