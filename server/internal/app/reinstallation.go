package app

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
)

type reinstallationRequest struct {
	DeviceID   string `json:"device_id"`
	Credential string `json:"credential"`
	Nonce      string `json:"nonce"`
}

func (a *App) registerReinstallationRoute() {
	a.mux.HandleFunc("POST /v2/install/reinstallation", func(w http.ResponseWriter, r *http.Request) {
		if err := a.confirmReinstallation(w, r); err != nil {
			a.fail(w, err)
		}
	})
}

// A current organization deployment key authorizes this check, not an expired
// device credential. It does not create devices or override an existing revocation.
// Signed, nonce-bound responses prevent an HTTP error or replay becoming a reset.
func (a *App) confirmReinstallation(w http.ResponseWriter, r *http.Request) error {
	if err := a.checkPublicRequest(r, "reinstallation", 300, 1200); err != nil {
		return err
	}
	bearer := r.Header.Get("Authorization")
	if !strings.HasPrefix(bearer, "Bearer ") || len(bearer) != 50 {
		return installerUnavailable()
	}
	token := strings.TrimPrefix(bearer, "Bearer ")
	var body reinstallationRequest
	if err := decode(w, r, &body); err != nil {
		return err
	}
	credential, err := base64.RawURLEncoding.DecodeString(body.Credential)
	if err != nil || len(credential) != 32 || len(body.Credential) != 43 ||
		!uuidPattern.MatchString(body.DeviceID) || !uuidPattern.MatchString(body.Nonce) {
		return bad("Invalid reinstallation identity.")
	}
	var org string
	err = a.db.QueryRow(r.Context(), `SELECT organization_id FROM installer_identity($1)`, hash(token)).Scan(&org)
	if err == pgx.ErrNoRows {
		return installerUnavailable()
	}
	if err != nil {
		return err
	}
	// Spent only once the key is known, so invented keys cannot fill the window.
	if err := a.checkIngestRate(r.Context(), "reinstallation:"+string(hash(token)), 300); err != nil {
		return err
	}
	tx, err := tenantTx(r.Context(), a.db, org)
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	var keyID string
	err = tx.QueryRow(r.Context(), `SELECT id FROM installer_profiles WHERE organization_id=$1 AND secret_hash=$2 AND platform IS NULL AND NOT revoked AND expires_at>now() AND edition=$3 FOR SHARE`, org, hash(token), Edition).Scan(&keyID)
	if err == pgx.ErrNoRows {
		return installerUnavailable()
	}
	if err != nil {
		return err
	}
	var status string
	var digest []byte
	err = tx.QueryRow(r.Context(), `SELECT status,credential_hash FROM devices WHERE organization_id=$1 AND id=$2 FOR SHARE`, org, body.DeviceID).Scan(&status, &digest)
	if err == pgx.ErrNoRows {
		status = "deleted"
	} else if err != nil {
		return err
	} else {
		if !equal(string(hash(body.Credential)), string(digest)) {
			return installerUnavailable()
		}
		switch status {
		case "approved", "pending":
			status = "present"
		case "revoked":
		default:
			return installerUnavailable()
		}
	}
	payload, err := json.Marshal(map[string]string{
		"purpose": "milvago/reinstallation/v1", "device_id": body.DeviceID,
		"nonce": body.Nonce, "status": status,
	})
	if err != nil {
		return err
	}
	signature := ed25519.Sign(a.policyKey(org), payload)
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	reply(w, 200, map[string]string{"payload": base64.StdEncoding.EncodeToString(payload), "signature": base64.StdEncoding.EncodeToString(signature)})
	return nil
}
