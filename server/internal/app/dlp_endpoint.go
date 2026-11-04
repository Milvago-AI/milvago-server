package app

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

func (a *App) v4Policy(w http.ResponseWriter, r *http.Request) {
	if err := a.versionedPolicyRequest(w, r, 4); err != nil {
		a.fail(w, err)
	}
}

func (a *App) enrichDLPPolicy(r *http.Request, tx pgx.Tx, org, device string, config map[string]json.RawMessage, legacyRevision int64) (int64, error) {
	settings, err := a.readDLP(r.Context(), tx, org, "endpoint", "device", device, 0)
	if err != nil {
		return 0, err
	}
	if err = dlpEngine(r.Context(), map[string]any{"op": "validate", "policy": settings.Policy}, nil); err != nil {
		return 0, err
	}
	var legacy ShadowConfig
	rawConfig, _ := json.Marshal(config)
	if json.Unmarshal(rawConfig, &legacy) != nil {
		return 0, bad("Invalid endpoint policy.")
	}
	var group *string
	if err = tx.QueryRow(r.Context(), `SELECT group_id FROM devices WHERE id=$1`, device).Scan(&group); err != nil {
		return 0, err
	}
	if !sameDLPEnforcement(settings.Policy, migrateLegacyDLP(legacy)) {
		required, e := requiresNativeDLPSupport(r.Context(), dlpPolicyForDevice(settings.Policy, device, group))
		if e != nil {
			return 0, e
		}
		if required {
			var caps []string
			if err = tx.QueryRow(r.Context(), `SELECT capabilities FROM devices WHERE id=$1`, device).Scan(&caps); err != nil {
				return 0, err
			}
			if !validNativeCapability(caps) {
				if err = closeUnqualifiedNativeDLP(config); err != nil {
					return 0, err
				}
			}
		}
	}
	var deliveryCaps []string
	if err = tx.QueryRow(r.Context(), `SELECT capabilities FROM devices WHERE id=$1`, device).Scan(&deliveryCaps); err != nil {
		return 0, err
	}
	settings = dlpDeliverySettings(settings, deliveryCaps)
	config["dlp"] = dlpJSON(settings.Policy)
	config["dlp_fingerprint"] = dlpJSON(settings.Fingerprint)
	config["dlp_legacy_disabled"] = dlpJSON(true)

	facts := map[string]string{"device_id": device, "organization_id": org}
	if group != nil {
		facts["group_id"] = *group
	} else {
		facts["group_id"] = "none"
	}
	config["dlp_context"] = dlpJSON(facts)
	raw, _ := json.Marshal(config)
	canonical, err := canonicalDLPJSON(raw)
	if err != nil {
		return 0, err
	}
	digest := dlpDocumentFingerprint(canonical)
	var revision int64
	err = tx.QueryRow(r.Context(), `INSERT INTO dlp_device_policy_versions(organization_id,device_id,fingerprint,revision) VALUES($1,$2,$3,GREATEST(nextval('dlp_policy_revision'),$4+1)) ON CONFLICT(organization_id,device_id) DO UPDATE SET fingerprint=excluded.fingerprint,revision=CASE WHEN dlp_device_policy_versions.fingerprint=excluded.fingerprint THEN dlp_device_policy_versions.revision ELSE GREATEST(nextval('dlp_policy_revision'),dlp_device_policy_versions.revision+1,$4+1) END RETURNING revision`, org, device, digest, legacyRevision).Scan(&revision)
	if err != nil {
		return 0, err
	}
	err = ensureDLPSnapshot(r.Context(), tx, org, settings.Policy)
	if err != nil {
		return 0, err
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO dlp_device_policy_history(organization_id,device_id,fingerprint,revision) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, org, device, settings.Fingerprint, revision)
	return revision, err
}

func dlpDocumentFingerprint(document []byte) string {
	// Reuse the canonical document hash, without retaining any transient content.
	return dlpBytesFingerprint(document)
}

func (a *App) dlpEnforcement(w http.ResponseWriter, r *http.Request) {
	if err := a.dlpEnforcementRequest(w, r); err != nil {
		a.fail(w, err)
	}
}
func (a *App) dlpEnforcementRequest(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Fingerprint string `json:"fingerprint"`
		Channel     string `json:"channel"`
		Tool        string `json:"tool"`
		Mechanism   string `json:"mechanism"`
		Status      string `json:"status"`
	}
	if err := decode(w, r, &body); err != nil {
		return err
	}
	if !validDLPFingerprint(body.Fingerprint) || !slices.Contains([]string{"browser", "native"}, body.Channel) || !slices.Contains([]string{"applied", "unavailable"}, body.Status) {
		return bad("Invalid DLP enforcement report.")
	}
	if body.Channel == "browser" {
		if !slices.Contains(browserTools, body.Tool) || !slices.Contains([]string{"browser-engine", "browser-request"}, body.Mechanism) {
			return bad("Invalid browser DLP component.")
		}
	} else if !slices.Contains(nativeEventTools, body.Tool) || !slices.Contains([]string{"local-proxy", "cli-hook", "native-engine"}, body.Mechanism) {
		return bad("Invalid native DLP component.")
	}
	if body.Channel == "native" && Edition != "commercial" {
		return forbidden()
	}
	tx, org, id, err := a.deviceTx(r)
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	var caps []string
	if err = tx.QueryRow(r.Context(), `SELECT capabilities FROM devices WHERE id=$1`, id).Scan(&caps); err != nil {
		return err
	}
	if !slices.Contains(caps, "dlp-v1") {
		return apiError{409, "dlp_update_required", "This agent has not advertised DLP support."}
	}
	settings, err := a.readDLP(r.Context(), tx, org, "endpoint", "device", id, 0)
	if err != nil {
		return err
	}
	if body.Fingerprint != dlpDeliverySettings(settings, caps).Fingerprint {
		return apiError{409, "revision_conflict", "Refresh the DLP policy before reporting enforcement."}
	}
	if _, err = tx.Exec(r.Context(), `INSERT INTO dlp_enforcement(organization_id,device_id,channel,tool,mechanism,fingerprint,status) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(organization_id,device_id,channel,tool,mechanism) DO UPDATE SET fingerprint=excluded.fingerprint,status=excluded.status,reported_at=clock_timestamp()`, org, id, body.Channel, body.Tool, body.Mechanism, body.Fingerprint, body.Status); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	reply(w, 200, map[string]bool{"ok": true})
	return nil
}

func validDLPFingerprint(value string) bool {
	return len(value) == 64 && strings.IndexFunc(value, func(c rune) bool { return !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') }) < 0
}
