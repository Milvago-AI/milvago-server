package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"slices"

	"github.com/jackc/pgx/v5"
)

func guardLegacyDLPWrite(ctx context.Context, tx pgx.Tx, target string, old, next ShadowConfig) error {
	before, _ := canonicalDLPJSON(dlpJSON(map[string]any{"protection": old.Protection, "privacy": old.Privacy}))
	after, _ := canonicalDLPJSON(dlpJSON(map[string]any{"protection": next.Protection, "privacy": next.Privacy}))
	if bytes.Equal(before, after) {
		return nil
	}
	var managed bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM dlp_settings WHERE domain='endpoint' AND (scope_kind='organization' OR scope_id=$1::uuid))`, target).Scan(&managed); err != nil {
		return err
	}
	if managed {
		return apiError{409, "dlp_moved", "Manage protection and masking in Administration / Data Loss Prevention. Reload this editor before saving."}
	}
	return nil
}

func (a *App) projectLegacyDLP(r *http.Request, tx pgx.Tx, org, device string, config map[string]json.RawMessage, shadow ShadowSettings) (int64, error) {
	settings, err := a.readDLP(r.Context(), tx, org, "endpoint", "device", device, 0)
	if err != nil {
		return 0, err
	}
	if !hasActiveDLPPrevention(settings.Policy) && !hasActiveDLPPrevention(migrateLegacyDLP(shadow.Config)) {
		return shadow.Revision, nil
	}
	// The exact migration needs no downgrade: existing devices keep their legacy
	// behavior until an administrator changes the dedicated DLP configuration.
	if sameDLPEnforcement(settings.Policy, migrateLegacyDLP(shadow.Config)) {
		return shadow.Revision, nil
	}
	revision, err := a.enrichDLPPolicy(r, tx, org, device, config, shadow.Revision)
	if err != nil {
		return 0, err
	}
	for _, key := range []string{"dlp", "dlp_fingerprint", "dlp_context", "dlp_legacy_disabled"} {
		delete(config, key)
	}
	protection := shadow.Config.Protection
	protection.BlockUploads = false
	protection.Keywords = []string{}
	privacy := shadow.Config.Privacy
	privacy.Enabled = false
	config["protection"] = dlpJSON(protection)
	config["privacy"] = dlpJSON(privacy)
	var group *string
	if err = tx.QueryRow(r.Context(), `SELECT group_id FROM devices WHERE id=$1`, device).Scan(&group); err != nil {
		return 0, err
	}
	relevant := dlpPolicyForDevice(settings.Policy, device, group)
	if relevant.Inspection && slices.ContainsFunc(relevant.Rules, func(rule DLPRule) bool {
		var effect struct {
			Action string `json:"action"`
		}
		_ = json.Unmarshal(rule.Consequence, &effect)
		return rule.Mode == "active" && effect.Action != "observe"
	}) {
		services := append([]ServiceConfig{}, shadow.Config.Services...)
		for i := range services {
			if services[i].Enabled {
				services[i].Mode = "block"
				services[i].RedirectURL = ""
			}
		}
		config["services"] = dlpJSON(services)
		if err = closeUnqualifiedNativeDLP(config); err != nil {
			return 0, err
		}
		protection.Message = "Update the Milvago agent and browser extension to apply the organization's DLP rules."
		config["protection"] = dlpJSON(protection)
	}
	return revision, nil
}

func hasActiveDLPPrevention(policy DLPPolicy) bool {
	if !policy.Inspection {
		return false
	}
	for _, rule := range policy.Rules {
		if rule.Mode != "active" {
			continue
		}
		var effect struct{ Action string }
		if json.Unmarshal(rule.Consequence, &effect) != nil || effect.Action != "observe" {
			return true
		}
	}
	return false
}
