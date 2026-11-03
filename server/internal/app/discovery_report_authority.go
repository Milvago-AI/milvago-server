package app

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"
)

type discoveryReportAuthority struct {
	tx           pgx.Tx
	organization string
	device       string
	catalog      json.RawMessage
}

// Each call takes fresh transaction-scoped authority locks. The caller owns the
// successful transaction; an unsuccessful call never hands one off.
func (a *App) lockDiscoveryReportAuthority(r *http.Request, report discoveryReport) (_ *discoveryReportAuthority, err error) {
	tx, org, device, err := a.deviceTx(r)
	if err != nil {
		return nil, err
	}
	handedOff := false
	defer func() {
		if !handedOff {
			if rollbackErr := tx.Rollback(r.Context()); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
				err = errors.Join(err, rollbackErr)
			}
		}
	}()
	// One device cannot race several scopes to bypass per-device storage admission.
	if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtextextended($1,713905))`, org+"/"+device); err != nil {
		return nil, err
	}
	var settingsRaw []byte
	var settingsRevision int64
	err = tx.QueryRow(r.Context(), `SELECT revision,configuration FROM discovery_settings WHERE organization_id=$1 FOR SHARE`, org).Scan(&settingsRevision, &settingsRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apiError{409, "discovery_disabled", "Discovery is disabled."}
	}
	if err != nil {
		return nil, err
	}
	var configuration DiscoverySettings
	if json.Unmarshal(settingsRaw, &configuration) != nil {
		return nil, errors.New("invalid stored discovery settings")
	}
	catalog, err := currentDiscoveryCatalog(r.Context(), tx, org)
	if err != nil {
		return nil, err
	}
	configuration, fingerprint, err := a.effectiveDiscovery(r.Context(), tx, org, device, settingsRevision, configuration, catalog)
	if err != nil {
		return nil, err
	}
	var deliveredRevision int64
	var deliveredFingerprint string
	if err = tx.QueryRow(r.Context(), `SELECT revision,fingerprint FROM discovery_device_authorizations WHERE organization_id=$1 AND device_id=$2 FOR SHARE`, org, device).Scan(&deliveredRevision, &deliveredFingerprint); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiError{409, "revision_conflict", "Refresh discovery authorization."}
		}
		return nil, err
	}
	if deliveredRevision != report.SettingsRevision || deliveredFingerprint != fingerprint {
		return nil, apiError{409, "revision_conflict", "Refresh discovery authorization."}
	}
	if !configuration.Host && !configuration.Containers && !configuration.VirtualMachines && !configuration.Network {
		return nil, apiError{409, "discovery_disabled", "Discovery is disabled."}
	}
	if !discoveryGuestHTTPReportAllowed(report, configuration) {
		return nil, forbidden()
	}
	for _, match := range report.Result.Identifications {
		for _, evidence := range match.Evidence {
			if !discoverySourceAllowed(evidence.Source, configuration) {
				return nil, forbidden()
			}
		}
	}
	for _, communication := range report.Result.Communications {
		if !discoverySourceAllowed(communication.Evidence.Source, configuration) {
			return nil, forbidden()
		}
	}
	for _, query := range report.Result.Queries {
		if !discoverySourceAllowed(query.Evidence.Source, configuration) {
			return nil, forbidden()
		}
	}
	for _, entity := range report.Entities {
		if entity.Kind == "vm" || entity.Kind == "wsl" {
			if !configuration.VirtualMachines {
				return nil, forbidden()
			}
		}
		if entity.Kind == "container" || entity.Kind == "runtime" {
			if !configuration.Containers {
				return nil, forbidden()
			}
		}
	}
	if report.Scope == "server" {
		return nil, bad("Reserved discovery scope.")
	}
	for _, coverage := range report.Coverage {
		if coverage.Scope == "server" {
			return nil, bad("Reserved discovery coverage scope.")
		}
	}
	if report.RunID != nil {
		if !uuidPattern.MatchString(*report.RunID) {
			return nil, bad("Invalid discovery run.")
		}
		var active bool
		if err = tx.QueryRow(r.Context(), `SELECT true FROM discovery_runs WHERE organization_id=$1 AND device_id=$2 AND id=$3 AND status IN ('pending','running') AND expires_at>now() FOR SHARE`, org, device, *report.RunID).Scan(&active); errors.Is(err, pgx.ErrNoRows) {
			return nil, apiError{409, "run_not_active", "This collection is no longer active."}
		} else if err != nil {
			return nil, err
		}
	}
	handedOff = true
	return &discoveryReportAuthority{tx: tx, organization: org, device: device, catalog: catalog}, nil
}
