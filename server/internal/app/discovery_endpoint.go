package app

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

type discoveryEvidence struct {
	FactID     string   `json:"fact_id"`
	Source     string   `json:"source"`
	ObservedAt int64    `json:"observed_at"`
	Fields     []string `json:"fields"`
}
type discoveryMatch struct {
	ApplicationID     string              `json:"application_id"`
	SignatureID       string              `json:"signature_id"`
	SignatureRevision uint32              `json:"signature_revision"`
	EntityID          string              `json:"entity_id"`
	State             string              `json:"state"`
	Evidence          []discoveryEvidence `json:"evidence"`
}
type discoveryDomainQuery struct {
	EntityID string            `json:"entity_id"`
	Provider string            `json:"provider"`
	Evidence discoveryEvidence `json:"evidence"`
}

type discoveryReport struct {
	Version          int     `json:"version"`
	CatalogRevision  int64   `json:"catalog_revision"`
	SettingsRevision int64   `json:"settings_revision"`
	RunID            *string `json:"run_id"`
	Scope            string  `json:"scope"`
	Sequence         int64   `json:"sequence"`
	Page             int     `json:"page"`
	Pages            int     `json:"pages"`
	ObservedAt       int64   `json:"observed_at"`
	Complete         bool    `json:"complete"`
	Entities         []struct {
		ID      string          `json:"id"`
		Kind    string          `json:"kind"`
		Display json.RawMessage `json:"display,omitempty"`
	} `json:"entities"`
	Relations []struct {
		From   string `json:"from"`
		To     string `json:"to"`
		Kind   string `json:"kind"`
		Source string `json:"source"`
	} `json:"relations"`
	Coverage []struct {
		Scope     string `json:"scope"`
		Adapter   string `json:"adapter"`
		Status    string `json:"status"`
		CheckedAt int64  `json:"checked_at"`
		Complete  bool   `json:"complete"`
	} `json:"coverage"`
	Result struct {
		Identifications []discoveryMatch `json:"identifications"`
		Communications  []struct {
			EntityID string            `json:"entity_id"`
			Provider string            `json:"provider"`
			Evidence discoveryEvidence `json:"evidence"`
		} `json:"communications"`
		Queries           []discoveryDomainQuery `json:"queries,omitempty"`
		EvaluatedFacts    int                    `json:"evaluated_facts"`
		UnknownConditions int                    `json:"unknown_conditions"`
	} `json:"result"`
}

func (a *App) deviceDiscoveryPolicy(w http.ResponseWriter, r *http.Request) {
	if err := a.deviceDiscoveryPolicyRequest(w, r); err != nil {
		a.fail(w, err)
	}
}
func (a *App) deviceDiscoveryPolicyRequest(w http.ResponseWriter, r *http.Request) error {
	tx, org, device, err := a.deviceTx(r)
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	revision, configuration, err := readDiscoverySettings(r.Context(), tx, org)
	if err != nil {
		return err
	}
	catalog, err := currentDiscoveryCatalog(r.Context(), tx, org)
	if err != nil {
		return err
	}
	configuration, fingerprint, err := a.effectiveDiscovery(r.Context(), tx, org, device, revision, configuration, catalog)
	if err != nil {
		return err
	}
	revision, err = discoveryDeliveryRevision(r.Context(), tx, org, device, fingerprint)
	if err != nil {
		return err
	}
	if !configuration.Host && !configuration.Containers && !configuration.VirtualMachines && !configuration.Network {
		if _, err = tx.Exec(r.Context(), `INSERT INTO discovery_coverage(organization_id,device_id,scope,adapter,status,complete,checked_at,sequence,expires_at) VALUES($1,$2,'endpoint','discovery-policy','disabled',false,now(),$3,now()+interval '10 minutes') ON CONFLICT(organization_id,device_id,scope,adapter) DO UPDATE SET status='disabled',checked_at=now(),sequence=excluded.sequence,expires_at=excluded.expires_at`, org, device, revision); err != nil {
			return err
		}
	} else if _, err = tx.Exec(r.Context(), `DELETE FROM discovery_coverage WHERE organization_id=$1 AND device_id=$2 AND scope='endpoint' AND adapter='discovery-policy'`, org, device); err != nil {
		return err
	}
	rows, err := tx.Query(r.Context(), `SELECT id::text FROM discovery_runs WHERE organization_id=$1 AND device_id=$2 AND status IN ('pending','running') AND expires_at>now() ORDER BY created_at LIMIT 1`, org, device)
	if err != nil {
		return err
	}
	runs := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		runs = append(runs, id)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	for _, id := range runs {
		if _, err = tx.Exec(r.Context(), `UPDATE discovery_runs SET status='running' WHERE organization_id=$1 AND id=$2 AND status='pending'`, org, id); err != nil {
			return err
		}
	}
	now := time.Now().UTC()
	payload, _ := json.Marshal(map[string]any{"kind": "discovery_policy", "version": 1, "device_id": device, "revision": revision, "issued_at": now, "expires_at": now.Add(10 * time.Minute), "configuration": configuration, "catalog": catalog, "runs": runs})
	signature := ed25519.Sign(a.policyKey(org), payload)
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	reply(w, 200, map[string]string{"payload": base64.StdEncoding.EncodeToString(payload), "signature": base64.StdEncoding.EncodeToString(signature)})
	return nil
}
func discoverySourceAllowed(source string, c DiscoverySettings) bool {
	switch source {
	case "installation", "host_process":
		return c.Host
	case "guest_process":
		return c.VirtualMachines && c.GuestRead
	case "container_process", "container_metadata":
		return c.Containers
	case "http":
		return c.HTTP
	case "host_flow", "vm_flow", "runtime_flow", "container_flow", "host_dns_query":
		return c.Network
	}
	return false
}

func discoveryGuestHTTPReportAllowed(report discoveryReport, c DiscoverySettings) bool {
	// HTTP inside a guest runs a fixed probe through the separately authorized
	// guest channel. HTTP recognition alone must not admit that channel's data.
	allowed := c.VirtualMachines && c.GuestRead && c.GuestExecute && c.HTTP
	for _, relation := range report.Relations {
		if relation.Source == "guest-channel-http-connection" && !allowed {
			return false
		}
	}
	for _, coverage := range report.Coverage {
		if coverage.Adapter == "guest-http" && !allowed {
			return false
		}
	}
	return true
}

func (a *App) ingestDiscoveryReport(w http.ResponseWriter, r *http.Request) {
	if err := a.ingestDiscoveryReportRequest(w, r); err != nil {
		a.fail(w, err)
	}
}
func (a *App) ingestDiscoveryReportRequest(w http.ResponseWriter, r *http.Request) error {
	if r.Header.Get("Content-Type") != "application/json" {
		return apiError{415, "unsupported_media_type", "Use application/json."}
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 128<<10+1))
	if err != nil || len(raw) > 128<<10 {
		return bad("Discovery report exceeds its limit.")
	}
	var report discoveryReport
	if err = decodeDiscoveryRaw(raw, &report); err != nil {
		return err
	}
	tx, org, device, err := a.deviceTx(r)
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	// One device cannot race several scopes to bypass per-device storage admission.
	if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtextextended($1,713905))`, org+"/"+device); err != nil {
		return err
	}
	var settingsRaw []byte
	var settingsRevision int64
	err = tx.QueryRow(r.Context(), `SELECT revision,configuration FROM discovery_settings WHERE organization_id=$1 FOR SHARE`, org).Scan(&settingsRevision, &settingsRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return apiError{409, "discovery_disabled", "Discovery is disabled."}
	}
	if err != nil {
		return err
	}
	var configuration DiscoverySettings
	if json.Unmarshal(settingsRaw, &configuration) != nil {
		return errors.New("invalid stored discovery settings")
	}
	catalog, err := currentDiscoveryCatalog(r.Context(), tx, org)
	if err != nil {
		return err
	}
	configuration, fingerprint, err := a.effectiveDiscovery(r.Context(), tx, org, device, settingsRevision, configuration, catalog)
	if err != nil {
		return err
	}
	var deliveredRevision int64
	var deliveredFingerprint string
	if err = tx.QueryRow(r.Context(), `SELECT revision,fingerprint FROM discovery_device_authorizations WHERE organization_id=$1 AND device_id=$2 FOR SHARE`, org, device).Scan(&deliveredRevision, &deliveredFingerprint); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return apiError{409, "revision_conflict", "Refresh discovery authorization."}
		}
		return err
	}
	if deliveredRevision != report.SettingsRevision || deliveredFingerprint != fingerprint {
		return apiError{409, "revision_conflict", "Refresh discovery authorization."}
	}
	if !configuration.Host && !configuration.Containers && !configuration.VirtualMachines && !configuration.Network {
		return apiError{409, "discovery_disabled", "Discovery is disabled."}
	}
	if !discoveryGuestHTTPReportAllowed(report, configuration) {
		return forbidden()
	}
	for _, match := range report.Result.Identifications {
		for _, evidence := range match.Evidence {
			if !discoverySourceAllowed(evidence.Source, configuration) {
				return forbidden()
			}
		}
	}
	for _, communication := range report.Result.Communications {
		if !discoverySourceAllowed(communication.Evidence.Source, configuration) {
			return forbidden()
		}
	}
	for _, query := range report.Result.Queries {
		if !discoverySourceAllowed(query.Evidence.Source, configuration) {
			return forbidden()
		}
	}
	for _, entity := range report.Entities {
		if entity.Kind == "vm" || entity.Kind == "wsl" {
			if !configuration.VirtualMachines {
				return forbidden()
			}
		}
		if entity.Kind == "container" || entity.Kind == "runtime" {
			if !configuration.Containers {
				return forbidden()
			}
		}
	}
	if report.Scope == "server" {
		return bad("Reserved discovery scope.")
	}
	for _, coverage := range report.Coverage {
		if coverage.Scope == "server" {
			return bad("Reserved discovery coverage scope.")
		}
	}
	if report.RunID != nil {
		if !uuidPattern.MatchString(*report.RunID) {
			return bad("Invalid discovery run.")
		}
		var active bool
		if err = tx.QueryRow(r.Context(), `SELECT true FROM discovery_runs WHERE organization_id=$1 AND device_id=$2 AND id=$3 AND status IN ('pending','running') AND expires_at>now() FOR SHARE`, org, device, *report.RunID).Scan(&active); errors.Is(err, pgx.ErrNoRows) {
			return apiError{409, "run_not_active", "This collection is no longer active."}
		} else if err != nil {
			return err
		}
	}
	if err = a.validateDiscoveryReport(r.Context(), org, catalog, json.RawMessage(raw)); err != nil {
		return err
	}
	now := time.Now().Unix()
	if report.Sequence <= 0 || report.ObservedAt < now-48*3600 || report.ObservedAt > now+60 {
		return bad("Discovery timestamp or sequence is invalid.")
	}
	if _, err = tx.Exec(r.Context(), `SAVEPOINT discovery_page`); err != nil {
		return err
	}
	var scopes int
	if err = tx.QueryRow(r.Context(), `SELECT count(*) FROM discovery_scans WHERE organization_id=$1 AND device_id=$2 AND scope<>$3`, org, device, report.Scope).Scan(&scopes); err != nil {
		return err
	}
	if scopes >= 32 {
		return rejectDiscoveryCapacity(r, tx, org, device, report.Sequence)
	}
	if _, err = tx.Exec(r.Context(), `INSERT INTO discovery_scans(organization_id,device_id,scope,sequence,pages,observed_at,complete) VALUES($1,$2,$3,$4,$5,to_timestamp($6),$7) ON CONFLICT DO NOTHING`, org, device, report.Scope, report.Sequence, report.Pages, report.ObservedAt, report.Complete); err != nil {
		return err
	}
	var sequence int64
	var pages int
	var observed time.Time
	var complete bool
	var hashes map[string]string
	if err = tx.QueryRow(r.Context(), `SELECT sequence,pages,observed_at,complete,page_hashes FROM discovery_scans WHERE organization_id=$1 AND device_id=$2 AND scope=$3 FOR UPDATE`, org, device, report.Scope).Scan(&sequence, &pages, &observed, &complete, &hashes); err != nil {
		return err
	}
	if sequence > report.Sequence {
		return apiError{409, "stale_snapshot", "A newer discovery snapshot already exists."}
	}
	if sequence < report.Sequence {
		if _, err = tx.Exec(r.Context(), `UPDATE discovery_scans SET sequence=$4,pages=$5,observed_at=to_timestamp($6),complete=$7,received_pages='{}',page_hashes='{}',finalized=false,updated_at=now() WHERE organization_id=$1 AND device_id=$2 AND scope=$3`, org, device, report.Scope, report.Sequence, report.Pages, report.ObservedAt, report.Complete); err != nil {
			return err
		}
		hashes = map[string]string{}
	} else if pages != report.Pages || observed.Unix() != report.ObservedAt || complete != report.Complete {
		return apiError{409, "snapshot_conflict", "Discovery snapshot metadata changed."}
	}
	digest := sha256.Sum256(raw)
	hash := hex.EncodeToString(digest[:])
	page := strconv.Itoa(report.Page)
	if previous, ok := hashes[page]; ok {
		if previous != hash {
			return apiError{409, "snapshot_conflict", "Discovery page changed during retry."}
		}
		reply(w, 200, map[string]bool{"ok": true, "duplicate": true})
		return nil
	}
	if err = a.storeDiscoveryReport(r, tx, org, device, &report); err != nil {
		var capacity apiError
		if errors.As(err, &capacity) && capacity.code == "discovery_capacity" {
			return rejectDiscoveryCapacity(r, tx, org, device, report.Sequence)
		}
		return err
	}
	hashes[page] = hash
	hashesRaw, _ := json.Marshal(hashes)
	if _, err = tx.Exec(r.Context(), `UPDATE discovery_scans SET received_pages=array_append(received_pages,$4),page_hashes=$5,updated_at=now(),finalized=cardinality(received_pages)+1=pages WHERE organization_id=$1 AND device_id=$2 AND scope=$3`, org, device, report.Scope, report.Page, hashesRaw); err != nil {
		return err
	}
	if len(hashes) == report.Pages {
		if !report.Complete {
			if err = reconcileDiscoveryProcessSources(r, tx, org, device, &report); err != nil {
				return err
			}
		}
		if report.Complete {
			for _, table := range []string{"discovery_identifications", "discovery_relations", "discovery_communications"} {
				if _, err = tx.Exec(r.Context(), `DELETE FROM `+table+` WHERE organization_id=$1 AND device_id=$2 AND scope=$3 AND sequence<$4`, org, device, report.Scope, report.Sequence); err != nil {
					return err
				}
			}
			if _, err = tx.Exec(r.Context(), `DELETE FROM discovery_entities WHERE organization_id=$1 AND device_id=$2 AND scope=$3 AND sequence<$4`, org, device, report.Scope, report.Sequence); err != nil {
				return err
			}
		}
		if report.RunID != nil {
			if _, err = tx.Exec(r.Context(), `UPDATE discovery_runs SET status='completed' WHERE organization_id=$1 AND device_id=$2 AND id=$3 AND status='running'`, org, device, *report.RunID); err != nil {
				return err
			}
		}
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	reply(w, 200, map[string]bool{"ok": true})
	return nil
}
