package app

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	permDiscoveryRead          = "discovery.read"
	permDiscoveryManage        = "discovery.manage"
	permDiscoveryCatalogManage = "discovery.catalog.manage"
	permDiscoveryRun           = "discovery.run"
)

//go:embed discovery_migration.sql
var discoveryMigration string

//go:embed discovery_factory.json
var discoveryFactory json.RawMessage

func initializeDiscovery(ctx context.Context, tx pgx.Tx, role string) error {
	if _, err := tx.Exec(ctx, aiGovernanceMigration); err != nil {
		return fmt.Errorf("AI governance migration: %w", err)
	}
	if _, err := tx.Exec(ctx, discoveryMigration); err != nil {
		return fmt.Errorf("discovery migration: %w", err)
	}
	_, err := tx.Exec(ctx, `GRANT SELECT,INSERT,UPDATE,DELETE ON ai_governance_registry,ai_governance_policies,ai_governance_exceptions,discovery_settings,discovery_catalogs,discovery_scans,discovery_device_authorizations,discovery_entities,discovery_identifications,discovery_relations,discovery_coverage,discovery_events,discovery_communications,discovery_reviews,discovery_runs TO `+role)
	return err
}

func (a *App) registerDiscoveryRoutes() {
	a.registerAIGovernanceRoutes()
	// The handler independently gates each inventory source.
	a.console("GET /api/discovery/inventory", "", a.inventorySearch)
	a.console("GET /api/discovery/summary", permReportsAggregate, a.discoverySummary)
	a.console("GET /api/discovery/applications", permDiscoveryRead, a.discoveryApplications)
	a.console("GET /api/discovery/applications/{id}", permDiscoveryRead, a.discoveryApplication)
	a.console("GET /api/discovery/applications/{id}/instances", permDiscoveryRead, a.discoveryInstances)
	a.console("GET /api/discovery/applications/{id}/locations", permDiscoveryRead, a.discoveryLocations)
	a.console("PUT /api/discovery/applications/{id}/review", permDiscoveryManage, a.discoveryReview)
	a.console("GET /api/discovery/environments", permDiscoveryRead, a.discoveryEnvironments)
	a.console("GET /api/discovery/environments/{id}", permDiscoveryRead, a.discoveryEnvironment)
	a.console("GET /api/discovery/environments/{id}/evidence", permDiscoveryRead, a.discoveryEnvironmentEvidence)
	a.console("GET /api/discovery/events", permDiscoveryRead, a.discoveryEvents)
	a.console("GET /api/discovery/evidence/{id}", permDiscoveryRead, a.discoveryEvidence)
	a.console("GET /api/discovery/coverage", permDiscoveryRead, a.discoveryCoverage)
	a.console("GET /api/discovery/settings", permDiscoveryManage, a.discoverySettings)
	a.console("GET /api/discovery/devices/{id}/system-binding", permDiscoveryManage, a.discoverySystemBinding)
	a.sessionOnly("PUT /api/discovery/settings", permDiscoveryManage, a.putDiscoverySettings)
	a.console("GET /api/discovery/catalog", permDiscoveryRead, a.discoveryCatalogMetadata)
	a.console("GET /api/discovery/catalog/draft", permDiscoveryCatalogManage, a.discoveryCatalogDraft)
	a.console("PUT /api/discovery/catalog/draft", permDiscoveryCatalogManage, a.putDiscoveryCatalogDraft)
	a.console("POST /api/discovery/catalog/compile", permDiscoveryCatalogManage, a.compileDiscoveryCatalog)
	a.console("POST /api/discovery/catalog/evaluate", permDiscoveryCatalogManage, a.evaluateDiscoveryCatalog)
	a.sessionOnly("POST /api/discovery/catalog/publish", permDiscoveryCatalogManage, a.publishDiscoveryCatalog)
	a.console("POST /api/discovery/runs", permDiscoveryRun, a.startDiscoveryRun)
	a.console("GET /api/discovery/runs", permDiscoveryRead, a.discoveryRuns)
	a.console("GET /api/discovery/runs/{id}", permDiscoveryRead, a.discoveryRun)
	a.console("POST /api/discovery/runs/{id}/cancel", permDiscoveryRun, a.cancelDiscoveryRun)
	a.mux.HandleFunc("GET /v1/discovery/policy", a.deviceDiscoveryPolicy)
	a.mux.HandleFunc("POST /v1/discovery/reports", a.deviceFirst(a.ingestDiscoveryReport))
}

type DiscoverySettings struct {
	Host            bool `json:"host"`
	Containers      bool `json:"containers"`
	VirtualMachines bool `json:"virtual_machines"`
	GuestRead       bool `json:"guest_read"`
	GuestExecute    bool `json:"guest_execute"`
	HTTP            bool `json:"http"`
	Network         bool `json:"network"`
	IntervalSeconds int  `json:"interval_seconds"`
}

func (c DiscoverySettings) validate() error {
	if c.IntervalSeconds < 60 || c.IntervalSeconds > 3600 || c.GuestExecute && !c.GuestRead || c.GuestRead && !c.VirtualMachines || c.HTTP && !(c.Host || c.Containers || c.VirtualMachines) {
		return bad("Invalid discovery source configuration.")
	}
	return nil
}
func readDiscoverySettings(ctx context.Context, tx pgx.Tx, org string) (int64, DiscoverySettings, error) {
	out := DiscoverySettings{IntervalSeconds: 300}
	var revision int64
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT revision,configuration FROM discovery_settings WHERE organization_id=$1 FOR SHARE`, org).Scan(&revision, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, out, nil
	}
	if err != nil {
		return 0, out, err
	}
	err = json.Unmarshal(raw, &out)
	return revision, out, err
}
func (a *App) discoverySettings(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	revision, c, err := readDiscoverySettings(r.Context(), tx, s.OrganizationID)
	if err != nil {
		return err
	}
	reply(w, 200, map[string]any{"revision": revision, "configuration": c})
	return nil
}
func (a *App) putDiscoverySettings(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	var body struct {
		Revision      int64             `json:"revision"`
		Configuration DiscoverySettings `json:"configuration"`
		Reason        string            `json:"reason"`
	}
	if err := decode(w, r, &body); err != nil {
		return err
	}
	if err := body.Configuration.validate(); err != nil {
		return err
	}
	if err := a.requireFreshMFA(r, tx, s); err != nil {
		return err
	}
	if len(strings.TrimSpace(body.Reason)) < 8 || len(body.Reason) > 1000 {
		return bad(msgReasonLengthRequired)
	}
	inserted, err := tx.Exec(r.Context(), `INSERT INTO discovery_settings(organization_id) VALUES($1) ON CONFLICT DO NOTHING`, s.OrganizationID)
	if err != nil {
		return err
	}
	var current int64
	if err := tx.QueryRow(r.Context(), `SELECT revision FROM discovery_settings WHERE organization_id=$1 FOR UPDATE`, s.OrganizationID).Scan(&current); err != nil {
		return err
	}
	if body.Revision != current && !(body.Revision == 0 && inserted.RowsAffected() == 1) {
		return apiError{409, "revision_conflict", "Refresh discovery settings before saving."}
	}
	raw, _ := json.Marshal(body.Configuration)
	if _, err := tx.Exec(r.Context(), `UPDATE discovery_settings SET revision=nextval('shadow_revision'),configuration=$2,updated_at=now() WHERE organization_id=$1`, s.OrganizationID, raw); err != nil {
		return err
	}
	if err := privacyAudit(r, tx, s, "discovery.settings.update", "discovery", map[string]any{"reason": strings.TrimSpace(body.Reason), "configuration": body.Configuration}); err != nil {
		return err
	}
	// Consent withdrawal also invalidates previously requested work.
	if !body.Configuration.Host && !body.Configuration.Containers && !body.Configuration.VirtualMachines && !body.Configuration.Network {
		if _, err := tx.Exec(r.Context(), `UPDATE discovery_runs SET status='cancelled' WHERE organization_id=$1 AND status IN ('pending','running')`, s.OrganizationID); err != nil {
			return err
		}
	}
	revision, configuration, err := readDiscoverySettings(r.Context(), tx, s.OrganizationID)
	if err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	reply(w, 200, map[string]any{"revision": revision, "configuration": configuration})
	return nil
}

func discoveryPage(r *http.Request) (int, []string, error) {
	limit := 50
	if text := r.URL.Query().Get("limit"); text != "" {
		parsed, err := strconv.Atoi(text)
		if err != nil || parsed < 1 || parsed > 100 {
			return 0, nil, bad("Invalid page size.")
		}
		limit = parsed
	}
	cursor := []string{}
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		if len(raw) > 1024 {
			return 0, nil, bad("Invalid cursor.")
		}
		bytes, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil || json.Unmarshal(bytes, &cursor) != nil || len(cursor) > 4 {
			return 0, nil, bad("Invalid cursor.")
		}
		for _, part := range cursor {
			if len(part) > 200 {
				return 0, nil, bad("Invalid cursor.")
			}
		}
	}
	return limit, cursor, nil
}
func discoveryCursor(parts ...string) string {
	raw, _ := json.Marshal(parts)
	return base64.RawURLEncoding.EncodeToString(raw)
}
func discoveryID(id string) bool {
	if len(id) == 0 || len(id) > 160 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.:/", r)) {
			return false
		}
	}
	return true
}

func (a *App) discoveryApplications(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if err := requireIndividual(r); err != nil {
		return err
	}
	limit, cursor, err := discoveryPage(r)
	if err != nil {
		return err
	}
	after := ""
	if len(cursor) > 0 {
		if len(cursor) != 1 || !discoveryID(cursor[0]) {
			return bad("Invalid application cursor.")
		}
		after = cursor[0]
	}
	query := r.URL.Query().Get("q")
	if len(query) > 120 {
		return bad("Search exceeds its limit.")
	}
	key := discoveryReadKey{s.OrganizationID, query, after, limit, discoveryInventoryVisible(s)}
	additional := discoveryAdditionalInventoryDevices(s)
	value, err := a.discoveryReads.loadRefreshing(r.Context(), key, func() (json.RawMessage, error) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		return readDiscoveryApplications(ctx, tx, key, additional)
	}, func(ctx context.Context) (json.RawMessage, error) {
		return a.refreshDiscoveryApplications(ctx, key, additional)
	})
	if err != nil {
		return err
	}
	reply(w, 200, value)
	return nil
}

func (a *App) discoveryApplication(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if err := requireIndividual(r); err != nil {
		return err
	}
	id := r.PathValue("id")
	if !discoveryID(id) {
		return bad("Invalid application.")
	}
	var count int
	var status string
	var first, last any
	if err := tx.QueryRow(r.Context(), `SELECT count(*),coalesce((SELECT status FROM discovery_reviews WHERE organization_id=$1 AND application_id=$2),'review'),min(first_seen),max(last_seen) FROM `+discoveryInventorySource(s)+` WHERE organization_id=$1 AND application_id=$2 AND expires_at>now()`, s.OrganizationID, id).Scan(&count, &status, &first, &last); err != nil {
		return err
	}
	if count == 0 {
		return apiError{404, "not_found", "Application not found."}
	}
	value := map[string]any{"id": id, "review": status, "observations": count, "first_seen": first, "last_seen": last}
	discoveryInventoryMetadata(id, []map[string]any{value})
	reply(w, 200, value)
	return nil
}
func (a *App) discoveryInstances(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if err := discoveryDetails(r, s); err != nil {
		return err
	}
	id := r.PathValue("id")
	if !discoveryID(id) {
		return bad("Invalid application.")
	}
	limit, cursor, err := discoveryPage(r)
	if err != nil {
		return err
	}
	device := r.URL.Query().Get("device_id")
	if device != "" && !uuidPattern.MatchString(device) {
		return bad("Invalid device filter.")
	}
	afterDevice, afterScope, afterEntity, afterSignature := "", "", "", ""
	if len(cursor) > 0 {
		if len(cursor) != 4 || !uuidPattern.MatchString(cursor[0]) || !discoveryID(cursor[1]) || !discoveryID(cursor[2]) || !discoveryID(cursor[3]) {
			return bad("Invalid instance cursor.")
		}
		afterDevice, afterScope, afterEntity, afterSignature = cursor[0], cursor[1], cursor[2], cursor[3]
	}
	rows, err := tx.Query(r.Context(), `SELECT device_id::text,scope,entity_id,signature_id,state,evidence,last_seen,(SELECT e.display FROM discovery_entities e WHERE e.organization_id=discovery_identifications.organization_id AND e.device_id=discovery_identifications.device_id AND e.scope=discovery_identifications.scope AND e.id=discovery_identifications.entity_id) FROM `+discoveryInventorySource(s)+` WHERE organization_id=$1 AND application_id=$2 AND expires_at>now() AND (device_id,scope,entity_id,signature_id)>(coalesce(nullif($3,'')::uuid,'00000000-0000-0000-0000-000000000000'::uuid),$4,$5,$6) AND ($8='' OR device_id=nullif($8,'')::uuid) ORDER BY discovery_identifications.device_id,scope,entity_id,signature_id LIMIT $7`, s.OrganizationID, id, afterDevice, afterScope, afterEntity, afterSignature, limit+1, device)
	if err != nil {
		return err
	}
	defer rows.Close()
	items := []map[string]any{}
	next := ""
	for rows.Next() {
		var device, scope, entity, signature, state string
		var proof json.RawMessage
		var display json.RawMessage
		var seen any
		if err = rows.Scan(&device, &scope, &entity, &signature, &state, &proof, &seen, &display); err != nil {
			return err
		}
		item := map[string]any{"entity_id": entity, "scope": scope, "signature_id": signature, "state": state, "evidence": proof, "last_seen": seen, "display": display}
		if hasPermission(s.Permissions, permDevicesRead) {
			item["device_id"] = device
		}
		item["cursor"] = discoveryCursor(device, scope, entity, signature)
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if len(items) > limit {
		items = items[:limit]
		next = items[len(items)-1]["cursor"].(string)
	}
	for _, item := range items {
		delete(item, "cursor")
	}
	discoveryInventoryMetadata(id, items)
	if err := a.discoveryDeviceNames(r, tx, s, items); err != nil {
		return err
	}
	reply(w, 200, map[string]any{"items": items, "next_cursor": next})
	return nil
}
func (a *App) discoveryReview(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if err := requireIndividual(r); err != nil {
		return err
	}
	id := r.PathValue("id")
	if !discoveryID(id) {
		return bad("Invalid application.")
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := decode(w, r, &body); err != nil {
		return err
	}
	if body.Status != "review" && body.Status != "authorized" && body.Status != "unauthorized" && body.Status != "false_positive" {
		return bad("Invalid review status.")
	}
	tag, err := tx.Exec(r.Context(), `INSERT INTO discovery_reviews(organization_id,application_id,status) SELECT $1,$2,$3 WHERE EXISTS(SELECT 1 FROM `+discoveryInventorySource(s)+` WHERE organization_id=$1 AND application_id=$2 AND expires_at>now()) ON CONFLICT(organization_id,application_id) DO UPDATE SET status=excluded.status,updated_at=now()`, s.OrganizationID, id, body.Status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return apiError{404, "not_found", "Application not found."}
	}
	if err = privacyAudit(r, tx, s, "discovery.application.review", id, map[string]any{"status": body.Status}); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	a.discoveryReads.invalidate(s.OrganizationID)
	reply(w, 200, map[string]bool{"ok": true})
	return nil
}

func (a *App) discoverySummary(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	k := 5
	if p := privacyFor(r); p != nil {
		k = p.view.Config.K
	}
	if k < 1 {
		k = 1
	}
	rows, err := tx.Query(r.Context(), `SELECT application_id,count(DISTINCT device_id) FROM `+discoveryInventorySource(s)+` WHERE organization_id=$1 AND expires_at>now() GROUP BY application_id HAVING count(DISTINCT device_id)>=$2 ORDER BY application_id LIMIT 100`, s.OrganizationID, k)
	if err != nil {
		return err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id string
		var count int
		if err = rows.Scan(&id, &count); err != nil {
			return err
		}
		items = append(items, map[string]any{"application_id": id, "devices": count})
	}
	if err = rows.Err(); err != nil {
		return err
	}
	reply(w, 200, map[string]any{"items": items, "k_anonymity": k})
	return nil
}
