package app

import (
	"github.com/jackc/pgx/v5"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

type ModelAccessRule struct {
	PlatformID string   `json:"platform_id"`
	Channel    string   `json:"channel"`
	Mode       string   `json:"mode"`
	Models     []string `json:"models"`
}
type ModelCatalogEntry struct {
	PlatformID string   `json:"platform_id"`
	Channel    string   `json:"channel"`
	Name       string   `json:"name"`
	Provider   string   `json:"provider"`
	Models     []string `json:"models"`
}

var modelIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/+\-]{0,199}$`)

const (
	anthropicDomain = "anthropic.com"
)

func modelCatalog() []ModelCatalogEntry {
	out := []ModelCatalogEntry{}
	names := []string{"ChatGPT", "Claude", "Le Chat", "Copilot", "Gemini", "NotebookLM", "DeepSeek", "Perplexity", "Grok"}
	for i, s := range catalog {
		out = append(out, ModelCatalogEntry{s.ID, "browser", names[i], s.Domains[0], []string{}})
	}
	if Edition == "commercial" {
		for _, s := range []struct{ id, name, provider string }{{"codex", "Codex", "openai.com"}, {"claude-code", "Claude Code", anthropicDomain}, {"claude-desktop", "Claude Desktop", anthropicDomain}, {"claude-desktop-agent", "Claude Desktop Agent", anthropicDomain}} {
			out = append(out, ModelCatalogEntry{s.id, "native", s.name, s.provider, []string{}})
		}
	}
	return out
}
func validModelPlatform(platform, channel string) bool {
	for _, p := range modelCatalog() {
		if p.PlatformID == platform && p.Channel == channel {
			return true
		}
	}
	return false
}
func validateModelAccess(rules []ModelAccessRule) error {
	if len(rules) > 160 {
		return bad("Too many model access rules.")
	}
	seen := map[string]bool{}
	for _, r := range rules {
		key := r.Channel + "/" + r.PlatformID
		if !modelPlatformShape(r.PlatformID, r.Channel) || seen[key] || !slices.Contains([]string{"off", "allowlist", "denylist"}, r.Mode) || len(r.Models) > 100 {
			return bad("Invalid model access rule for this edition.")
		}
		seen[key] = true
		models := map[string]bool{}
		for _, m := range r.Models {
			if !modelIDPattern.MatchString(m) || models[m] {
				return bad("Use unique exact model identifiers.")
			}
			models[m] = true
		}
	}
	return nil
}

// Legacy endpoints cannot enforce a model boundary. Keep the whole browser
// platform closed instead of silently dropping an administrator's restriction.
func legacyModelConfig(c ShadowConfig) ShadowConfig {
	c.Services = append([]ServiceConfig{}, c.Services...)
	for _, r := range c.ModelAccess {
		if r.Channel != "browser" || r.Mode == "off" {
			continue
		}
		for i := range c.Services {
			if c.Services[i].ID == r.PlatformID {
				c.Services[i].Enabled = true
				c.Services[i].Mode = "block"
				c.Services[i].RedirectURL = ""
			}
		}
	}
	return c
}

type enforcementReport struct {
	Revision   int64  `json:"revision"`
	PlatformID string `json:"platform_id"`
	Channel    string `json:"channel"`
	Status     string `json:"status"`
	Reason     string `json:"reason"`
	Mechanism  string `json:"mechanism"`
}

func validEnforcementReport(v enforcementReport) bool {
	return v.Revision > 0 && validModelPlatform(v.PlatformID, v.Channel) &&
		slices.Contains([]string{"applied", "unavailable"}, v.Status) &&
		len(v.Reason) <= 200 && (v.Reason == "" || categoryPattern.MatchString(v.Reason)) &&
		((v.Channel == "browser" && v.Mechanism == "browser-request") || (v.Channel == "native" && v.Mechanism == "local-proxy"))
}
func (a *App) modelEnforcement(w http.ResponseWriter, r *http.Request) {
	if e := a.modelEnforcementRequest(w, r); e != nil {
		a.fail(w, e)
	}
}
func (a *App) modelEnforcementRequest(w http.ResponseWriter, r *http.Request) error {
	// Community has no per-model control, so it accepts no enforcement report.
	if Edition != "commercial" {
		return apiError{404, "not_found", "Endpoint route not found."}
	}
	var v enforcementReport
	if e := decode(w, r, &v); e != nil {
		return e
	}
	if !validEnforcementReport(v) {
		return bad("Invalid enforcement report.")
	}
	tx, org, id, e := a.deviceTx(r)
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	if _, e = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock_shared(7069202)`); e != nil {
		return e
	}
	var kind string
	if e = tx.QueryRow(r.Context(), `SELECT kind FROM devices WHERE id=$1`, id).Scan(&kind); e != nil {
		return e
	}
	if v.Channel == "native" && kind != "native" {
		return forbidden()
	}
	cfg, e := a.effectiveShadow(r.Context(), tx, org, id)
	if e != nil {
		return e
	}
	if v.Revision != cfg.Revision {
		return apiError{409, "revision_conflict", "Refresh the current policy before reporting enforcement."}
	}
	active := false
	for _, rule := range cfg.Config.ModelAccess {
		if rule.PlatformID == v.PlatformID && rule.Channel == v.Channel && rule.Mode != "off" {
			active = true
		}
	}
	if !active {
		return bad("No active model restriction for this platform and channel.")
	}
	if _, e = tx.Exec(r.Context(), `INSERT INTO model_enforcement(organization_id,device_id,platform_id,channel,revision,status,reason,mechanism) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(organization_id,device_id,platform_id,channel) DO UPDATE SET revision=excluded.revision,status=excluded.status,reason=excluded.reason,mechanism=excluded.mechanism,reported_at=now()`, org, id, v.PlatformID, v.Channel, v.Revision, v.Status, v.Reason, v.Mechanism); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]bool{"accepted": true})
	return nil
}

type modelStatusItem struct {
	DeviceID         string     `json:"device_id"`
	Hostname         string     `json:"hostname"`
	Version          string     `json:"version"`
	Platform         string     `json:"platform"`
	PlatformID       string     `json:"platform_id"`
	Channel          string     `json:"channel"`
	ExpectedRevision int64      `json:"expected_revision"`
	AppliedRevision  int64      `json:"applied_revision"`
	Status           string     `json:"status"`
	Reason           string     `json:"reason"`
	ReportedAt       *time.Time `json:"reported_at"`
}

func modelCapableVersion(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	var n [3]int
	for i, p := range parts {
		v, e := strconv.Atoi(p)
		if e != nil || v < 0 {
			return false
		}
		n[i] = v
	}
	return n[0] > 0 || n[1] >= 4
}

// enforcementSkew is how far ahead of the reading clock a report may be dated and
// still count as fresh. It bounds clock disagreement between the server and the
// database, not agent behaviour: an agent cannot influence `reported_at`, which
// the server writes itself.
const enforcementSkew = 30 * time.Second

func enforcementState(version string, expected, reported int64, status string, at *time.Time, now time.Time) string {
	if at == nil {
		if !modelCapableVersion(version) {
			return "needs_update"
		}
		return "pending"
	}
	if reported != expected {
		return "pending"
	}
	// `at` is written by PostgreSQL (`reported_at`), so it is only ever compared
	// against a clock that may not be the same one. The caller reads `now` from the
	// database for that reason; the tolerance below is what keeps the comparison
	// honest anyway -- in production the server and the database are different
	// machines, and a strict `at.After(now)` turns a few milliseconds of skew into
	// "unavailable" for a device that has just reported "applied". Beyond the
	// tolerance the timestamp is not a fresh report, it is a broken clock.
	if now.Sub(*at) > 3*time.Minute || at.After(now.Add(enforcementSkew)) {
		return "unavailable"
	}
	if status == "applied" {
		return "applied"
	}
	return "unavailable"
}
func aggregateModelStatus(items []modelStatusItem, floor int) []map[string]any {
	type state struct{ platform, channel, status string }
	per := map[state]map[string]bool{}
	for _, v := range items {
		k := state{v.PlatformID, v.Channel, v.Status}
		if per[k] == nil {
			per[k] = map[string]bool{}
		}
		per[k][v.DeviceID] = true
	}
	// Nothing below the aggregation threshold, as a report cell.
	counts := []map[string]any{}
	for k, devices := range per {
		if len(devices) < floor {
			continue
		}
		counts = append(counts, map[string]any{"platform_id": k.platform, "channel": k.channel, "status": k.status, "devices": len(devices)})
	}
	slices.SortFunc(counts, func(a, b map[string]any) int {
		return strings.Compare(a["platform_id"].(string)+"\x00"+a["channel"].(string)+"\x00"+a["status"].(string), b["platform_id"].(string)+"\x00"+b["channel"].(string)+"\x00"+b["status"].(string))
	})
	return counts
}

type modelStatusDevice struct{ id, host, version, platform, kind, status string }

func modelStatusForRule(r *http.Request, tx pgx.Tx, d modelStatusDevice, rule ModelAccessRule, revision int64, now time.Time) (modelStatusItem, bool, error) {
	if rule.Mode == "off" || (rule.Channel == "native" && d.kind != "native") {
		return modelStatusItem{}, false, nil
	}
	v := modelStatusItem{DeviceID: d.id, Hostname: d.host, Version: d.version, Platform: d.platform, PlatformID: rule.PlatformID, Channel: rule.Channel, ExpectedRevision: revision}
	var reportedStatus string
	e := tx.QueryRow(r.Context(), `SELECT revision,status,reason,reported_at FROM model_enforcement WHERE device_id=$1 AND platform_id=$2 AND channel=$3`, d.id, rule.PlatformID, rule.Channel).Scan(&v.AppliedRevision, &reportedStatus, &v.Reason, &v.ReportedAt)
	if e != nil && e != pgx.ErrNoRows {
		return modelStatusItem{}, false, e
	}
	v.Status = enforcementState(d.version, revision, v.AppliedRevision, reportedStatus, v.ReportedAt, now)
	if d.status != "approved" {
		v.Status = "unavailable"
		v.Reason = "device_" + d.status
	}
	if v.Status == "unavailable" && v.Reason == "" {
		v.Reason = "control_unavailable"
	}
	return v, true, nil
}

func (a *App) modelStatusItems(r *http.Request, tx pgx.Tx, s *Session, devices []modelStatusDevice) ([]modelStatusItem, error) {
	items := []modelStatusItem{}
	// Read the clock from the database, the same one that stamped `reported_at`.
	// Comparing a PostgreSQL timestamp against the server's own clock made
	// freshness depend on their disagreement rather than on the device.
	var now time.Time
	if e := tx.QueryRow(r.Context(), `SELECT clock_timestamp()`).Scan(&now); e != nil {
		return nil, e
	}
	for _, d := range devices {
		cfg, e := a.effectiveShadow(r.Context(), tx, s.OrganizationID, d.id)
		if e != nil {
			return nil, e
		}
		for _, rule := range cfg.Config.ModelAccess {
			v, active, e := modelStatusForRule(r, tx, d, rule, cfg.Revision, now)
			if e != nil {
				return nil, e
			}
			if active {
				items = append(items, v)
			}
		}

	}
	return items, nil
}

func (a *App) modelAccessStatus(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	rows, e := tx.Query(r.Context(), `SELECT id,hostname_ciphertext,version,platform,kind,status FROM devices ORDER BY hostname,id`)
	if e != nil {
		return e
	}
	devices := []modelStatusDevice{}
	// The route is open to overview.read (the reporter role): a machine is named only
	// to someone who may read the devices, and never under aggregate-only reporting,
	// as Discovery already does. Otherwise it is its alias (audit of 2026-09-24).
	named := namesMachines(r, s)
	for rows.Next() {
		var d modelStatusDevice
		if e = rows.Scan(&d.id, &d.host, &d.version, &d.platform, &d.kind, &d.status); e != nil {
			rows.Close()
			return e
		}
		if named {
			d.host, e = a.machineName(r, s.OrganizationID, d.id, d.host)
		} else {
			d.host = deviceAlias(d.id)
		}
		if e != nil {
			rows.Close()
			return e
		}
		devices = append(devices, d)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return e
	}
	items, e := a.modelStatusItems(r, tx, s, devices)
	if e != nil {
		return e
	}
	// Under aggregate-only reporting, counts only (product decision, 2026-09-24): machines
	// per platform, channel and state. A row per machine, even under a label, kept its
	// set of rules together -- a group or an override -- and /api/devices names it.
	if requireIndividual(r) != nil {
		counts := aggregateModelStatus(items, privacyFor(r).view.Config.K)
		reply(w, 200, map[string]any{"items": []modelStatusItem{}, "counts": counts})
		return nil
	}
	reply(w, 200, map[string]any{"items": items})
	return nil
}
