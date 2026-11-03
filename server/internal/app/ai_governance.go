package app

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"go.yaml.in/yaml/v3"
)

const permAIGovernanceApprove = "ai.governance.approve"

//go:embed ai_governance_migration.sql
var aiGovernanceMigration string

// A business authorization never enables collection or promises enforcement.
// The existing transport policy and its device anti-rollback remain independent.
type AIGovernanceRule struct {
	ID              string     `json:"id" yaml:"id"`
	Application     string     `json:"application_id" yaml:"application_id"`
	Activity        string     `json:"activity" yaml:"activity"`
	Scope           string     `json:"scope" yaml:"scope"`
	Target          string     `json:"target_id" yaml:"target_id"`
	Decision        string     `json:"decision" yaml:"decision"`
	Mandatory       bool       `json:"mandatory" yaml:"mandatory"`
	AllowExceptions bool       `json:"allow_exceptions" yaml:"allow_exceptions"`
	Owner           string     `json:"owner" yaml:"owner"`
	Purpose         string     `json:"purpose" yaml:"purpose"`
	ReviewDue       time.Time  `json:"review_due" yaml:"review_due"`
	ValidUntil      *time.Time `json:"valid_until,omitempty" yaml:"valid_until,omitempty"`
}
type AIGovernanceDocument struct {
	Version int                `json:"version" yaml:"version"`
	Rules   []AIGovernanceRule `json:"rules" yaml:"rules"`
}

func (d *AIGovernanceDocument) normalizeTargets() {
	for i := range d.Rules {
		d.Rules[i].Target = strings.ToLower(d.Rules[i].Target)
	}
}

type aiGovernanceLayer struct {
	Organization string               `json:"organization_id"`
	Revision     int64                `json:"revision"`
	Document     AIGovernanceDocument `json:"document"`
}
type aiGovernanceException struct {
	ID         string     `json:"id"`
	Device     string     `json:"device_id"`
	Rule       string     `json:"rule_id"`
	Revision   int64      `json:"policy_revision"`
	Reason     string     `json:"reason"`
	ApprovedBy string     `json:"approved_by"`
	ApprovedAt time.Time  `json:"approved_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}
type aiGovernanceAssessment struct {
	Status       string   `json:"status"`
	Decision     string   `json:"decision,omitempty"`
	Rule         string   `json:"rule_id,omitempty"`
	Organization string   `json:"organization_id,omitempty"`
	Revision     int64    `json:"revision,omitempty"`
	Scope        string   `json:"scope,omitempty"`
	Exception    string   `json:"exception_id,omitempty"`
	Exceptions   []string `json:"exception_ids,omitempty"`
	ReviewDue    bool     `json:"review_overdue"`
	Enforcement  string   `json:"enforcement"`
}

func validAIGovernanceText(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) || len(strings.TrimSpace(value)) < minimum || len(value) > maximum {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}

func (d AIGovernanceDocument) validate(now time.Time) error {
	if d.Version != 1 || d.Rules == nil || len(d.Rules) > 256 {
		return bad("Invalid governance document: version 1 and at most 256 rules required.")
	}
	ids := map[string]bool{}
	targets := map[string]bool{}
	for _, r := range d.Rules {
		key := r.Application + "\x00" + r.Activity + "\x00" + r.Scope + "\x00" + strings.ToLower(r.Target)
		if !discoveryID(r.ID) || len(r.ID) > 80 || strings.ContainsAny(r.ID, "/:") || ids[r.ID] || targets[key] {
			return bad("Duplicate or invalid governance rule.")
		}
		ids[r.ID] = true
		targets[key] = true
		if r.Application != "*" && !discoveryID(r.Application) || r.Activity != "presence" && r.Activity != "execution" || r.Decision != "allow" && r.Decision != "deny" {
			return bad("Invalid application, activity or decision.")
		}
		if r.Scope != "organization" && r.Scope != "group" && r.Scope != "device" || r.Scope == "organization" && r.Target != "" || r.Scope != "organization" && !uuidPattern.MatchString(r.Target) {
			return bad("Invalid governance scope.")
		}
		if r.Mandatory && r.Decision != "deny" || r.AllowExceptions && r.Decision != "deny" {
			return bad("Only a denial may be mandatory or accept exceptions.")
		}
		if !validAIGovernanceText(r.Owner, 1, 200) || !validAIGovernanceText(r.Purpose, 8, 1000) || r.ReviewDue.IsZero() || r.ReviewDue.After(now.AddDate(2, 0, 0)) || r.ValidUntil != nil && !r.ValidUntil.After(now) {
			return bad("A responsible owner, purpose and valid review date are required.")
		}
	}
	return nil
}

func readAIGovernance(ctx context.Context, tx pgx.Tx, org string) (aiGovernanceLayer, error) {
	layer := aiGovernanceLayer{Organization: org, Document: AIGovernanceDocument{Version: 1, Rules: []AIGovernanceRule{}}}
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT revision,document FROM ai_governance_policies WHERE organization_id=$1`, org).Scan(&layer.Revision, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return layer, nil
	}
	if err != nil {
		return layer, err
	}
	err = json.Unmarshal(raw, &layer.Document)
	if err == nil {
		layer.Document.normalizeTargets()
	}
	return layer, err
}
func (a *App) registerAIGovernanceRoutes() {
	a.console("GET /api/ai-governance/systems", permPolicyManage, a.aiGovernanceSystems)
	a.console("POST /api/ai-governance/systems/validate", permPolicyManage, a.validateAIGovernanceSystems)
	a.sessionOnly("PUT /api/ai-governance/systems", permPolicyManage, a.putAIGovernanceSystems)
	a.console("GET /api/ai-governance/framework", permDiscoveryRead, a.aiGovernanceFramework)
	a.console("GET /api/ai-governance/policy", permPolicyManage, a.aiGovernancePolicy)
	a.console("POST /api/ai-governance/validate", permPolicyManage, a.validateAIGovernance)
	a.sessionOnly("PUT /api/ai-governance/policy", permPolicyManage, a.putAIGovernancePolicy)
	a.console("GET /api/ai-governance/effective", permDiscoveryRead, a.aiGovernanceEffective)
	a.console("GET /api/ai-governance/approval-options", permAIGovernanceApprove, a.aiGovernanceApprovalOptions)
	a.console("GET /api/ai-governance/exceptions", permDevicesRead, a.aiGovernanceExceptions)
	a.sessionOnly("POST /api/ai-governance/exceptions", permAIGovernanceApprove, a.approveAIGovernanceException)
	a.sessionOnly("POST /api/ai-governance/exceptions/{id}/revoke", permAIGovernanceApprove, a.revokeAIGovernanceException)
	a.console("GET /api/ai-governance/history", permPolicyManage, a.aiGovernanceHistory)
}
func (a *App) aiGovernancePolicy(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if err := requireIndividual(r); err != nil {
		return err
	}
	layer, err := readAIGovernance(r.Context(), tx, s.OrganizationID)
	if err != nil {
		return err
	}
	ancestors, err := a.aiGovernanceAncestors(r.Context(), tx, s.OrganizationID)
	if err != nil {
		return err
	}
	reply(w, 200, map[string]any{"revision": layer.Revision, "document": layer.Document, "ancestors": ancestors})
	return nil
}
func (a *App) validateAIGovernance(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	var body struct {
		Source string `json:"source"`
	}
	if err := decode(w, r, &body); err != nil {
		return err
	}
	if len(body.Source) == 0 || len(body.Source) > 131072 {
		return bad("Governance source exceeds its limit.")
	}
	decoder := yaml.NewDecoder(strings.NewReader(body.Source))
	decoder.KnownFields(true)
	var d AIGovernanceDocument
	if err := decoder.Decode(&d); err != nil {
		return bad("Invalid governance YAML.")
	}
	var tail any
	if decoder.Decode(&tail) != io.EOF {
		return bad("Only one governance document is accepted.")
	}
	d.normalizeTargets()
	if err := d.validate(time.Now()); err != nil {
		return err
	}
	reply(w, 200, map[string]any{"document": d, "simulation": true, "persisted": false})
	return nil
}
func (a *App) putAIGovernancePolicy(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if err := requireIndividual(r); err != nil {
		return err
	}
	var body struct {
		Revision int64                `json:"revision"`
		Document AIGovernanceDocument `json:"document"`
		Reason   string               `json:"reason"`
	}
	if err := decode(w, r, &body); err != nil {
		return err
	}
	body.Document.normalizeTargets()
	if err := body.Document.validate(time.Now()); err != nil {
		return err
	}
	if !validAIGovernanceText(body.Reason, 8, 1000) {
		return bad(msgReasonLengthRequired)
	}
	if err := a.requireFreshMFA(r, tx, s); err != nil {
		return err
	}
	// Resolve targets under tenant RLS. A valid UUID is never sufficient authority.
	for _, rule := range body.Document.Rules {
		if rule.Scope == "organization" {
			continue
		}
		query := `SELECT EXISTS(SELECT 1 FROM devices WHERE organization_id=$1 AND id=$2)`
		if rule.Scope == "group" {
			query = `SELECT EXISTS(SELECT 1 FROM device_groups WHERE organization_id=$1 AND id=$2)`
		}
		var exists bool
		if err := tx.QueryRow(r.Context(), query, s.OrganizationID, rule.Target).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return bad("Governance target not found in this organization.")
		}
	}
	tag, err := tx.Exec(r.Context(), `INSERT INTO ai_governance_policies(organization_id) VALUES($1) ON CONFLICT DO NOTHING`, s.OrganizationID)
	if err != nil {
		return err
	}
	var revision int64
	if err = tx.QueryRow(r.Context(), `SELECT revision FROM ai_governance_policies WHERE organization_id=$1 FOR UPDATE`, s.OrganizationID).Scan(&revision); err != nil {
		return err
	}
	if body.Revision != revision && !(body.Revision == 0 && tag.RowsAffected() == 1) {
		return apiError{409, "revision_conflict", "Refresh governance policy before saving."}
	}
	raw, _ := json.Marshal(body.Document)
	if err = tx.QueryRow(r.Context(), `UPDATE ai_governance_policies SET revision=nextval('shadow_revision'),document=$2,updated_at=now() WHERE organization_id=$1 RETURNING revision`, s.OrganizationID, raw).Scan(&revision); err != nil {
		return err
	}
	if err = privacyAudit(r, tx, s, "ai.governance.publish", "ai-governance", map[string]any{"reason": strings.TrimSpace(body.Reason), "revision": revision, "document": body.Document}); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	reply(w, 200, map[string]any{"revision": revision, "document": body.Document})
	return nil
}

// Mandatory denials are evaluated before specificity; a local allow cannot
// remove one. Ancestor exceptions cannot be approved by a descendant's role.
func evaluateAIGovernance(layers []aiGovernanceLayer, exceptions []aiGovernanceException, org, device, group, app, activity string, proven bool, now time.Time) aiGovernanceAssessment {
	// UUID spelling is case-insensitive in PostgreSQL and at the API boundary.
	device, group = strings.ToLower(device), strings.ToLower(group)
	out := aiGovernanceAssessment{Status: "no_rule", Enforcement: "detection_only"}
	type candidate struct {
		rule      AIGovernanceRule
		layer     aiGovernanceLayer
		score     int
		exception string
	}
	candidates := []candidate{}
	mandatoryExceptions := []string{}
	for depth, layer := range layers {
		for _, rule := range layer.Document.Rules {
			if rule.Activity != activity || rule.Application != "*" && rule.Application != app || rule.ValidUntil != nil && !rule.ValidUntil.After(now) {
				continue
			}
			scope := 0
			switch rule.Scope {
			case "organization":
			case "group":
				if layer.Organization != org || !strings.EqualFold(rule.Target, group) {
					continue
				}
				scope = 1
			case "device":
				if layer.Organization != org || !strings.EqualFold(rule.Target, device) {
					continue
				}
				scope = 2
			default:
				continue
			}
			c := candidate{rule: rule, layer: layer, score: depth*10 + scope*2}
			if rule.Application == app {
				c.score++
			}
			if rule.AllowExceptions && layer.Organization == org {
				for _, e := range exceptions {
					if strings.EqualFold(e.Device, device) && e.Rule == rule.ID && e.Revision == layer.Revision && e.RevokedAt == nil && e.ExpiresAt.After(now) {
						c.exception = e.ID
						break
					}
				}
			}
			if rule.Mandatory && rule.Decision == "deny" && c.exception == "" {
				c.score += 100000
			}
			if rule.Mandatory && c.exception != "" {
				mandatoryExceptions = append(mandatoryExceptions, c.exception)
			}
			candidates = append(candidates, c)
		}
	}
	if len(candidates) == 0 {
		return out
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].score > candidates[j].score })
	c := candidates[0]
	out.Rule = c.rule.ID
	out.Organization = c.layer.Organization
	out.Revision = c.layer.Revision
	out.Scope = c.rule.Scope
	out.Decision = c.rule.Decision
	out.Exception = c.exception
	out.ReviewDue = !c.rule.ReviewDue.After(now)
	if c.exception != "" {
		out.Decision = "allow"
	}
	if out.Decision == "allow" {
		seen := map[string]bool{}
		for _, id := range append(mandatoryExceptions, c.exception) {
			if id != "" && !seen[id] {
				out.Exceptions = append(out.Exceptions, id)
				seen[id] = true
			}
		}
		if out.Exception == "" && len(out.Exceptions) > 0 {
			out.Exception = out.Exceptions[0]
		}
	}
	if !proven {
		out.Status = "insufficient_evidence"
	} else if out.Decision == "deny" {
		out.Status = "deviation"
	} else if out.ReviewDue {
		out.Status = "review_due"
	} else {
		out.Status = "allowed"
	}
	return out
}

func (a *App) governanceForLocations(r *http.Request, tx pgx.Tx, s *Session, app string, items []map[string]any) error {
	if len(items) == 0 {
		return nil
	}
	layers, err := a.aiGovernanceAncestors(r.Context(), tx, s.OrganizationID)
	if err != nil {
		return err
	}
	local, err := readAIGovernance(r.Context(), tx, s.OrganizationID)
	if err != nil {
		return err
	}
	layers = append(layers, local)
	ids := make([]string, 0, len(items))
	for _, item := range items {
		ids = append(ids, item["device_id"].(string))
	}
	rows, err := tx.Query(r.Context(), `SELECT id::text,coalesce(group_id::text,'') FROM devices WHERE organization_id=$1 AND id=ANY($2::uuid[])`, s.OrganizationID, ids)
	if err != nil {
		return err
	}
	groups := map[string]string{}
	for rows.Next() {
		var id, group string
		if err = rows.Scan(&id, &group); err != nil {
			rows.Close()
			return err
		}
		groups[id] = group
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	exceptions, err := readAIGovernanceExceptions(r.Context(), tx, s.OrganizationID, ids)
	if err != nil {
		return err
	}
	now := time.Now()
	for _, item := range items {
		states, _ := item["states"].([]string)
		presence, execution := false, false
		for _, state := range states {
			presence = presence || state == "installed" || state == "executed" || state == "interface_recognized"
			execution = execution || state == "executed"
		}
		device := item["device_id"].(string)
		item["governance"] = map[string]any{"presence": evaluateAIGovernance(layers, exceptions, s.OrganizationID, device, groups[device], app, "presence", presence, now), "execution": evaluateAIGovernance(layers, exceptions, s.OrganizationID, device, groups[device], app, "execution", execution, now), "evaluated_at": now, "group_id": groups[device]}
	}
	return nil
}
func (a *App) aiGovernanceEffective(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if err := discoveryDetails(r, s); err != nil {
		return err
	}
	device, app := strings.ToLower(r.URL.Query().Get("device_id")), r.URL.Query().Get("application_id")
	if !uuidPattern.MatchString(device) || !discoveryID(app) {
		return bad("A device and application are required.")
	}
	var exists bool
	if err := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM devices WHERE organization_id=$1 AND id=$2)`, s.OrganizationID, device).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return apiError{404, "not_found", "Device not found."}
	}
	var states []string
	if err := tx.QueryRow(r.Context(), `SELECT coalesce(array_agg(DISTINCT state),'{}') FROM `+discoveryInventorySource(s)+` WHERE organization_id=$1 AND device_id=$2 AND application_id=$3 AND expires_at>now()`, s.OrganizationID, device, app).Scan(&states); err != nil {
		return err
	}
	items := []map[string]any{{"device_id": device, "states": states}}
	if err := a.governanceForLocations(r, tx, s, app, items); err != nil {
		return err
	}
	reply(w, 200, items[0])
	return nil
}
func readAIGovernanceExceptions(ctx context.Context, tx pgx.Tx, org string, devices []string) ([]aiGovernanceException, error) {
	rows, err := tx.Query(ctx, `SELECT id::text,device_id::text,rule_id,policy_revision,reason,approved_by::text,approved_at,expires_at,revoked_at FROM ai_governance_exceptions WHERE organization_id=$1 AND device_id=ANY($2::uuid[]) AND policy_revision=coalesce((SELECT revision FROM ai_governance_policies WHERE organization_id=$1),0) AND revoked_at IS NULL AND expires_at>now() ORDER BY approved_at DESC LIMIT 1001`, org, devices)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []aiGovernanceException{}
	for rows.Next() {
		var e aiGovernanceException
		if err = rows.Scan(&e.ID, &e.Device, &e.Rule, &e.Revision, &e.Reason, &e.ApprovedBy, &e.ApprovedAt, &e.ExpiresAt, &e.RevokedAt); err != nil {
			return nil, err
		}
		items = append(items, e)
	}
	if len(items) > 1000 {
		return nil, bad("Governance exception limit exceeded.")
	}
	return items, rows.Err()
}
func (a *App) aiGovernanceExceptions(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if !hasPermission(s.Permissions, permPolicyManage) && !hasPermission(s.Permissions, permAIGovernanceApprove) {
		return forbidden()
	}
	if err := discoveryDetails(r, s); err != nil {
		return err
	}
	device := r.URL.Query().Get("device_id")
	if !uuidPattern.MatchString(device) {
		return bad("A device is required.")
	}
	items, err := readAIGovernanceExceptions(r.Context(), tx, s.OrganizationID, []string{device})
	if err != nil {
		return err
	}
	reply(w, 200, map[string]any{"items": items})
	return nil
}

// Delegated approvers may read only applicable exception options; approval must
// not require granting policy publication authority as a side effect.
func (a *App) aiGovernanceApprovalOptions(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if err := discoveryDetails(r, s); err != nil {
		return err
	}
	device, app := strings.ToLower(r.URL.Query().Get("device_id")), r.URL.Query().Get("application_id")
	if !uuidPattern.MatchString(device) || !discoveryID(app) {
		return bad("A device and application are required.")
	}
	var group string
	if err := tx.QueryRow(r.Context(), `SELECT coalesce(group_id::text,'') FROM devices WHERE organization_id=$1 AND id=$2`, s.OrganizationID, device).Scan(&group); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return apiError{404, "not_found", "Device not found."}
		}
		return err
	}
	layer, err := readAIGovernance(r.Context(), tx, s.OrganizationID)
	if err != nil {
		return err
	}
	rules := []AIGovernanceRule{}
	now := time.Now()
	for _, rule := range layer.Document.Rules {
		if rule.Decision != "deny" || !rule.AllowExceptions || rule.Application != "*" && rule.Application != app || rule.Scope == "device" && !strings.EqualFold(rule.Target, device) || rule.Scope == "group" && !strings.EqualFold(rule.Target, group) || rule.ValidUntil != nil && !rule.ValidUntil.After(now) || !rule.ReviewDue.After(now) {
			continue
		}
		rules = append(rules, rule)
	}
	reply(w, 200, map[string]any{"revision": layer.Revision, "rules": rules})
	return nil
}
func (a *App) approveAIGovernanceException(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if err := discoveryDetails(r, s); err != nil {
		return err
	}
	var body struct {
		Device   string    `json:"device_id"`
		Rule     string    `json:"rule_id"`
		Revision int64     `json:"revision"`
		Reason   string    `json:"reason"`
		Expires  time.Time `json:"expires_at"`
	}
	if err := decode(w, r, &body); err != nil {
		return err
	}
	body.Device = strings.ToLower(body.Device)
	now := time.Now()
	if !uuidPattern.MatchString(body.Device) || !validAIGovernanceText(body.Reason, 8, 1000) || !body.Expires.After(now) || body.Expires.After(now.AddDate(0, 3, 0)) {
		return bad("A device, justification and exception expiry within three months are required.")
	}
	if err := a.requireFreshMFA(r, tx, s); err != nil {
		return err
	}
	// Serialize approvals with policy publication and the active exception cap.
	var locked int64
	if err := tx.QueryRow(r.Context(), `SELECT revision FROM ai_governance_policies WHERE organization_id=$1 FOR UPDATE`, s.OrganizationID).Scan(&locked); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return bad("Publish a governance policy first.")
		}
		return err
	}
	layer, err := readAIGovernance(r.Context(), tx, s.OrganizationID)
	if err != nil {
		return err
	}
	if layer.Revision != body.Revision {
		return apiError{409, "revision_conflict", "Refresh governance policy before approving an exception."}
	}
	var group string
	if err = tx.QueryRow(r.Context(), `SELECT coalesce(group_id::text,'') FROM devices WHERE organization_id=$1 AND id=$2`, s.OrganizationID, body.Device).Scan(&group); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return bad("Device not found.")
		}
		return err
	}
	var rule *AIGovernanceRule
	for _, candidate := range layer.Document.Rules {
		if candidate.ID == body.Rule {
			copy := candidate
			rule = &copy
			break
		}
	}
	if rule == nil || rule.Decision != "deny" || !rule.AllowExceptions || rule.Scope == "device" && !strings.EqualFold(rule.Target, body.Device) || rule.Scope == "group" && !strings.EqualFold(rule.Target, group) || rule.ValidUntil != nil && !rule.ValidUntil.After(now) || !rule.ReviewDue.After(now) {
		return bad("This rule does not permit an exception for this device.")
	}
	if rule.ValidUntil != nil && body.Expires.After(*rule.ValidUntil) {
		return bad("Exception cannot outlive its rule.")
	}
	var duplicate bool
	if err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM ai_governance_exceptions WHERE organization_id=$1 AND device_id=$2 AND rule_id=$3 AND policy_revision=$4 AND revoked_at IS NULL AND expires_at>now())`, s.OrganizationID, body.Device, body.Rule, body.Revision).Scan(&duplicate); err != nil {
		return err
	}
	if duplicate {
		return apiError{409, "exception_exists", "An active exception already exists for this device and rule. Revoke it before replacing it."}
	}
	var count int
	if err = tx.QueryRow(r.Context(), `SELECT count(*) FROM ai_governance_exceptions WHERE organization_id=$1 AND policy_revision=$2 AND revoked_at IS NULL AND expires_at>now()`, s.OrganizationID, body.Revision).Scan(&count); err != nil {
		return err
	}
	if count >= 1000 {
		return bad("Active governance exception limit reached.")
	}
	var id string
	if err = tx.QueryRow(r.Context(), `INSERT INTO ai_governance_exceptions(organization_id,device_id,rule_id,policy_revision,reason,approved_by,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id::text`, s.OrganizationID, body.Device, body.Rule, body.Revision, strings.TrimSpace(body.Reason), s.UserID, body.Expires).Scan(&id); err != nil {
		return err
	}
	if err = privacyAudit(r, tx, s, "ai.governance.exception.approve", id, map[string]any{"device_id": body.Device, "rule_id": body.Rule, "revision": body.Revision, "reason": strings.TrimSpace(body.Reason), "expires_at": body.Expires}); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	reply(w, 201, map[string]any{"id": id})
	return nil
}
func (a *App) revokeAIGovernanceException(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if err := discoveryDetails(r, s); err != nil {
		return err
	}
	id := r.PathValue("id")
	if !uuidPattern.MatchString(id) {
		return bad("Invalid exception.")
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if err := decode(w, r, &body); err != nil {
		return err
	}
	if !validAIGovernanceText(body.Reason, 8, 1000) {
		return bad(msgReasonLengthRequired)
	}
	if err := a.requireFreshMFA(r, tx, s); err != nil {
		return err
	}
	tag, err := tx.Exec(r.Context(), `UPDATE ai_governance_exceptions SET revoked_at=now() WHERE organization_id=$1 AND id=$2 AND revoked_at IS NULL`, s.OrganizationID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return apiError{404, "not_found", "Active exception not found."}
	}
	if err = privacyAudit(r, tx, s, "ai.governance.exception.revoke", id, map[string]any{"reason": strings.TrimSpace(body.Reason)}); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	reply(w, 200, map[string]bool{"ok": true})
	return nil
}
func (a *App) aiGovernanceHistory(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if err := requireIndividual(r); err != nil {
		return err
	}
	limit, cursor, err := discoveryPage(r)
	if err != nil {
		return err
	}
	afterDate, afterID := "", ""
	if len(cursor) > 0 {
		if len(cursor) != 2 || !uuidPattern.MatchString(cursor[1]) {
			return bad("Invalid governance history cursor.")
		}
		if _, err := time.Parse(time.RFC3339Nano, cursor[0]); err != nil {
			return bad("Invalid governance history cursor.")
		}
		afterDate, afterID = cursor[0], cursor[1]
	}
	// Explicit projection: no unrelated audit event or user identity is exposed.
	rows, err := tx.Query(r.Context(), `SELECT id::text,action,target,details,occurred_at FROM audit WHERE organization_id=$1 AND action IN ('ai.governance.publish','ai.governance.exception.approve','ai.governance.exception.revoke') AND (occurred_at,id)<(coalesce(nullif($2,'')::timestamptz,'infinity'::timestamptz),coalesce(nullif($3,'')::uuid,'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid)) ORDER BY occurred_at DESC,id DESC LIMIT $4`, s.OrganizationID, afterDate, afterID, limit+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, action, target string
		var details json.RawMessage
		var at time.Time
		if err = rows.Scan(&id, &action, &target, &details, &at); err != nil {
			return err
		}
		items = append(items, map[string]any{"id": id, "action": action, "target": target, "details": details, "created_at": at})
	}
	if err = rows.Err(); err != nil {
		return err
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		next = discoveryCursor(items[len(items)-1]["created_at"].(time.Time).Format(time.RFC3339Nano), items[len(items)-1]["id"].(string))
	}
	reply(w, 200, map[string]any{"items": items, "next_cursor": next})
	return nil
}
