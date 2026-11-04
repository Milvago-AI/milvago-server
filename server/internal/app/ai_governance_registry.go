package app

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"go.yaml.in/yaml/v3"
)

// Business declarations complement observations. They never authorize software,
// enable collection, or change the revision of an authorization exception.
type AIDeclaredSystem struct {
	ID             string    `json:"id" yaml:"id"`
	Name           string    `json:"name" yaml:"name"`
	Owner          string    `json:"owner" yaml:"owner"`
	Purpose        string    `json:"purpose" yaml:"purpose"`
	Scope          string    `json:"scope" yaml:"scope"`
	Target         string    `json:"target_id" yaml:"target_id"`
	Applications   []string  `json:"application_ids" yaml:"application_ids"`
	Providers      []string  `json:"providers" yaml:"providers"`
	Models         []string  `json:"models" yaml:"models"`
	DataCategories []string  `json:"data_categories" yaml:"data_categories"`
	RiskLevel      string    `json:"risk_level" yaml:"risk_level"`
	RiskSummary    string    `json:"risk_summary" yaml:"risk_summary"`
	Safeguards     string    `json:"safeguards" yaml:"safeguards"`
	Status         string    `json:"status" yaml:"status"`
	ReviewDue      time.Time `json:"review_due" yaml:"review_due"`
}
type AIDeclaredSystems struct {
	Version int                `json:"version" yaml:"version"`
	Systems []AIDeclaredSystem `json:"systems" yaml:"systems"`
}

func declaredChoice(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}

func (d *AIDeclaredSystems) normalize() {
	if len(d.Systems) > 128 {
		return
	}
	for i := range d.Systems {
		d.Systems[i].Target = strings.ToLower(d.Systems[i].Target)
		for _, list := range []*[]string{&d.Systems[i].Applications, &d.Systems[i].Providers, &d.Systems[i].Models, &d.Systems[i].DataCategories} {
			if len(*list) > 16 {
				continue
			}
			if *list == nil {
				*list = []string{}
			}
			for n := range *list {
				(*list)[n] = strings.TrimSpace((*list)[n])
			}
		}
	}
}
func (d AIDeclaredSystems) validate(now time.Time) error {
	if d.Version != 1 || d.Systems == nil || len(d.Systems) > 128 {
		return bad("A version 1 registry with at most 128 declared systems is required.")
	}
	ids := map[string]bool{}
	for _, system := range d.Systems {
		if !discoveryID(system.ID) || len(system.ID) > 80 || strings.ContainsAny(system.ID, "/:") || ids[system.ID] {
			return bad("Duplicate or invalid declared system identifier.")
		}
		ids[system.ID] = true
		if !validAIGovernanceText(system.Name, 1, 160) || !validAIGovernanceText(system.Owner, 1, 200) || !validAIGovernanceText(system.Purpose, 8, 1000) || !validAIGovernanceText(system.RiskSummary, 0, 2000) || !validAIGovernanceText(system.Safeguards, 0, 2000) {
			return bad("A system name, responsible owner and purpose are required; text limits apply.")
		}
		if system.Scope != "organization" && system.Scope != "group" && system.Scope != "device" || system.Scope == "organization" && system.Target != "" || system.Scope != "organization" && !uuidPattern.MatchString(system.Target) {
			return bad("Invalid declared system scope.")
		}
		if !declaredChoice(system.Status, "planned", "review", "active", "retired") || !declaredChoice(system.RiskLevel, "unassessed", "low", "moderate", "high") || system.ReviewDue.IsZero() || system.ReviewDue.After(now.AddDate(2, 0, 0)) {
			return bad("A declared lifecycle, risk level and review date are required.")
		}
		for index, list := range [][]string{system.Applications, system.Providers, system.Models, system.DataCategories} {
			if len(list) > 16 {
				return bad("At most 16 values are accepted for each declared system list.")
			}
			seen := map[string]bool{}
			for _, value := range list {
				if seen[value] || !validAIGovernanceText(value, 1, 160) || index < 2 && !discoveryID(value) || index == 3 && !declaredChoice(value, "public", "internal", "confidential", "personal", "sensitive_personal") {
					return bad("Invalid or duplicate declared system list value.")
				}
				seen[value] = true
			}
		}
	}
	raw, err := json.Marshal(d)
	if err != nil || len(raw) > 262144 {
		return bad("Declared systems exceed the 256 KiB registry limit.")
	}
	return nil
}

func (a *App) aiGovernanceSystems(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if err := requireIndividual(r); err != nil {
		return err
	}
	document := AIDeclaredSystems{Version: 1, Systems: []AIDeclaredSystem{}}
	var revision int64
	var raw []byte
	err := tx.QueryRow(r.Context(), `SELECT revision,document FROM ai_governance_registry WHERE organization_id=$1`, s.OrganizationID).Scan(&revision, &raw)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &document); err != nil {
			return err
		}
		document.normalize()
	}
	reply(w, 200, map[string]any{"revision": revision, "document": document})
	return nil
}

func (a *App) validateAIGovernanceSystems(w http.ResponseWriter, r *http.Request, _ pgx.Tx, _ *Session) error {
	var body struct {
		Source string `json:"source"`
	}
	if err := decode(w, r, &body); err != nil {
		return err
	}
	if len(body.Source) == 0 || len(body.Source) > 262144 {
		return bad("Declared systems source exceeds its limit.")
	}
	decoder := yaml.NewDecoder(strings.NewReader(body.Source))
	decoder.KnownFields(true)
	var document AIDeclaredSystems
	if err := decoder.Decode(&document); err != nil {
		return bad("Invalid declared systems YAML.")
	}
	var tail any
	if decoder.Decode(&tail) != io.EOF {
		return bad("Only one registry document is accepted.")
	}
	document.normalize()
	if err := document.validate(time.Now()); err != nil {
		return err
	}
	reply(w, 200, map[string]any{"valid": true, "document": document})
	return nil
}

func (a *App) putAIGovernanceSystems(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if err := requireIndividual(r); err != nil {
		return err
	}
	var body struct {
		Revision int64             `json:"revision"`
		Document AIDeclaredSystems `json:"document"`
		Reason   string            `json:"reason"`
	}
	if err := decode(w, r, &body); err != nil {
		return err
	}
	body.Document.normalize()
	if err := body.Document.validate(time.Now()); err != nil {
		return err
	}
	if !validAIGovernanceText(body.Reason, 8, 1000) {
		return bad(msgReasonLengthRequired)
	}
	if err := a.requireFreshMFA(r, tx, s); err != nil {
		return err
	}
	for _, system := range body.Document.Systems {
		if system.Scope == "organization" {
			continue
		}
		query := `SELECT EXISTS(SELECT 1 FROM devices WHERE organization_id=$1 AND id=$2)`
		if system.Scope == "group" {
			query = `SELECT EXISTS(SELECT 1 FROM device_groups WHERE organization_id=$1 AND id=$2)`
		}
		var exists bool
		if err := tx.QueryRow(r.Context(), query, s.OrganizationID, system.Target).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return bad("Declared system target not found in this organization.")
		}
	}
	tag, err := tx.Exec(r.Context(), `INSERT INTO ai_governance_registry(organization_id) VALUES($1) ON CONFLICT DO NOTHING`, s.OrganizationID)
	if err != nil {
		return err
	}
	var revision int64
	if err = tx.QueryRow(r.Context(), `SELECT revision FROM ai_governance_registry WHERE organization_id=$1 FOR UPDATE`, s.OrganizationID).Scan(&revision); err != nil {
		return err
	}
	if body.Revision != revision && !(body.Revision == 0 && tag.RowsAffected() == 1) {
		return apiError{409, "revision_conflict", "Refresh the declared systems registry before saving."}
	}
	raw, err := json.Marshal(body.Document)
	if err != nil {
		return err
	}
	if err = tx.QueryRow(r.Context(), `UPDATE ai_governance_registry SET revision=nextval('shadow_revision'),document=$2,updated_at=now() WHERE organization_id=$1 RETURNING revision`, s.OrganizationID, raw).Scan(&revision); err != nil {
		return err
	}
	if err = privacyAudit(r, tx, s, "ai.governance.systems.update", "ai-systems", map[string]any{"reason": strings.TrimSpace(body.Reason), "revision": revision, "document": body.Document}); err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	reply(w, 200, map[string]any{"revision": revision, "document": body.Document})
	return nil
}
