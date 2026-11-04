package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

//go:embed dlp_migration.sql
var dlpMigration string

func initializeDLP(ctx context.Context, tx pgx.Tx, role string) error {
	if _, err := tx.Exec(ctx, dlpMigration); err != nil {
		return fmt.Errorf("DLP migration: %w", err)
	}
	_, err := tx.Exec(ctx, `GRANT SELECT,INSERT,UPDATE,DELETE ON dlp_settings,dlp_policy_snapshots,dlp_decisions,dlp_enforcement,dlp_device_policy_versions,dlp_device_policy_history TO `+role+`; GRANT USAGE,SELECT ON SEQUENCE dlp_policy_revision TO `+role)
	if err != nil {
		return err
	}
	if err := seedBootstrapDLPDefaults(ctx, tx); err != nil {
		return err
	}
	if err := seedStoredDLPTemplates(ctx, tx); err != nil {
		return err
	}
	return initializeDLPDefaultRuleProtection(ctx, tx)
}

func (a *App) registerDLPRoutes() {
	a.console("GET /api/dlp/settings", permPolicyManage, a.dlpSettings)
	a.console("PUT /api/dlp/settings", permPolicyManage, a.putDLPSettings)
	for _, scope := range []string{"groups", "devices"} {
		a.console("GET /api/"+scope+"/{id}/dlp", permPolicyManage, a.dlpSettings)
		a.console("PUT /api/"+scope+"/{id}/dlp", permPolicyManage, a.putDLPSettings)
	}
	a.console("POST /api/dlp/compile", permPolicyManage, a.compileDLP)
	a.console("POST /api/dlp/evaluate", permPolicyManage, a.evaluateDLP)
	a.console("GET /api/dlp/status", permPolicyManage, a.dlpStatus)
	a.console("GET /api/dlp/decisions", permEventsRead, a.dlpDecisions)
}

func dlpFingerprint(policy DLPPolicy) string {
	raw, _ := json.Marshal(policy)
	raw, _ = canonicalDLPJSON(raw)
	return dlpBytesFingerprint(raw)
}

func dlpBytesFingerprint(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func dlpScope(r *http.Request, s *Session) (domain, kind, id string, err error) {
	domain, kind, id = r.URL.Query().Get("domain"), "organization", s.OrganizationID
	if domain == "" {
		domain = "endpoint"
	}
	if domain != "endpoint" {
		err = bad("Only endpoint DLP is available.")
		return
	}
	if r.PathValue("id") != "" {
		id = r.PathValue("id")
		if !uuidPattern.MatchString(id) || domain != "endpoint" {
			err = bad("Invalid DLP scope.")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/groups/") {
			kind = "group"
		} else {
			kind = "device"
		}
	}
	return
}

func (a *App) readDLP(ctx context.Context, tx pgx.Tx, org, domain, kind, id string, depth int) (DLPSettings, error) {
	if depth > 24 {
		return DLPSettings{}, bad("DLP inheritance is too deep.")
	}
	memo, _ := ctx.Value(dlpReadMemoKey{}).(*dlpReadMemo)
	key := [4]string{org, domain, kind, id}
	if kind != "device" {
		if cached, ok := memo.get(key); ok {
			return cached, nil
		}
	}
	out, err := a.readDLPResolved(ctx, tx, org, domain, kind, id, depth)
	if err != nil {
		return out, err
	}
	policy, changed, err := normalizeDLPDictionaries(ctx, out.Policy)
	if err != nil {
		return out, err
	}
	if changed {
		out.Policy = policy
		out.Fingerprint = dlpFingerprint(policy)
	}
	if kind != "device" {
		memo.put(key, out)
	}
	return out, nil
}

func (a *App) readDLPResolved(ctx context.Context, tx pgx.Tx, org, domain, kind, id string, depth int) (DLPSettings, error) {
	if depth > 24 {
		return DLPSettings{}, bad("DLP inheritance is too deep.")
	}
	out := DLPSettings{ScopeOptions: dlpScopeOptions(), Policy: defaultDLP(domain), Capabilities: map[string]bool{"native": Edition == "commercial", "mcp": Edition == "commercial", "builtins": Edition == "commercial", "patterns": true, "classification": Edition == "commercial"}}
	var group *string
	if kind != "organization" {
		var found bool
		if kind == "device" {
			if err := tx.QueryRow(ctx, `SELECT group_id FROM devices WHERE id=$1`, id).Scan(&group); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return out, apiError{404, "not_found", "DLP scope not found."}
				}
				return out, err
			}
		} else {
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM device_groups WHERE id=$1)`, id).Scan(&found); err != nil {
				return out, err
			}
			if !found {
				return out, apiError{404, "not_found", "DLP scope not found."}
			}
		}
	}
	var raw []byte
	var inherited bool
	var localRevision int64
	err := tx.QueryRow(ctx, `SELECT revision,policy,inherited FROM dlp_settings WHERE domain=$1 AND scope_kind=$2 AND scope_id=$3`, domain, kind, id).Scan(&localRevision, &raw, &inherited)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return out, err
	}
	if err == nil && !inherited {
		if json.Unmarshal(raw, &out.Policy) != nil {
			return out, errors.New("stored DLP policy is invalid")
		}
		out.Policy = withDefaultDLPDetectors(out.Policy)
		out.DefaultRuleIDs, err = readDLPDefaultRules(ctx, tx, domain, kind, id)
		if err != nil {
			return out, err
		}
		out.Revision = localRevision
		out.Fingerprint = dlpFingerprint(out.Policy)
		return out, nil
	}
	if kind != "organization" {
		parentKind, parentID := "organization", org
		if group != nil {
			parentKind, parentID = "group", *group
		}
		parent, e := a.readDLP(ctx, tx, org, domain, parentKind, parentID, depth+1)
		if e != nil {
			return out, e
		}
		// Preserve legacy section overrides until this scope explicitly adopts its DLP policy.
		if errors.Is(err, pgx.ErrNoRows) && domain == "endpoint" {
			var overridden bool
			query := `SELECT EXISTS(SELECT 1 FROM shadow_group_overrides WHERE group_id=$1 AND configuration ?| ARRAY['protection','privacy'])`
			if kind == "device" {
				query = `SELECT EXISTS(SELECT 1 FROM shadow_device_overrides WHERE device_id=$1 AND configuration ?| ARRAY['protection','privacy'])`
			}
			if e = tx.QueryRow(ctx, query, id).Scan(&overridden); e != nil {
				return out, e
			}
			if overridden {
				var legacy ShadowSettings
				if kind == "device" {
					legacy, e = a.effectiveShadow(ctx, tx, org, id)
				} else {
					legacy, e = a.groupShadow(ctx, tx, org, id)
				}
				if e != nil {
					return out, e
				}
				migrated := migrateLegacyDLP(legacy.Config)
				out.Policy, e = previewDLPTemplates(ctx, tx, org, migrated)
				if e != nil {
					return out, e
				}
				out.DefaultRuleIDs = defaultDLPTemplateIDs(out.Policy)
				migrated = out.Policy
				out.Fingerprint = dlpFingerprint(migrated)
				out.Revision = max(localRevision, legacy.Revision)
				out.Inherited = false
				out.InheritedFrom = "legacy:" + kind + ":" + id
				return out, nil
			}
		}
		parent.Inherited, parent.InheritedFrom = true, parentKind+":"+parentID
		parent.Revision = max(parent.Revision, localRevision)
		return parent, nil
	}
	if inherited && Edition == "commercial" {
		var parent *string
		if err = tx.QueryRow(ctx, `SELECT parent_id FROM organizations WHERE id=$1`, org).Scan(&parent); err != nil {
			return out, err
		}
		if parent != nil {
			if _, err = tx.Exec(ctx, sqlSetOrganizationContext, *parent); err != nil {
				return out, err
			}
			value, e := a.readDLP(ctx, tx, *parent, domain, "organization", *parent, depth+1)
			_, restore := tx.Exec(ctx, sqlSetOrganizationContext, org)
			if e != nil {
				return out, e
			}
			if restore != nil {
				return out, restore
			}
			value.Inherited, value.InheritedFrom = true, "organization:"+*parent
			value.Revision = max(value.Revision, localRevision)
			return value, nil
		}
	}
	out.Revision = localRevision
	if domain == "endpoint" {
		legacy, e := a.readShadow(ctx, tx, org, 0)
		if e != nil {
			return out, e
		}
		out.Policy, e = previewDLPTemplates(ctx, tx, org, migrateLegacyDLP(legacy.Config))
		if e != nil {
			return out, e
		}
		out.Revision = max(out.Revision, legacy.Revision)
	}
	out.DefaultRuleIDs = defaultDLPTemplateIDs(out.Policy)
	out.Fingerprint = dlpFingerprint(out.Policy)
	return out, nil
}

func (a *App) dlpSettings(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	domain, kind, id, err := dlpScope(r, s)
	if err != nil {
		return err
	}
	out, err := a.readDLP(r.Context(), tx, s.OrganizationID, domain, kind, id, 0)
	if err != nil {
		return err
	}
	reply(w, 200, out)
	return nil
}

func validateDLPEdition(policy DLPPolicy) error {
	if Edition == "commercial" {
		return nil
	}
	if policy.NativeInspection {
		return apiError{409, "capability_unavailable", "Native DLP inspection requires the Enterprise edition."}
	}
	for _, d := range policy.Detectors {
		var kind struct {
			Kind string `json:"kind"`
		}
		_ = json.Unmarshal(d.Definition, &kind)
		if kind.Kind == "builtin" {
			return apiError{409, "capability_unavailable", "Built-in DLP detectors require the Enterprise edition."}
		}
	}
	for _, r := range policy.Rules {
		for _, expression := range []json.RawMessage{r.Scope, r.Condition} {
			var value any
			if json.Unmarshal(expression, &value) != nil {
				return bad("Invalid DLP expression.")
			}
			var inspect func(any) bool
			inspect = func(value any) bool {
				switch item := value.(type) {
				case map[string]any:
					if field, _ := item["field"].(string); field == "model" || field == "client_id" {
						return true
					}
					if field, _ := item["field"].(string); field == "channel" {
						if v, _ := item["value"].(string); v == "native" || v == "mcp" {
							return true
						}
						if values, ok := item["values"].([]any); ok {
							for _, v := range values {
								if v == "native" || v == "mcp" {
									return true
								}
							}
						}
					}
					for _, v := range item {
						if inspect(v) {
							return true
						}
					}
				case []any:
					for _, v := range item {
						if inspect(v) {
							return true
						}
					}
				}
				return false
			}
			if inspect(value) {
				return apiError{409, "capability_unavailable", "This DLP scope requires the Enterprise edition."}
			}
		}
	}
	return nil
}

func dlpRuleBehavior(rule DLPRule) string {
	rule.Name = ""
	rule.Message = ""
	rule.Revision = 1
	raw, _ := json.Marshal(rule)
	raw, _ = canonicalDLPJSON(raw)
	return string(raw)
}

func canonicalDLPJSON(raw []byte) ([]byte, error) {
	// A logical AST level contains both an object and a children array. A
	// valid depth-16 policy needs room for both representations.
	value, err := decodeDLPJSONLimits(raw, 64, 50000)
	if err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func newActiveDLP(old, next DLPPolicy) bool {
	if !next.Inspection {
		return false
	}
	if !old.Inspection {
		return slices.ContainsFunc(next.Rules, func(r DLPRule) bool { return r.Mode == "active" })
	}
	if !old.NativeInspection && next.NativeInspection && slices.ContainsFunc(next.Rules, func(r DLPRule) bool { return r.Mode == "active" }) {
		return true
	}
	before := map[string]string{}
	for _, rule := range old.Rules {
		before[rule.ID] = dlpRuleBehavior(rule)
	}
	for _, rule := range next.Rules {
		if rule.Mode == "active" && before[rule.ID] != dlpRuleBehavior(rule) {
			return true
		}
	}
	// Removing or disabling another rule is not a new activation. Changes to
	// shared detectors can still change an otherwise identical active rule.
	beforeDetectors := DLPPolicy{Domain: old.Domain, Detectors: old.Detectors}
	afterDetectors := DLPPolicy{Domain: next.Domain, Detectors: next.Detectors}
	return !sameDLPEnforcement(beforeDetectors, afterDetectors) && slices.ContainsFunc(next.Rules, func(r DLPRule) bool { return r.Mode == "active" })
}

func (a *App) putDLPSettings(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	domain, kind, id, err := dlpScope(r, s)
	if err != nil {
		return err
	}
	var body struct {
		Revision  int64     `json:"revision"`
		Policy    DLPPolicy `json:"policy"`
		Inherited bool      `json:"inherited"`
	}
	if err = decode(w, r, &body); err != nil {
		return err
	}
	if body.Policy.Domain != domain {
		return bad("DLP domain and policy disagree.")
	}
	if err = validateDLPEdition(body.Policy); err != nil {
		return err
	}
	if err = dlpEngine(r.Context(), map[string]any{"op": "validate", "policy": body.Policy}, nil); err != nil {
		return err
	}
	if body.Policy, _, err = normalizeDLPDictionaries(r.Context(), body.Policy); err != nil {
		return err
	}
	if _, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtextextended($1,72))`, s.OrganizationID); err != nil {
		return err
	}
	old, err := a.readDLP(r.Context(), tx, s.OrganizationID, domain, kind, id, 0)
	if err != nil {
		return err
	}
	if old.Revision != body.Revision {
		return apiError{409, "revision_conflict", "Configuration changed; reload before saving."}
	}
	var defaultIDs []string
	var preserveLocal bool
	body.Policy, defaultIDs, preserveLocal, err = protectDLPDefaultRules(r.Context(), tx, domain, kind, id, old, body.Policy, body.Inherited)
	if err != nil {
		return err
	}
	if preserveLocal {
		if err = dlpEngine(r.Context(), map[string]any{"op": "validate", "policy": body.Policy}, nil); err != nil {
			return err
		}
	}
	if body.Inherited && kind == "organization" {
		var hasParent bool
		if Edition != "commercial" {
			return bad("This organization has no parent.")
		}
		if err = tx.QueryRow(r.Context(), `SELECT parent_id IS NOT NULL FROM organizations WHERE id=$1`, s.OrganizationID).Scan(&hasParent); err != nil {
			return err
		}
		if !hasParent {
			return bad("This organization has no parent.")
		}
	}

	groups, devices := map[string]bool{}, map[string]bool{}
	for _, rule := range body.Policy.Rules {
		target := rule.Application
		if target == nil || target.Kind == "organization" {
			continue
		}
		target.ID = strings.ToLower(target.ID)
		for index, id := range target.IDs {
			target.IDs[index] = strings.ToLower(id)
		}
		for _, id := range dlpApplicationIDs(target) {
			if target.Kind == "group" || target.Kind == "groups" {
				groups[id] = true
			} else {
				devices[id] = true
			}
		}
	}
	if !body.Inherited {
		for _, selection := range []struct {
			table string
			ids   map[string]bool
		}{{"device_groups", groups}, {"devices", devices}} {
			if len(selection.ids) == 0 {
				continue
			}
			ids := make([]string, 0, len(selection.ids))
			for id := range selection.ids {
				ids = append(ids, id)
			}
			var found int
			if err = tx.QueryRow(r.Context(), "SELECT count(*) FROM "+selection.table+" WHERE id::text=ANY($1::text[])", ids).Scan(&found); err != nil {
				return err
			}
			if found != len(ids) {
				return apiError{404, "dlp_application_not_found", "One or more rule targets are unavailable in this organization."}
			}
		}
	}
	body.Policy = withDefaultDLPDetectors(body.Policy)
	if err = validateDLPConsequenceChanges(r.Context(), old.Policy, body.Policy); err != nil {
		return err
	}
	oldDetectors, _ := canonicalDLPJSON(dlpJSON(old.Policy.Detectors))
	nextDetectors, _ := canonicalDLPJSON(dlpJSON(body.Policy.Detectors))
	detectorsChanged := !bytes.Equal(oldDetectors, nextDetectors)
	for index := range body.Policy.Rules {
		if preserveLocal {
			continue
		}
		rule := &body.Policy.Rules[index]
		found := false
		for _, previous := range old.Policy.Rules {
			if previous.ID == rule.ID {
				found = true
				expected := previous.Revision
				if detectorsChanged || dlpRuleBehavior(previous) != dlpRuleBehavior(*rule) || previous.Name != rule.Name || previous.Message != rule.Message {
					expected++
				}
				if rule.Revision != previous.Revision && rule.Revision != expected {
					return bad("Invalid rule revision.")
				}
				rule.Revision = expected
				break
			}
		}
		if !found {
			rule.Revision = 1
		}
	}
	raw, _ := json.Marshal(body.Policy)
	var device, group any
	if kind == "device" {
		device = id
	}
	if kind == "group" {
		group = id
	}
	if _, err = tx.Exec(r.Context(), `INSERT INTO dlp_settings(organization_id,domain,scope_kind,scope_id,device_id,group_id,policy,inherited,default_rule_ids) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(organization_id,domain,scope_kind,scope_id) DO UPDATE SET policy=excluded.policy,inherited=excluded.inherited,default_rule_ids=excluded.default_rule_ids,revision=nextval('shadow_revision'),updated_at=now()`, s.OrganizationID, domain, kind, id, device, group, raw, body.Inherited, dlpJSON(defaultIDs)); err != nil {
		return err
	}
	effectiveNext, err := a.readDLP(r.Context(), tx, s.OrganizationID, domain, kind, id, 0)
	if err != nil {
		return err
	}
	if err = validateDLPEdition(effectiveNext.Policy); err != nil {
		return err
	}
	if err = dlpEngine(r.Context(), map[string]any{"op": "validate", "policy": effectiveNext.Policy}, nil); err != nil {
		return err
	}
	if domain == "endpoint" && newActiveDLP(old.Policy, effectiveNext.Policy) {
		var incompatible bool
		scope, args := dlpTargetDevicePredicate(kind, id, effectiveNext.Policy)
		query := `SELECT EXISTS(SELECT 1 FROM devices WHERE status<>'revoked' AND NOT (capabilities ? 'dlp-v1')` + scope + `)`
		if err = tx.QueryRow(r.Context(), query, args...).Scan(&incompatible); err != nil {
			return err
		}
		if incompatible {
			return apiError{409, "dlp_update_required", "Update the targeted agents before activating this protection."}
		}

		if dlpHasConfirmation(effectiveNext.Policy, true) {
			// Confirmation and contextual dictionaries have independent support.
			scope, args := dlpTargetDevicePredicate(kind, id, dlpConfirmationPolicy(effectiveNext.Policy))
			if err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM devices WHERE status<>'revoked' AND NOT (capabilities ? 'dlp-confirm-v1')`+scope+`)`, args...).Scan(&incompatible); err != nil {
				return err
			}
			if incompatible {
				return apiError{409, "dlp_confirmation_update_required", "Update the targeted agents before requiring confirmation. Older agents keep affected sends blocked."}
			}
		}
		if err = requireDLPContextTargets(r.Context(), tx, kind, id, effectiveNext.Policy); err != nil {
			return err
		}
		nativePolicy, e := nativeDLPProtection(r.Context(), effectiveNext.Policy)
		if e != nil {
			return e
		}
		if len(nativePolicy.Rules) > 0 {
			scope, args := dlpTargetDevicePredicate(kind, id, nativePolicy)
			if err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM devices WHERE status<>'revoked' AND kind='native' AND NOT (capabilities ? 'dlp-native-v1')`+scope+`)`, args...).Scan(&incompatible); err != nil {
				return err
			}
			if incompatible {
				return apiError{409, "dlp_native_unqualified", "Native prevention is not qualified for these installations. Use simulation until their control component is qualified."}
			}
		}
	}
	if err = ensureDLPSnapshot(r.Context(), tx, s.OrganizationID, effectiveNext.Policy); err != nil {
		return err
	}
	if err = audit(r.Context(), tx, s.OrganizationID, s.UserID, "dlp.settings.update", id); err != nil {
		return err
	}
	out, err := a.readDLP(r.Context(), tx, s.OrganizationID, domain, kind, id, 0)
	if err != nil {
		return err
	}
	if err = tx.Commit(r.Context()); err != nil {
		return err
	}
	reply(w, 200, out)
	return nil
}

func (a *App) compileDLP(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	var body struct {
		Source *string  `json:"source"`
		Rule   *DLPRule `json:"rule"`
	}
	if err := decode(w, r, &body); err != nil {
		return err
	}
	if (body.Source == nil) == (body.Rule == nil) {
		return bad("Provide either source or a rule.")
	}
	request := map[string]any{"op": "parse", "source": body.Source}
	if body.Rule != nil {
		request = map[string]any{"op": "format", "rule": body.Rule}
	}
	var result json.RawMessage
	if err := dlpEngine(r.Context(), request, &result); err != nil {
		return err
	}
	reply(w, 200, result)
	return nil
}

func (a *App) evaluateDLP(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	var input DLPInput
	if err := decode(w, r, &input); err != nil {
		return err
	}
	if err := validateDLPEdition(input.Policy); err != nil {
		return err
	}
	var result struct {
		Result DLPOutput `json:"result"`
	}
	if err := dlpEngine(r.Context(), map[string]any{"op": "evaluate", "input": input}, &result); err != nil {
		return err
	}
	reply(w, 200, result.Result)
	return nil
}
