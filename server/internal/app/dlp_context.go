package app

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/jackc/pgx/v5"
)

// Unsupported clients receive a bounded, explicit prevention fallback rather
// than a policy containing variants their parser cannot understand.
func dlpContextDelivery(policy DLPPolicy, caps []string) (DLPPolicy, bool) {
	if slices.Contains(caps, "dlp-contextual-v1") {
		return policy, false
	}
	definitions := map[string]DLPDetector{}
	for _, d := range policy.Detectors {
		definitions[d.ID] = d
	}
	unsupported := map[string]bool{}
	detectors := make([]DLPDetector, 0, len(policy.Detectors))
	changed := false
	for _, d := range policy.Detectors {
		var def struct {
			Kind       string
			Dictionary string
			Minimum    int
		}
		if json.Unmarshal(d.Definition, &def) != nil || def.Kind != "dictionary_context" {
			detectors = append(detectors, d)
			continue
		}
		changed = true
		if legacy, ok := dlpLegacyContextDefinition(d, definitions); ok {
			d.Definition = legacy
			detectors = append(detectors, d)
		} else {
			unsupported[d.ID] = true
		}
	}
	if !changed {
		return policy, false
	}
	rules := append([]DLPRule{}, policy.Rules...)
	raw := map[string]json.RawMessage{}
	for _, d := range policy.Detectors {
		raw[d.ID] = d.Definition
	}
	for i, rule := range rules {
		affected := false
		for _, id := range dlpConsequenceDependencies(rule, raw) {
			affected = affected || unsupported[id]
		}
		if !affected {
			continue
		}
		var effect struct{ Action string }
		_ = json.Unmarshal(rule.Consequence, &effect)
		if rule.Mode == "active" && effect.Action != "observe" {
			rule.Condition = dlpJSON(map[string]string{"op": "true"})
			rule.Consequence = dlpJSON(map[string]string{"action": "block"})
			rule.Review = false
			rule.Message = "Update Milvago to apply contextual dictionary protection."
		} else {
			// An unsupported simulation or audit must not manufacture a term match.
			rule.Condition = dlpJSON(map[string]any{"op": "not", "child": map[string]string{"op": "true"}})
		}
		rules[i] = rule
	}
	policy.Detectors = detectors
	policy.Rules = rules
	return policy, true
}

func dlpContextRequiredPolicy(policy DLPPolicy) DLPPolicy {
	definitions := map[string]DLPDetector{}
	raw := map[string]json.RawMessage{}
	for _, d := range policy.Detectors {
		definitions[d.ID] = d
		raw[d.ID] = d.Definition
	}
	unsupported := map[string]bool{}
	for _, d := range policy.Detectors {
		var def struct{ Kind string }
		_ = json.Unmarshal(d.Definition, &def)
		if def.Kind == "dictionary_context" {
			_, legacy := dlpLegacyContextDefinition(d, definitions)
			unsupported[d.ID] = !legacy
		}
	}
	rules := []DLPRule{}
	for _, rule := range policy.Rules {
		if rule.Mode != "active" {
			continue
		}
		for _, id := range dlpConsequenceDependencies(rule, raw) {
			if unsupported[id] {
				rules = append(rules, rule)
				break
			}
		}
	}
	policy.Rules = rules
	return policy
}

func requireDLPContextTargets(ctx context.Context, tx pgx.Tx, kind, id string, policy DLPPolicy) error {
	required := dlpContextRequiredPolicy(policy)
	if !policy.Inspection || len(required.Rules) == 0 {
		return nil
	}
	scope, args := dlpTargetDevicePredicate(kind, id, required)
	var incompatible bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM devices WHERE status<>'revoked' AND NOT (capabilities ? 'dlp-contextual-v1')`+scope+`)`, args...).Scan(&incompatible); err != nil {
		return err
	}
	if incompatible {
		return apiError{409, "dlp_contextual_update_required", "Update the targeted agents and browser extensions before activating contextual dictionary protection."}
	}
	return nil
}
