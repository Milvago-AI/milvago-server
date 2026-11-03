package app

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
)

func dlpHasConfirmation(policy DLPPolicy, activeOnly bool) bool {
	if activeOnly && !policy.Inspection {
		return false
	}
	return slices.ContainsFunc(policy.Rules, func(rule DLPRule) bool {
		var effect struct {
			Action string `json:"action"`
		}
		_ = json.Unmarshal(rule.Consequence, &effect)
		return effect.Action == "warn" && (!activeOnly || rule.Mode == "active")
	})
}

func dlpConsequenceDependencies(rule DLPRule, detectors map[string]json.RawMessage) []string {
	found := map[string]bool{}
	var visit func(any)
	visit = func(value any) {
		switch item := value.(type) {
		case map[string]any:
			if id, ok := item["detector"].(string); ok {
				found[id] = true
			}
			for _, child := range item {
				visit(child)
			}
		case []any:
			for _, child := range item {
				visit(child)
			}
		}
	}
	for _, raw := range []json.RawMessage{rule.Condition, rule.Consequence} {
		var value any
		_ = json.Unmarshal(raw, &value)
		visit(value)
	}
	for id := range found {
		var definition struct {
			Dictionary string `json:"dictionary"`
		}
		_ = json.Unmarshal(detectors[id], &definition)
		if definition.Dictionary != "" {
			found[definition.Dictionary] = true
		}
	}
	ids := []string{}
	for id := range found {
		ids = append(ids, id)
	}
	return ids
}

func validateDLPConsequenceChanges(ctx context.Context, before, next DLPPolicy) error {
	oldRules := map[string]DLPRule{}
	oldDefinitions := map[string]json.RawMessage{}
	definitions := map[string]json.RawMessage{}
	for _, rule := range before.Rules {
		oldRules[rule.ID] = rule
	}
	for _, detector := range before.Detectors {
		oldDefinitions[detector.ID] = detector.Definition
	}
	for _, detector := range next.Detectors {
		definitions[detector.ID] = detector.Definition
	}
	for _, rule := range next.Rules {
		previous, exists := oldRules[rule.ID]
		changed := !exists || dlpRuleBehavior(previous) != dlpRuleBehavior(rule) || previous.Message != rule.Message
		for _, id := range dlpConsequenceDependencies(rule, definitions) {
			oldJSON, _ := canonicalDLPJSON(oldDefinitions[id])
			newJSON, _ := canonicalDLPJSON(definitions[id])
			changed = changed || string(oldJSON) != string(newJSON)
		}
		// Existing advanced policies keep their behavior until the affected rule or
		// a detector it uses changes. Renaming unrelated library objects is harmless.
		if !changed || rule.Mode == "disabled" {
			continue
		}
		var result struct {
			Options struct {
				Valid bool   `json:"valid"`
				Error string `json:"error"`
			} `json:"options"`
		}
		if err := dlpEngine(ctx, map[string]any{"op": "consequences", "policy": next, "rule": rule}, &result); err != nil {
			return err
		}
		if !result.Options.Valid {
			return apiError{400, "dlp_consequence_incompatible", "The consequence is incompatible with this rule: " + strings.ReplaceAll(result.Options.Error, "_", " ") + "."}
		}
	}
	return nil
}

func dlpConfirmationPolicy(policy DLPPolicy) DLPPolicy {
	rules := []DLPRule{}
	for _, rule := range policy.Rules {
		var effect struct {
			Action string `json:"action"`
		}
		_ = json.Unmarshal(rule.Consequence, &effect)
		if rule.Mode == "active" && effect.Action == "warn" {
			rules = append(rules, rule)
		}
	}
	policy.Rules = rules
	return policy
}
