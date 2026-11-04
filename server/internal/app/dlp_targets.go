package app

import (
	"encoding/json"
	"slices"
	"strings"
)

func dlpApplicationIDs(target *DLPApplication) []string {
	if target == nil || target.Kind == "organization" {
		return nil
	}
	values := target.IDs
	if target.Kind == "group" || target.Kind == "device" {
		values = []string{target.ID}
	}
	out := make([]string, len(values))
	for index, id := range values {
		out[index] = strings.ToLower(id)
	}
	return out
}

// Multi-target metadata compiles to the existing signed scope language. Older
// v4 engines already support IN and receive neither new variants nor extra rules.
func dlpDeliverySettings(settings DLPSettings, capabilities ...[]string) DLPSettings {
	policy := settings.Policy
	contextChanged := false
	if len(capabilities) > 0 {
		policy, contextChanged = dlpContextDelivery(policy, capabilities[0])
	}
	rules := append([]DLPRule{}, policy.Rules...)
	changed := contextChanged
	for index, rule := range rules {
		var effect struct {
			Action string `json:"action"`
		}
		_ = json.Unmarshal(rule.Consequence, &effect)
		if len(capabilities) > 0 && !slices.Contains(capabilities[0], "dlp-confirm-v1") && effect.Action == "warn" {
			rule.Consequence = dlpJSON(map[string]string{"action": "block"})
			rule.Review = false
			rule.Message = "Update Milvago before confirming this submission."
			rules[index] = rule
			changed = true
		}
		target := rule.Application
		if target == nil || (target.Kind != "groups" && target.Kind != "devices") {
			continue
		}
		field := "device_id"
		if target.Kind == "groups" {
			field = "group_id"
		}
		restriction := map[string]any{"op": "in", "field": field, "values": dlpApplicationIDs(target)}
		rule.Scope = dlpJSON(map[string]any{"op": "all", "children": []any{rule.Scope, restriction}})
		rule.Application = nil
		rules[index] = rule
		changed = true
	}
	if changed {
		policy.Rules = rules
		settings.Policy = policy
		settings.Fingerprint = dlpFingerprint(policy)
	}
	return settings
}
