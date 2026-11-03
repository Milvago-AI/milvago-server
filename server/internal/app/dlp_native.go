package app

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

func sameDLPEnforcement(left, right DLPPolicy) bool {
	shape := func(policy DLPPolicy) json.RawMessage {
		rules := make([]string, 0, len(policy.Rules))
		for _, rule := range policy.Rules {
			if rule.Mode == "disabled" {
				continue
			}
			rules = append(rules, dlpRuleBehavior(rule))
		}
		slices.Sort(rules)
		detectors := make([]string, 0, len(policy.Detectors))
		for _, detector := range policy.Detectors {
			raw, _ := canonicalDLPJSON(dlpJSON(map[string]any{"id": detector.ID, "definition": detector.Definition}))
			detectors = append(detectors, string(raw))
		}
		slices.Sort(detectors)
		return dlpJSON(map[string]any{"domain": policy.Domain, "inspection": policy.Inspection, "native_inspection": policy.NativeInspection, "rules": rules, "detectors": detectors})
	}
	return string(shape(left)) == string(shape(right))
}

func nativeDLPProtection(ctx context.Context, policy DLPPolicy) (DLPPolicy, error) {
	original := policy
	policy.Rules = []DLPRule{}
	if !policy.Inspection || !policy.NativeInspection {
		return policy, nil
	}
	probe := policy
	probe.Rules = []DLPRule{}
	for _, rule := range original.Rules {
		var effect struct {
			Action string `json:"action"`
		}
		if json.Unmarshal(rule.Consequence, &effect) != nil {
			return policy, bad("Invalid DLP effect.")
		}
		if rule.Mode != "active" || effect.Action == "observe" {
			continue
		}
		rule.Application = nil
		rule.Condition = dlpJSON(map[string]string{"op": "true"})
		rule.Consequence = dlpJSON(map[string]string{"action": "block"})
		rule.Review = false
		probe.Rules = append(probe.Rules, rule)
	}
	if len(probe.Rules) == 0 {
		return policy, nil
	}
	var result struct {
		Result DLPOutput `json:"result"`
	}
	if err := dlpEngine(ctx, map[string]any{"op": "evaluate", "input": DLPInput{Policy: probe, Texts: map[string][]string{}, Facts: map[string]string{"channel": "native"}}}, &result); err != nil {
		return policy, err
	}
	for _, decision := range result.Result.Decisions {
		for _, rule := range original.Rules {
			if rule.ID == decision.RuleID {
				policy.Rules = append(policy.Rules, rule)
				break
			}
		}
	}
	return policy, nil
}

func requiresNativeDLPSupport(ctx context.Context, policy DLPPolicy) (bool, error) {
	relevant, err := nativeDLPProtection(ctx, policy)
	return len(relevant.Rules) > 0, err
}

// Delivery compatibility checks use signed device identity, never caller facts.
func dlpPolicyForDevice(policy DLPPolicy, device string, group *string) DLPPolicy {
	rules := []DLPRule{}
	for _, rule := range policy.Rules {
		target := rule.Application
		if target != nil && target.Kind != "organization" {
			actual := device
			if target.Kind == "group" || target.Kind == "groups" {
				if group == nil {
					continue
				}
				actual = *group
			}
			if !slices.ContainsFunc(dlpApplicationIDs(target), func(id string) bool { return strings.EqualFold(id, actual) }) {
				continue
			}
		}
		rules = append(rules, rule)
	}
	policy.Rules = rules
	return policy
}

// The enclosing policy scope intersects the union of active rule applications.
func dlpTargetDevicePredicate(kind, id string, policy DLPPolicy) (string, []any) {
	scope, args := dlpScopedDevicePredicate(kind, id)
	groups, devices := []string{}, []string{}
	for _, rule := range policy.Rules {
		if rule.Mode != "active" {
			continue
		}
		if rule.Application == nil || rule.Application.Kind == "organization" {
			return scope, args
		}
		if rule.Application.Kind == "group" || rule.Application.Kind == "groups" {
			groups = append(groups, dlpApplicationIDs(rule.Application)...)
		} else {
			devices = append(devices, dlpApplicationIDs(rule.Application)...)
		}
	}
	offset := len(args)
	args = append(args, groups, devices)
	return scope + fmt.Sprintf(" AND (group_id::text=ANY($%d::text[]) OR id::text=ANY($%d::text[]))", offset+1, offset+2), args
}

func closeUnqualifiedNativeDLP(config map[string]json.RawMessage) error {
	var services []map[string]any
	if raw := config["native_services"]; len(raw) > 0 {
		if json.Unmarshal(raw, &services) != nil {
			return bad("Invalid native service policy.")
		}
		for _, service := range services {
			if service["enabled"] == true {
				service["mode"] = "block"
			}
		}
		config["native_services"] = dlpJSON(services)
	} else {
		// Older installed clients share the website service projection.
		var web []map[string]any
		if json.Unmarshal(config["services"], &web) != nil {
			return bad("Invalid service policy.")
		}
		for _, service := range web {
			if service["enabled"] == true {
				service["mode"] = "block"
				delete(service, "redirect_url")
			}
		}
		config["services"] = dlpJSON(web)
	}
	config["dlp_native_unavailable"] = dlpJSON(true)
	return nil
}

func dlpScopedDevicePredicate(kind, id string) (string, []any) {
	switch kind {
	case "device":
		return " AND id=$1", []any{id}
	case "group":
		return " AND group_id=$1", []any{id}
	default:
		return "", nil
	}
}

func validNativeCapability(caps []string) bool { return slices.Contains(caps, "dlp-native-v1") }
