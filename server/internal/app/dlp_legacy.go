package app

import (
	"encoding/json"
	"fmt"
)

func dlpJSON(value any) json.RawMessage { raw, _ := json.Marshal(value); return raw }

// Legacy identifiers do not contain the protected phrases or regular expressions.
func migrateLegacyDLP(config ShadowConfig) DLPPolicy {
	policy := defaultDLP("endpoint")
	policy.Inspection = config.Protection.BlockUploads || len(config.Protection.Keywords) > 0 || config.Privacy.Enabled
	policy.Journal = config.Collection.Enabled
	policy.NativeInspection = Edition == "commercial" && config.Collection.Enabled && config.Collection.StoreContent
	makeRule := func(id, name, detector, mode string, effect any, review bool) {
		condition := map[string]any{"op": "matches", "field": "prompt", "detector": detector, "minimum": 1}
		policy.Rules = append(policy.Rules, DLPRule{ID: id, Revision: 1, Name: name, Mode: "active", Priority: 100, Condition: dlpJSON(condition), Scope: dlpJSON(map[string]any{"op": "true"}), Consequence: dlpJSON(effect), Review: review, Message: config.Protection.Message})
		if mode == "off" {
			policy.Rules[len(policy.Rules)-1].Mode = "disabled"
		}
	}
	if config.Protection.BlockUploads {
		policy.Rules = append(policy.Rules, DLPRule{ID: "legacy-uploads", Revision: 1, Name: "File uploads", Mode: "active", Priority: 0, Condition: dlpJSON(map[string]any{"op": "upload"}), Scope: dlpJSON(map[string]any{"op": "true"}), Consequence: dlpJSON(map[string]any{"action": "block"}), Message: config.Protection.Message})
	}
	if len(config.Protection.Keywords) > 0 {
		policy.Detectors = append(policy.Detectors, DLPDetector{ID: "legacy-protected-phrases", Name: "Protected phrases", Definition: dlpJSON(map[string]any{"kind": "dictionary", "values": config.Protection.Keywords, "exceptions": config.Protection.Exceptions})})
		for _, item := range []struct{ tier, mode string }{{"exact", config.Protection.Exact}, {"unicode", config.Protection.Unicode}, {"fuzzy", config.Protection.Fuzzy}} {
			id := "legacy-keywords-" + item.tier
			policy.Detectors = append(policy.Detectors, DLPDetector{ID: id, Name: "Protected phrases: " + item.tier, Definition: dlpJSON(map[string]any{"kind": "keyword_tier", "dictionary": "legacy-protected-phrases", "tier": item.tier})})
			action := "observe"
			if item.mode == "block" {
				action = "block"
			}
			makeRule(id, "Protected phrases: "+item.tier, id, item.mode, map[string]any{"action": action}, false)
		}
	}
	for _, category := range config.Privacy.Types {
		id := "legacy-mask-" + category
		policy.Detectors = append(policy.Detectors, DLPDetector{ID: id, Name: category, Definition: dlpJSON(map[string]any{"kind": "builtin", "category": category})})
		mode := "off"
		if config.Privacy.Enabled {
			mode = "active"
		}
		makeRule(id, "Mask "+category, id, mode, map[string]any{"action": "mask", "detector": id, "label": upperDLP(category)}, config.Privacy.Review)
	}
	for index, custom := range config.Privacy.CustomRules {
		id := fmt.Sprintf("legacy-custom-%d", index+1)
		policy.Detectors = append(policy.Detectors, DLPDetector{ID: id, Name: custom.Label, Definition: dlpJSON(map[string]any{"kind": "regex", "pattern": custom.Pattern, "ignore_case": custom.CaseInsensitive})})
		mode := "off"
		if custom.Enabled && config.Privacy.Enabled {
			mode = "active"
		}
		makeRule(id, custom.Label, id, mode, map[string]any{"action": "mask", "detector": id, "label": custom.Label}, config.Privacy.Review)
	}
	return withDefaultDLPDetectors(policy)
}

func upperDLP(value string) string {
	bytes := []byte(value)
	for index, b := range bytes {
		if b >= 'a' && b <= 'z' {
			bytes[index] = b - 32
		}
	}
	return string(bytes)
}
