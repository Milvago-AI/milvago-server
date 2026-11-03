package app

import (
	"context"
	"encoding/json"
)

func normalizeDLPDictionaries(ctx context.Context, policy DLPPolicy) (DLPPolicy, bool, error) {
	needed := false
	for _, detector := range policy.Detectors {
		var definition struct {
			Kind       string   `json:"kind"`
			Exceptions []string `json:"exceptions"`
		}
		if err := json.Unmarshal(detector.Definition, &definition); err != nil {
			return policy, false, err
		}
		if definition.Kind == "dictionary" && len(definition.Exceptions) > 0 {
			needed = true
		}
	}
	if !needed {
		return policy, false, nil
	}
	var result struct {
		Policy DLPPolicy `json:"policy"`
	}
	if err := dlpEngine(ctx, map[string]any{"op": "normalize", "policy": policy}, &result); err != nil {
		return policy, false, err
	}
	return result.Policy, true, nil
}
