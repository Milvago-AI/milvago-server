//go:build !commercial

package app

import "encoding/json"

func dlpLegacyContextDefinition(DLPDetector, map[string]DLPDetector) (json.RawMessage, bool) {
	return nil, false
}
func withDefaultMedicalDictionary(policy DLPPolicy) DLPPolicy { return policy }
