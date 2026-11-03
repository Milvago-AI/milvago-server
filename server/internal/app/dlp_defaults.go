package app

import (
	"encoding/json"
	"strconv"
)

// The library does not activate rules, inspection, collection or text retention.
func withDefaultDLPDetectors(policy DLPPolicy) DLPPolicy {
	if Edition != "commercial" {
		return policy
	}
	defaults := []struct{ category, name string }{
		{"email", "Email address"}, {"phone", "Telephone number"}, {"iban", "International bank account number (IBAN)"},
		{"card", "Payment card number"}, {"fr_nir", "French social security number (NIR)"},
		{"us_ssn", "United States Social Security Number (SSN)"}, {"ca_sin", "Canadian Social Insurance Number (SIN)"},
		{"ch_avs", "Swiss social insurance number (AHV/AVS)"}, {"ip", "IPv4 address"},
		{"source_code", "Source code"},
	}
	for _, item := range defaults {
		found := false
		for _, detector := range policy.Detectors {
			var definition struct {
				Kind     string `json:"kind"`
				Category string `json:"category"`
			}
			_ = json.Unmarshal(detector.Definition, &definition)
			category := definition.Category
			if category == "social_id" {
				category = "fr_nir"
			}
			if category == "ssn_us" {
				category = "us_ssn"
			}
			if definition.Kind == "builtin" && category == item.category {
				found = true
				break
			}
		}
		if found {
			continue
		}
		id := "builtin-" + item.category
		used := map[string]bool{}
		for _, detector := range policy.Detectors {
			used[detector.ID] = true
		}
		for suffix := 2; used[id]; suffix++ {
			id = "builtin-" + item.category + "-" + strconv.Itoa(suffix)
		}
		if len(policy.Detectors) < 256 {
			policy.Detectors = append(policy.Detectors, DLPDetector{ID: id, Name: item.name, Definition: dlpJSON(map[string]string{"kind": "builtin", "category": item.category})})
		}
	}
	return withDefaultMedicalDictionary(policy)
}
