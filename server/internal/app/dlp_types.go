package app

import "encoding/json"

type DLPDetector struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Definition json.RawMessage `json:"definition"`
}

type DLPApplication struct {
	Kind string   `json:"kind"`
	ID   string   `json:"id,omitempty"`
	IDs  []string `json:"ids,omitempty"`
}

type DLPRule struct {
	Application *DLPApplication `json:"application,omitempty"`
	ID          string          `json:"id"`
	Revision    int64           `json:"revision"`
	Name        string          `json:"name"`
	Mode        string          `json:"mode"`
	Priority    int             `json:"priority"`
	Condition   json.RawMessage `json:"condition"`
	Scope       json.RawMessage `json:"scope"`
	Consequence json.RawMessage `json:"consequence"`
	Review      bool            `json:"review"`
	Message     string          `json:"message"`
}

type DLPPolicy struct {
	SchemaVersion    int           `json:"schema_version"`
	Domain           string        `json:"domain"`
	Inspection       bool          `json:"inspection"`
	NativeInspection bool          `json:"native_inspection"`
	Journal          bool          `json:"journal"`
	Detectors        []DLPDetector `json:"detectors"`
	Rules            []DLPRule     `json:"rules"`
}

type DLPDecision struct {
	RuleID       string `json:"rule_id"`
	RuleRevision int64  `json:"rule_revision"`
	RuleName     string `json:"rule_name"`
	Mode         string `json:"mode"`
	Consequence  string `json:"consequence"`
	Condition    string `json:"condition"`
	Scope        string `json:"scope"`
	Outcome      string `json:"outcome"`
	Occurrences  int    `json:"occurrences"`
}

type DLPInput struct {
	Policy DLPPolicy           `json:"policy"`
	Texts  map[string][]string `json:"texts"`
	Facts  map[string]string   `json:"facts"`
	Upload *bool               `json:"upload"`
}

type DLPOutput struct {
	Action       string              `json:"action"`
	Texts        map[string][]string `json:"texts"`
	Decisions    []DLPDecision       `json:"decisions"`
	Reason       string              `json:"reason"`
	Transformed  bool                `json:"transformed"`
	Confirmation bool                `json:"confirmation,omitempty"`
}

type DLPScopeChoice struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}
type DLPScopeOptions struct {
	Browsers     []DLPScopeChoice `json:"browsers"`
	Services     []DLPScopeChoice `json:"services"`
	Applications []DLPScopeChoice `json:"applications"`
}

type DLPSettings struct {
	DefaultRuleIDs []string        `json:"default_rule_ids"`
	ScopeOptions   DLPScopeOptions `json:"scope_options"`
	Revision       int64           `json:"revision"`
	Policy         DLPPolicy       `json:"policy"`
	Inherited      bool            `json:"inherited"`
	InheritedFrom  string          `json:"inherited_from,omitempty"`
	Fingerprint    string          `json:"fingerprint"`
	Capabilities   map[string]bool `json:"capabilities"`
}

func defaultDLP(domain string) DLPPolicy {
	return DLPPolicy{SchemaVersion: 1, Domain: domain, Inspection: false, Journal: true, Detectors: []DLPDetector{}, Rules: []DLPRule{}}
}
