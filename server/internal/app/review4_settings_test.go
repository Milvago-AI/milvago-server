package app

import (
	"encoding/json"
	"slices"
	"testing"
)

// Fourth review, M5: the extension and the engine refuse a destination with a port, so the
// server must not publish one that every agent would then turn into a block.
func TestRedirectDestinationRefusesAPort(t *testing.T) {
	service := func(target string) ShadowConfig {
		return ShadowConfig{Services: []ServiceConfig{{ID: "chatgpt", Domains: []string{"chatgpt.com"}, Mode: "redirect", RedirectURL: target, Enabled: true}}}
	}
	for _, target := range []string{"https://alternative.example.org:443/", "https://alternative.example.org:8443/", "https://alternative.example.org:/"} {
		if validateServiceShadow(service(target)) == nil {
			t.Fatalf("%s accepted", target)
		}
	}
	if e := validateServiceShadow(service("https://alternative.example.org/path")); e != nil {
		t.Fatal(e)
	}
}

// Fourth review, M6: the engine always keeps the keyword label, so "keyword" is no longer a
// classification choice. A stored policy that still lists it loads, the value dropped.
func TestKeywordClassificationIsIgnoredNotRefused(t *testing.T) {
	cfg, err := overlayShadow(defaultShadowConfig(), map[string]json.RawMessage{"classification": json.RawMessage(`{"browser":["iban","keyword"],"coding":["keyword"],"medical_terms":[]}`)})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.Classification.Browser, []string{"iban"}) || len(cfg.Classification.Coding) != 0 {
		t.Fatalf("keyword kept: %v %v", cfg.Classification.Browser, cfg.Classification.Coding)
	}
	if e := validateClassificationShadow(cfg); e != nil {
		t.Fatal(e)
	}
	if slices.Contains(classificationChoices, "keyword") {
		t.Fatal("keyword still offered as a classification choice")
	}
}

// A route that posts its message as binary protobuf names it; any other encoding is refused.
func TestNetworkRuleBodyFormat(t *testing.T) {
	provider := DetectionProvider{ID: "claude", Domains: []string{"claude.ai"}}
	rule := DetectionNetwork{Method: "POST", Host: "claude.ai", Path: "/rpc/Send", TextPaths: []string{"2[*].3[*]"}}
	for _, format := range []string{"", "protobuf"} {
		rule.BodyFormat = format
		if e := validateProviderNetworkRule(provider, rule); e != nil {
			t.Fatalf("%q refused: %v", format, e)
		}
	}
	for _, format := range []string{"xml", "Protobuf", "json"} {
		rule.BodyFormat = format
		if validateProviderNetworkRule(provider, rule) == nil {
			t.Fatalf("%q accepted", format)
		}
	}
}
