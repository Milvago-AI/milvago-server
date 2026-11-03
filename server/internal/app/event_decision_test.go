package app

import "testing"

// Real campaign 0.7.3: a blocked service, a refused file and a protected word left either no
// event or one that did not say why. Each reason is accepted only on the event it explains.
func TestEventDecisionReasonsMatchTheirEvent(t *testing.T) {
	for _, c := range []struct {
		reason, kind, action, platform string
		ok                             bool
	}{
		{"model_denied", "prompt", "blocked", "claude", true},
		{"model_denied", "prompt", "blocked", "", false},
		{"control_unavailable", "prompt", "blocked", "claude", true},
		{"service_blocked", "navigation", "blocked", "", true},
		{"service_blocked", "prompt", "blocked", "", false},
		{"service_redirected", "navigation", "redirected", "", true},
		{"service_redirected", "navigation", "blocked", "", false},
		{"upload_blocked", "prompt", "blocked", "", true},
		{"upload_blocked", "prompt", "observed", "", false},
		{"keyword", "prompt", "blocked", "", true},
		{"keyword", "response", "blocked", "", false},
		{"invented", "prompt", "blocked", "claude", false},
		{"", "prompt", "observed", "", true},
	} {
		v := V2Event{DecisionReason: c.reason, Kind: c.kind, Action: c.action, PlatformID: c.platform}
		if got := validEventDecision(&v); got != c.ok {
			t.Errorf("%s %s/%s platform %q: got %v", c.reason, c.kind, c.action, c.platform, got)
		}
	}
}
