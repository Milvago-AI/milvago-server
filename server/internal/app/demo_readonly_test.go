package app

import "testing"

// The rule a demonstration instance runs on, checked on its own: it is applied
// before routing, so nothing else in the server would notice if it drifted.
func TestDemoRefuses(t *testing.T) {
	for _, c := range []struct {
		method, path string
		refused      bool
		why          string
	}{
		{"GET", "/api/events", false, "reading is the whole point of the instance"},
		{"GET", "/api/shadow/events/abc", false, "reading retained content stays available"},
		{"HEAD", "/api/overview", false, "HEAD is a read"},
		{"GET", "/", false, "the console shell is served"},
		{"GET", "/auth/login", false, "signing in is a redirect, not a mutation"},
		{"GET", "/auth/callback", false, "the identity provider returns here"},
		{"POST", "/auth/logout", false, "a visitor must be able to close a session on a shared screen"},
		// Moving between organizations re-points the viewer's own session and grants
		// nothing. Refusing it locked a visitor inside whichever organization the
		// sign-in happened to pick, on an instance built to show several.
		{"POST", "/api/session/organization", false, "switching organization is how a visitor reads the others"},
		{"PUT", "/api/profile", true, "registered with no permission at all, so the role does not cover it"},
		{"POST", "/api/settings", true, "settings are a mutation"},
		{"PUT", "/api/settings", true, "settings are a mutation"},
		{"DELETE", "/api/devices/11111111-1111-4111-8111-111111111111", true, "removing a device is a mutation"},
		{"POST", "/api/members/invitations", true, "inviting is a mutation"},
		{"POST", "/api/keys", true, "minting a credential is a mutation"},
		{"PATCH", "/api/privacy", true, "an unexpected method is refused, not guessed"},
		// The endpoint exists only when the instance was started with it; what it
		// serves is read-only by construction — the tool catalog admits GET console
		// routes alone — so the read-only rule does not have to refuse its envelope
		// (product decision, 2026-09-17).
		{"POST", mcpPath, false, "the model endpoint carries read-only tools, and a demonstration may publish a key for it"},
		{"PUT", mcpPath, true, "only the JSON-RPC POST is an envelope; anything else is a mutation"},
		// Ingestion is how the demonstration data arrives. It carries a device
		// credential no visitor holds, and a published instance keeps these paths
		// off its edge.
		{"POST", "/v1/enroll", false, "the synthetic fleet enrols"},
		{"POST", "/v2/events", false, "the synthetic fleet reports"},
		{"POST", "/v2/heartbeat", false, "the synthetic fleet stays visible"},
		{"POST", "/v3/enforcement", false, "endpoint routes are out of scope"},
	} {
		if got := demoRefuses(c.method, c.path); got != c.refused {
			t.Errorf("%s %s: refused=%v, want %v (%s)", c.method, c.path, got, c.refused, c.why)
		}
	}
}
