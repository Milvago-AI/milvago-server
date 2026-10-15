package app

import (
	"testing"
	"time"
)

// The account state a record carries is a closed vocabulary, on the event, on the late
// completion and on the catalogue rule that states it. Signed-out ChatGPT names no model,
// so this field is what the console reads instead; a free label would let a device invent one.
func TestSessionStateIsAClosedVocabulary(t *testing.T) {
	t.Run("event and completion", sessionStateEventAndCompletion)
	t.Run("catalogue rule", sessionStateCatalogueRule)
	t.Run("conversation paths", sessionStateConversationPaths)
	t.Run("presence record", func(t *testing.T) {
		// A presence record reduces to the platform: no account state survives on it.
		presence := sessionTestEvent("signed_out")
		reducedToPresence(presence)
		if presence.Session != "" {
			t.Fatal("presence kept an account state")
		}
	})
}

const sessionTestID = "11111111-1111-4111-8111-111111111111"

func sessionTestEvent(session string) *V2Event {
	return &V2Event{ID: sessionTestID, Kind: "prompt", OccurredAt: time.Now(), Provider: "chatgpt.com", Source: "browser", Tool: "firefox", Action: "observed", Labels: []string{}, PolicyRevision: 1, Session: session}
}

func sessionTestProvider() DetectionProvider {
	return DetectionProvider{ID: "chatgpt", Label: "ChatGPT", Domains: []string{"chatgpt.com"}, ConversationPath: "/c/*", ConversationSegment: 1, QualifiedAt: "2026-09-11T00:00:00Z"}
}

func sessionStateEventAndCompletion(t *testing.T) {
	for _, s := range []string{"", "signed_in", "signed_out"} {
		if e := validateV2(sessionTestEvent(s), time.Now()); e != nil {
			t.Fatalf("session %q refused: %v", s, e)
		}
		if s != "" {
			if e := validateCompletion(V2Completion{ID: sessionTestID, Session: s}); e != nil {
				t.Fatalf("completion session %q refused: %v", s, e)
			}
		}
	}
	for _, s := range []string{"anonymous", "free", "Signed_out"} {
		if validateV2(sessionTestEvent(s), time.Now()) == nil {
			t.Fatalf("event session %q accepted", s)
		}
		if validateCompletion(V2Completion{ID: sessionTestID, Session: s}) == nil {
			t.Fatalf("completion session %q accepted", s)
		}
	}
	// A completion carrying only the account state is an observation, not an empty one.
	if validateCompletion(V2Completion{ID: sessionTestID}) == nil {
		t.Fatal("empty completion accepted")
	}
}

func sessionStateCatalogueRule(t *testing.T) {
	provider := sessionTestProvider()
	rule := DetectionNetwork{Method: "POST", Host: "chatgpt.com", Path: "/unauth-mweb/conversation/updates", TextPath: "prompt"}
	for _, s := range []string{"", "signed_in", "signed_out"} {
		rule.Session = s
		if e := validateProviderNetworkRule(provider, rule); e != nil {
			t.Fatalf("rule session %q refused: %v", s, e)
		}
	}
	rule.Session = "anonymous"
	if validateProviderNetworkRule(provider, rule) == nil {
		t.Fatal("rule session outside the vocabulary accepted")
	}
}

func sessionStateConversationPaths(t *testing.T) {
	valid := func(paths ...string) error {
		p := sessionTestProvider()
		p.ConversationPaths = paths
		return validateDetectionProvider(p, map[string]bool{}, map[string]bool{}, map[string]bool{})
	}
	if e := valid("/uc/*"); e != nil {
		t.Fatalf("measured signed-out conversation path refused: %v", e)
	}
	for _, bad := range [][]string{{""}, {"uc/*"}, {"/uc/(a+)+"}, {"/a/*", "/b/*", "/c/*", "/d/*", "/e/*"}} {
		if valid(bad...) == nil {
			t.Fatalf("conversation paths %q accepted", bad)
		}
	}
	// The signed-out page moves to /uc/<id>: its identifier is minimized like /c/<id>.
	if got, _ := normalizeEventURL("https://chatgpt.com/uc/6abad4ee-1a3c-83ea-8ac0-5b28d9c18ff5", "chatgpt.com"); got != "https://chatgpt.com/uc/:conversation" {
		t.Fatalf("signed-out conversation URL kept its identifier: %q", got)
	}
}
