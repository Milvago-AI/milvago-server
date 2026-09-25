package app

import "testing"

// FuzzDecodeDetection exercises decodeDetection (detection.go), the parser and
// validator for a detection catalogue. It is reached from importDetectionCatalog
// (detection_import.go) once a publisher-signed envelope has already been verified --
// signature verification happens strictly before this call, never inside it -- so this
// function is the last line of defense against a catalogue whose *signature* checks out
// but whose *content* is malformed or hostile. It is also what parses the embedded
// detection_factory.json at boot, so it must never panic on well-formed input either.
//
// Invariant: on acceptance, every size bound validateDetection is documented to enforce
// actually held on the decoded value -- the memo in decodedDetection hands this struct
// to every later caller (agents, console, MCP tools) exactly as returned here.
func assertDetectionNetworkPaths(t *testing.T, provider DetectionProvider) {
	t.Helper()
	for _, network := range provider.Network {
		if !validDetectionJSONPath(network.TextPath) {
			t.Fatalf("accepted an invalid text_path %q on provider %q", network.TextPath, provider.ID)
		}
	}
}

func assertUniqueDetectionProviders(t *testing.T, providers []DetectionProvider) {
	t.Helper()
	ids := map[string]bool{}
	for _, provider := range providers {
		if ids[provider.ID] {
			t.Fatalf("accepted a duplicate provider id %q", provider.ID)
		}
		ids[provider.ID] = true
		assertDetectionNetworkPaths(t, provider)
	}
}

func assertDecodedDetection(t *testing.T, raw []byte) {
	t.Helper()
	content, err := decodeDetection(raw)
	if err != nil {
		return
	}
	if len(content.Providers) == 0 || len(content.Providers) > 128 {
		t.Fatalf("accepted catalogue with %d providers", len(content.Providers))
	}
	if len(content.NativeTools) > 32 {
		t.Fatalf("accepted %d native tools", len(content.NativeTools))
	}
	if len(content.KnownPlatforms) > 256 {
		t.Fatalf("accepted %d known platforms", len(content.KnownPlatforms))
	}
	assertUniqueDetectionProviders(t, content.Providers)
}

func FuzzDecodeDetection(f *testing.F) {
	f.Add(detectionFactory)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"providers":[]}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))
	f.Add([]byte(`{"providers":[{"id":"__proto__","domains":["a.com"],"qualified_at":"2026-01-01T00:00:00Z"}]}`))
	f.Add([]byte(`{"providers":[{"id":"x","domains":["a.com"],"qualified_at":"2026-01-01T00:00:00Z","network":[{"method":"POST","host":"a.com","path":"/","text_path":"__proto__.a"}]}]}`))
	f.Add([]byte(`{"unknown_field":1}`))
	f.Add([]byte(`{"known_platforms":[{"id":"x","domains":["a.com"]}]}`))

	f.Fuzz(assertDecodedDetection)
}
