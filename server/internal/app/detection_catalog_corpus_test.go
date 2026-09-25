package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type catalogCorpusFixture struct {
	Case    string          `json:"case"`
	Server  string          `json:"server"`
	Engine  string          `json:"engine"`
	Content json.RawMessage `json:"content"`
}

func TestDetectionCatalogCorpus(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve the corpus path")
	}
	// The corpus lives with the extension in the monorepo; the server-only repository
	// (milvago-server, no endpoint/) receives a copy under testdata/ from the export.
	directory := filepath.Join(filepath.Dir(source), "testdata", "catalog")
	if _, err := os.Stat(directory); err != nil {
		directory = filepath.Join(filepath.Dir(source), "..", "..", "..", "endpoint", "extension", "fixtures", "catalog")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	total, serverAccepts, serverRejects := 0, 0, 0
	engineAccepts, engineRejects, differentVerdicts := 0, 0, 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		total++
		path := filepath.Join(directory, entry.Name())
		t.Run(entry.Name(), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var fixture catalogCorpusFixture
			if err := json.Unmarshal(raw, &fixture); err != nil {
				t.Fatal(err)
			}
			if fixture.Case == "" || (fixture.Server != "accept" && fixture.Server != "reject") || (fixture.Engine != "accept" && fixture.Engine != "reject") || len(fixture.Content) == 0 {
				t.Fatal("invalid corpus fixture metadata")
			}
			content, err := decodeDetection(fixture.Content)
			serverAccepted := err == nil
			if serverAccepted != (fixture.Server == "accept") {
				t.Fatalf("server validation=%t, fixture=%s: %v", serverAccepted, fixture.Server, err)
			}
			if content.Providers == nil && serverAccepted {
				t.Fatal("accepted fixture decoded without providers")
			}
			if serverAccepted {
				serverAccepts++
			} else {
				serverRejects++
			}
			if fixture.Engine == "accept" {
				engineAccepts++
			} else {
				engineRejects++
			}
			if fixture.Server != fixture.Engine {
				differentVerdicts++
			}
		})
	}
	if total == 0 {
		t.Fatal("catalogue corpus is empty")
	}
	if serverAccepts == 0 || serverRejects == 0 || engineAccepts == 0 || engineRejects == 0 || differentVerdicts == 0 {
		t.Fatalf("corpus coverage incomplete: total=%d server_accept=%d server_reject=%d declared_engine_accept=%d declared_engine_reject=%d different_verdicts=%d", total, serverAccepts, serverRejects, engineAccepts, engineRejects, differentVerdicts)
	}
	t.Logf("replayed %d catalogue cases: server accept/reject=%d/%d, declared engine accept/reject=%d/%d, different verdicts=%d", total, serverAccepts, serverRejects, engineAccepts, engineRejects, differentVerdicts)
}
