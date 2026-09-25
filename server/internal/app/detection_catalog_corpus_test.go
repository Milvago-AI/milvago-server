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

type catalogCorpusCounts struct {
	total, serverAccepts, serverRejects             int
	engineAccepts, engineRejects, differentVerdicts int
}

func (counts *catalogCorpusCounts) record(fixture catalogCorpusFixture, serverAccepted bool) {
	if serverAccepted {
		counts.serverAccepts++
	} else {
		counts.serverRejects++
	}
	if fixture.Engine == "accept" {
		counts.engineAccepts++
	} else {
		counts.engineRejects++
	}
	if fixture.Server != fixture.Engine {
		counts.differentVerdicts++
	}
}

func catalogCorpusDirectory(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve the corpus path")
	}
	// The server-only repository receives a copy under testdata from the export.
	directory := filepath.Join(filepath.Dir(source), "testdata", "catalog")
	if _, err := os.Stat(directory); err != nil {
		directory = filepath.Join(filepath.Dir(source), "..", "..", "..", "endpoint", "extension", "fixtures", "catalog")
	}
	return directory
}

func readCatalogCorpusFixture(t *testing.T, path string) (catalogCorpusFixture, bool) {
	t.Helper()
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
	return fixture, serverAccepted
}

func TestDetectionCatalogCorpus(t *testing.T) {
	directory := catalogCorpusDirectory(t)
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	counts := catalogCorpusCounts{}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		counts.total++
		path := filepath.Join(directory, entry.Name())
		t.Run(entry.Name(), func(t *testing.T) {
			fixture, serverAccepted := readCatalogCorpusFixture(t, path)
			counts.record(fixture, serverAccepted)
		})
	}
	if counts.total == 0 {
		t.Fatal("catalogue corpus is empty")
	}
	if counts.serverAccepts == 0 || counts.serverRejects == 0 || counts.engineAccepts == 0 || counts.engineRejects == 0 || counts.differentVerdicts == 0 {
		t.Fatalf("corpus coverage incomplete: total=%d server_accept=%d server_reject=%d declared_engine_accept=%d declared_engine_reject=%d different_verdicts=%d", counts.total, counts.serverAccepts, counts.serverRejects, counts.engineAccepts, counts.engineRejects, counts.differentVerdicts)
	}
	t.Logf("replayed %d catalogue cases: server accept/reject=%d/%d, declared engine accept/reject=%d/%d, different verdicts=%d", counts.total, counts.serverAccepts, counts.serverRejects, counts.engineAccepts, counts.engineRejects, counts.differentVerdicts)
}
