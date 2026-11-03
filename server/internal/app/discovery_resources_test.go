package app

import (
	"context"
	"encoding/json"
	"os"
	"runtime"
	"sync"
	"testing"
)

func TestDiscoveryWASMInstancesRemainBoundedOnSuccessAndFailure(t *testing.T) {
	entities := []any{}
	matches := []any{}
	for n := 0; n < 100; n++ {
		id := discoveryCursor("synthetic", string(rune('a'+n)))
		entities = append(entities, map[string]any{"id": id, "kind": "process"})
		matches = append(matches, map[string]any{"entity_id": id, "application_id": "openclaw", "signature_id": "openclaw.process", "signature_revision": 1, "state": "executed", "evidence": []any{map[string]any{"fact_id": id, "source": "host_process", "observed_at": 1, "fields": []string{"executable"}}}})
	}
	report := map[string]any{"version": 1, "scope": "endpoint", "sequence": 1, "catalog_revision": discoveryFixtureCatalogRevision, "settings_revision": 1, "run_id": nil, "page": 0, "pages": 1, "observed_at": 1, "complete": false, "entities": entities, "relations": []any{}, "coverage": []any{}, "result": map[string]any{"identifications": matches, "communications": []any{}, "evaluated_facts": 100, "unknown_conditions": 0}}
	valid := map[string]any{"op": "validate_report", "catalog": json.RawMessage(discoveryFactory), "report": report}
	invalid := map[string]any{"op": "validate_report", "catalog": json.RawMessage(discoveryFactory), "report": map[string]any{"version": "data:image/png"}}
	exercise := func() error { return discoveryEngine(context.Background(), valid, nil) }
	for n := 0; n < 32; n++ {
		if err := exercise(); err != nil {
			t.Fatal(err)
		}
		if discoveryEngine(context.Background(), invalid, nil) == nil {
			t.Fatal("invalid report succeeded")
		}
	}
	var before runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	goroutines := runtime.NumGoroutine()
	descriptors, descriptorErr := os.ReadDir("/proc/self/fd")
	for round := 0; round < 4; round++ {
		var workers sync.WaitGroup
		failures := make(chan error, 4)
		for worker := 0; worker < 4; worker++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for n := 0; n < 80; n++ {
					if err := exercise(); err != nil {
						failures <- err
						return
					}
					if discoveryEngine(context.Background(), invalid, nil) == nil {
						failures <- bad("Invalid report succeeded during repetition.")
						return
					}
				}
			}()
		}
		workers.Wait()
		close(failures)
		for err := range failures {
			t.Fatal(err)
		}
		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		// A bounded regression guard does not establish long-term retention.
		// Runtime bookkeeping may retain small allocations.
		if after.HeapAlloc > before.HeapAlloc+4*1024*1024 {
			t.Fatalf("retained heap grew by %d bytes", after.HeapAlloc-before.HeapAlloc)
		}
		t.Logf("round %d: live heap %d bytes", round+1, after.HeapAlloc)
	}
	shared, err := sharedDiscoveryRuntime()
	if err != nil {
		t.Fatal(err)
	}
	if len(shared.capacity) != 0 {
		t.Fatal("an evaluation permit was retained")
	}
	if runtime.NumGoroutine() > goroutines+4 {
		t.Fatal("evaluation goroutines accumulated")
	}
	if descriptorErr == nil {
		after, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		if len(after) > len(descriptors) {
			t.Fatal("evaluation file descriptors accumulated")
		}
	} else {
		t.Log("descriptor census is unavailable on this platform")
	}
}
