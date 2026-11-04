package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
)

// Independent copy of the pre-memo derivation for byte compatibility checks.
func legacyDiscoveryFingerprint(sourceRevision int64, configuration DiscoverySettings, catalog json.RawMessage) (string, error) {
	var canonical any
	decoder := json.NewDecoder(bytes.NewReader(catalog))
	decoder.UseNumber()
	if err := decoder.Decode(&canonical); err != nil {
		return "", err
	}
	raw, err := json.Marshal(struct {
		SourceRevision int64             `json:"source_revision"`
		Configuration  DiscoverySettings `json:"configuration"`
		Catalog        any               `json:"catalog"`
	}{sourceRevision, configuration, canonical})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func TestDiscoveryFingerprintMemoMatchesLegacyDerivation(t *testing.T) {
	configuration := DiscoverySettings{Host: true, HTTP: true, IntervalSeconds: 300}
	for index, catalog := range []string{
		`{"revision":7,"name":"Synthetic catalog"}`,
		`{"name":"Synthetic catalog", "revision":7}`,
		`{"revision":7,"large":9007199254740993,"decimal":1.2300e+02,"negative":-0,"exponent":1e9999}`,
		`{"revision":7,"text":"é雪\u2028<&>","escaped":"\u00e9"}`,
		`{"revision":7,"nested":[true,false,null,{"z":2,"a":1}]}`,
		`null`, `[]`, `"synthetic"`, `true`,
		// Retain the old first-Decode behavior; actual DB content is jsonb.
		`{"revision":7} {"trailing":true}`,
		``, `{`, `{"revision":}`, `{"number":01}`, `{"text":"\uZZZZ"}`,
	} {
		t.Run(fmt.Sprintf("case-%d", index), func(t *testing.T) {
			var cache discoveryFingerprintCache
			for _, revision := range []int64{-1, 0, 700, 1<<63 - 1} {
				want, wantErr := legacyDiscoveryFingerprint(revision, configuration, json.RawMessage(catalog))
				for range 2 {
					got, err := cache.fingerprint("tenant-a", revision, configuration, json.RawMessage(catalog))
					if (err == nil) != (wantErr == nil) || got != want {
						t.Fatalf("memo changed legacy fingerprint or acceptance: got %q/%v, want %q/%v", got, err, want, wantErr)
					}
					if err != nil && err.Error() != wantErr.Error() {
						t.Fatal("memo changed legacy error", err, wantErr)
					}
				}
			}
		})
	}
}

func TestDiscoveryFingerprintMemoKeysEveryEffectiveInputAndTenant(t *testing.T) {
	var cache discoveryFingerprintCache
	configuration := DiscoverySettings{Host: true, IntervalSeconds: 300}
	catalog := json.RawMessage(`{"revision":7,"name":"first"}`)
	baseline, err := cache.fingerprint("tenant-a", 700, configuration, catalog)
	if err != nil {
		t.Fatal(err)
	}
	type variant struct {
		organization  string
		revision      int64
		configuration DiscoverySettings
		catalog       json.RawMessage
		sameDigest    bool
	}
	variants := []variant{
		{"tenant-b", 700, configuration, catalog, true},
		{"tenant-a", 701, configuration, catalog, false},
	}
	for index := range 8 {
		next := configuration
		switch index {
		case 0:
			next.Host = false
		case 1:
			next.Containers = true
		case 2:
			next.VirtualMachines = true
		case 3:
			next.GuestRead = true
		case 4:
			next.GuestExecute = true
		case 5:
			next.HTTP = true
		case 6:
			next.Network = true
		case 7:
			next.IntervalSeconds = 301
		}
		variants = append(variants, variant{"tenant-a", 700, next, catalog, false})
	}
	variants = append(variants,
		variant{"tenant-a", 700, configuration, json.RawMessage(`{"revision":7,"name":"other"}`), false},
		variant{"tenant-a", 700, configuration, json.RawMessage(` { "name":"first", "revision":7 } `), true},
	)
	for index, variant := range variants {
		want, err := legacyDiscoveryFingerprint(variant.revision, variant.configuration, variant.catalog)
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			got, err := cache.fingerprint(variant.organization, variant.revision, variant.configuration, variant.catalog)
			if err != nil || got != want || (got == baseline) != variant.sameDigest {
				t.Fatalf("effective input variant %d reused another fingerprint: %v", index, err)
			}
		}
		if len(cache.entries) != index+2 {
			t.Fatal("tenant or complete fresh input was omitted from the memo key", index, len(cache.entries))
		}
	}
	copy(catalog, []byte(`{"revision":7,"name":"other"}`))
	modified, err := cache.fingerprint("tenant-a", 700, configuration, catalog)
	if err != nil || modified == baseline {
		t.Fatal("a caller's changed same-revision bytes reused a previous result", err)
	}
	if got, err := cache.fingerprint("tenant-a", 700, configuration, json.RawMessage(`{"revision":7,"name":"first"}`)); err != nil || got != baseline {
		t.Fatal("later input mutation corrupted a retained pure digest", err)
	}
}

func TestDiscoveryFingerprintMemoDoesNotRememberFailuresAndBoundsEntries(t *testing.T) {
	var cache discoveryFingerprintCache
	configuration := DiscoverySettings{Host: true, IntervalSeconds: 300}
	for range 2 {
		if _, err := cache.fingerprint("tenant-a", 700, configuration, json.RawMessage(`{"revision":`)); err == nil || len(cache.entries) != 0 {
			t.Fatal("failed parsing created a memo entry", err, len(cache.entries))
		}
	}
	inputs := make([]json.RawMessage, 0, 64)
	for index := range 64 {
		catalog := json.RawMessage(fmt.Sprintf(`{"revision":7,"number":%d}`, index))
		inputs = append(inputs, catalog)
		want, wantErr := legacyDiscoveryFingerprint(700, configuration, catalog)
		got, err := cache.fingerprint("tenant-a", 700, configuration, catalog)
		if err != nil || wantErr != nil || got != want || len(cache.entries) > discoveryFingerprintCacheEntries {
			t.Fatal("memo changed output or exceeded its entry bound", err, len(cache.entries))
		}
	}
	if len(cache.entries) != discoveryFingerprintCacheEntries {
		t.Fatal("memo did not retain its bounded completed entries")
	}
	var evicted json.RawMessage
	for _, input := range inputs {
		retained := false
		for key := range cache.entries {
			if key.catalog == sha256.Sum256(input) {
				retained = true
			}
		}
		if !retained {
			evicted = input
			break
		}
	}
	if evicted == nil {
		t.Fatal("overflow never evicted a completed entry")
	}
	want, _ := legacyDiscoveryFingerprint(700, configuration, evicted)
	if got, err := cache.fingerprint("tenant-a", 700, configuration, evicted); err != nil || got != want || len(cache.entries) != discoveryFingerprintCacheEntries {
		t.Fatal("eviction changed a recomputed fingerprint or exceeded the bound", err)
	}
	beforeFailure := len(cache.entries)
	if _, err := cache.fingerprint("tenant-a", 700, configuration, json.RawMessage(`{"broken"`)); err == nil || len(cache.entries) != beforeFailure {
		t.Fatal("failed parsing changed completed entries", err)
	}
}

func TestDiscoveryFingerprintMemoConcurrentMissesRemainPureAndBounded(t *testing.T) {
	var cache discoveryFingerprintCache
	configuration := DiscoverySettings{Host: true, IntervalSeconds: 300}
	failures := make(chan error, 64)
	var workers sync.WaitGroup
	for index := range 64 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			catalog := json.RawMessage(fmt.Sprintf(`{"revision":7,"number":%d}`, index%32))
			want, err := legacyDiscoveryFingerprint(700, configuration, catalog)
			if err != nil {
				failures <- err
				return
			}
			got, err := cache.fingerprint("tenant-a", 700, configuration, catalog)
			if err != nil || got != want {
				failures <- fmt.Errorf("concurrent derivation changed output: %v", err)
			}
		}()
	}
	workers.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if len(cache.entries) > discoveryFingerprintCacheEntries {
		t.Fatal("concurrent completions exceeded the memo bound")
	}
}
