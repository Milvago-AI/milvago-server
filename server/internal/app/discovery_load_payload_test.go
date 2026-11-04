package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"testing"
)

// This is the original fixture map, with the same per-report three numbers.
// The synthetic fact timestamps remain in the immutable input arrays.
func discoveryLoadReportBody(entities, matches, queries []any, revision, sequence, observed int64) map[string]any {
	return map[string]any{"version": 1, "catalog_revision": discoveryFixtureCatalogRevision, "settings_revision": revision, "run_id": nil, "scope": "endpoint", "sequence": sequence, "page": 0, "pages": 1, "observed_at": observed, "complete": false, "entities": entities, "relations": []any{}, "coverage": []any{}, "result": map[string]any{"identifications": matches, "communications": []any{}, "queries": queries, "evaluated_facts": 100, "unknown_conditions": 0}}
}

type discoveryLoadReportTemplate struct {
	fragments [4][]byte
	capacity  int
}

// Marshal once before the measured arrivals. Decode only the top-level fields
// to locate numeric spans; nested evidence.observed_at is never substituted.
func newDiscoveryLoadReportTemplate(entities, matches, queries []any) (discoveryLoadReportTemplate, error) {
	raw, err := json.Marshal(discoveryLoadReportBody(entities, matches, queries, 0, 0, 0))
	if err != nil {
		return discoveryLoadReportTemplate{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return discoveryLoadReportTemplate{}, errors.New("invalid fixture template")
	}
	spans := [][2]int{}
	wanted := []string{"observed_at", "sequence", "settings_revision"}
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return discoveryLoadReportTemplate{}, err
		}
		key, ok := token.(string)
		if !ok {
			return discoveryLoadReportTemplate{}, errors.New("invalid fixture template key")
		}
		before := int(decoder.InputOffset())
		var value json.RawMessage
		if err = decoder.Decode(&value); err != nil {
			return discoveryLoadReportTemplate{}, err
		}
		if key == "observed_at" || key == "sequence" || key == "settings_revision" {
			if len(spans) >= len(wanted) || key != wanted[len(spans)] || before >= len(raw) || raw[before] != ':' || !bytes.Equal(value, []byte("0")) {
				return discoveryLoadReportTemplate{}, errors.New("fixture numeric shape drift")
			}
			spans = append(spans, [2]int{before + 1, int(decoder.InputOffset())})
		}
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') || len(spans) != 3 {
		return discoveryLoadReportTemplate{}, errors.New("incomplete fixture template")
	}
	template := discoveryLoadReportTemplate{capacity: len(raw) + 60}
	previous := 0
	for index, span := range spans {
		template.fragments[index] = raw[previous:span[0]]
		previous = span[1]
	}
	template.fragments[3] = raw[previous:]
	return template, nil
}

func (template discoveryLoadReportTemplate) encode(revision, sequence, observed int64) []byte {
	raw := make([]byte, 0, template.capacity)
	values := [3]int64{observed, sequence, revision}
	for index, value := range values {
		raw = append(raw, template.fragments[index]...)
		raw = strconv.AppendInt(raw, value, 10)
	}
	return append(raw, template.fragments[3]...)
}

func discoveryLoadPayloadFixture(dnsHints, escaped bool) (entities, matches, queries []any) {
	entities, matches, queries = []any{}, []any{}, []any{}
	observed := int64(1700000000)
	for n := 0; n < 100; n++ {
		id := "process/" + strconv.Itoa(n)
		if escaped && n == 0 {
			id += "<>&\u2028\u2029\"\\"
		}
		entities = append(entities, map[string]any{"id": id, "kind": "process"})
		matches = append(matches, map[string]any{"entity_id": id, "application_id": "openclaw", "signature_id": "openclaw.process", "signature_revision": 1, "state": "executed", "evidence": []any{map[string]any{"fact_id": "fact/" + strconv.Itoa(n), "source": "host_process", "observed_at": observed, "fields": []string{"executable"}}}})
	}
	if dnsHints {
		entities = append(entities, map[string]any{"id": "host/dns", "kind": "host"})
		for _, provider := range []string{"openai", "anthropic", "google", "mistral"} {
			queries = append(queries, map[string]any{"entity_id": "host/dns", "provider": provider, "evidence": map[string]any{"fact_id": "fact/dns-" + provider, "source": "host_dns_query", "observed_at": observed, "fields": []string{"remote_host"}}})
		}
	}
	return
}

func TestDiscoveryLoadReportTemplateExactBytesAndIsolation(t *testing.T) {
	for _, dns := range []bool{false, true} {
		for _, escaped := range []bool{false, true} {
			entities, matches, queries := discoveryLoadPayloadFixture(dns, escaped)
			template, err := newDiscoveryLoadReportTemplate(entities, matches, queries)
			if err != nil {
				t.Fatal("template preparation failed")
			}
			for _, values := range [][3]int64{{0, 0, 0}, {73, 1760000000123, 1700000037}, {9223372036854775807, -9223372036854775808, -1}} {
				expected, err := json.Marshal(discoveryLoadReportBody(entities, matches, queries, values[0], values[1], values[2]))
				if err != nil {
					t.Fatal("legacy report encoding failed")
				}
				actual := template.encode(values[0], values[1], values[2])
				if !bytes.Equal(actual, expected) {
					t.Fatal("report HTTP bytes changed")
				}
				var decoded struct {
					Sequence int64             `json:"sequence"`
					Revision int64             `json:"settings_revision"`
					Observed int64             `json:"observed_at"`
					Entities []json.RawMessage `json:"entities"`
					Result   struct {
						Facts   int `json:"evaluated_facts"`
						Matches []struct {
							Evidence []struct {
								Observed int64 `json:"observed_at"`
							} `json:"evidence"`
						} `json:"identifications"`
						Queries []json.RawMessage `json:"queries"`
					} `json:"result"`
				}
				entityCount, queryCount := 100, 0
				if dns {
					entityCount, queryCount = 101, 4
				}
				if json.Unmarshal(actual, &decoded) != nil || decoded.Sequence != values[1] || decoded.Revision != values[0] || decoded.Observed != values[2] || len(decoded.Entities) != entityCount || decoded.Result.Facts != 100 || len(decoded.Result.Matches) != 100 || len(decoded.Result.Queries) != queryCount {
					t.Fatal("fixture report semantics changed")
				}
				for _, match := range decoded.Result.Matches {
					if len(match.Evidence) != 1 || match.Evidence[0].Observed != 1700000000 {
						t.Fatal("immutable fact timestamp changed")
					}
				}
				actual[0] = '['
				if !bytes.Equal(template.encode(values[0], values[1], values[2]), expected) {
					t.Fatal("request bytes alias immutable fragments")
				}
			}
			before, _ := json.Marshal(discoveryLoadReportBody(entities, matches, queries, 7, 8, 9))
			var workers sync.WaitGroup
			bad := make(chan bool, 32)
			for index := 0; index < 32; index++ {
				workers.Add(1)
				go func(sequence int64) {
					defer workers.Done()
					expected, err := json.Marshal(discoveryLoadReportBody(entities, matches, queries, 73, sequence, 1700000037))
					actual := template.encode(73, sequence, 1700000037)
					bad <- err != nil || !bytes.Equal(actual, expected)
					actual[0] = '['
				}(int64(index))
			}
			workers.Wait()
			close(bad)
			for failure := range bad {
				if failure {
					t.Fatal("concurrent report encoding changed bytes")
				}
			}
			after, _ := json.Marshal(discoveryLoadReportBody(entities, matches, queries, 7, 8, 9))
			if !bytes.Equal(before, after) {
				t.Fatal("fixture input arrays mutated")
			}
		}
	}
}

var discoveryLoadPayloadBenchmarkSink []byte

// Run a bounded fixed iteration count in the isolated parent fixture. This
// measures encoding only, not server throughput or the cause of a CI abort.
func BenchmarkDiscoveryLoadReportEncoding(b *testing.B) {
	for _, dns := range []bool{false, true} {
		name := "facts100"
		if dns {
			name = "facts100_dns4"
		}
		entities, matches, queries := discoveryLoadPayloadFixture(dns, false)
		template, err := newDiscoveryLoadReportTemplate(entities, matches, queries)
		if err != nil {
			b.Fatal("template preparation failed")
		}
		expected, _ := json.Marshal(discoveryLoadReportBody(entities, matches, queries, 73, 1700000000123, 1700000037))
		if !bytes.Equal(expected, template.encode(73, 1700000000123, 1700000037)) {
			b.Fatal("encoder differential failed")
		}
		b.Run(name+"/legacy", func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(expected)))
			for index := 0; index < b.N; index++ {
				raw, err := json.Marshal(discoveryLoadReportBody(entities, matches, queries, 73, 1700000000123+int64(index), 1700000037))
				if err != nil || len(raw) == 0 {
					b.Fatal("legacy encoding failed")
				}
				discoveryLoadPayloadBenchmarkSink = raw
			}
		})
		b.Run(name+"/immutable", func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(expected)))
			for index := 0; index < b.N; index++ {
				raw := template.encode(73, 1700000000123+int64(index), 1700000037)
				if len(raw) == 0 {
					b.Fatal("immutable encoding failed")
				}
				discoveryLoadPayloadBenchmarkSink = raw
			}
		})
	}
}
