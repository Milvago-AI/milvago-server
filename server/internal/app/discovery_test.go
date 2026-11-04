package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
)

var discoveryFixtureCatalogRevision = func() int64 {
	var catalog struct {
		Revision int64 `json:"revision"`
	}
	if json.Unmarshal(discoveryFactory, &catalog) != nil || catalog.Revision < 1 {
		panic("invalid discovery factory revision in test fixture")
	}
	return catalog.Revision
}()

func TestDiscoveryFactoryRecognizesNativeOpenClawGateway(t *testing.T) {
	snapshot := map[string]any{"version": 1, "scope": "endpoint", "sequence": 1, "observed_at": 100, "complete": false,
		"entities": []any{map[string]string{"id": "process/gateway", "kind": "process"}}, "relations": []any{}, "coverage": []any{},
		"facts": []any{map[string]any{"id": "fact/gateway", "entity_id": "process/gateway", "source": "container_process", "observed_at": 100,
			"fields": map[string]any{"executable": []string{"openclaw-gateway"}}}}}
	var result struct {
		Result struct {
			Identifications []discoveryMatch `json:"identifications"`
		} `json:"result"`
	}
	if err := discoveryEngine(context.Background(), map[string]any{"op": "evaluate", "catalog": discoveryFactory, "snapshot": snapshot}, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Result.Identifications) != 1 || result.Result.Identifications[0].SignatureID != "openclaw.gateway" || result.Result.Identifications[0].State != "executed" {
		t.Fatal("native gateway title was not recognized by the shipped WASM")
	}
}

func TestDiscoveryFactoryAndYAMLValidation(t *testing.T) {
	if err := discoveryEngine(context.Background(), map[string]any{"op": "compile", "catalog": discoveryFactory}, nil); err != nil {
		t.Fatal(err)
	}
	yaml := "version: 1\nrevision: 1\nsignatures: []\n"
	raw, err := discoveryJSON(yaml)
	if err != nil {
		t.Fatal(err)
	}
	if err = discoveryEngine(context.Background(), map[string]any{"op": "compile", "catalog": raw}, nil); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"version: 1\nversion: 2", "version: &source 1\nrevision: *source", "!!binary aGVsbG8=", "[image, data]", strings.Repeat("x", 96<<10+1), "version: null\nrevision: 1\nsignatures: []"} {
		raw, err := discoveryJSON(source)
		if err == nil {
			err = discoveryEngine(context.Background(), map[string]any{"op": "compile", "catalog": raw}, nil)
		}
		if err == nil {
			t.Fatalf("accepted hostile YAML: %.60s", source)
		}
	}
	duplicate := json.RawMessage(`{"version":1,"version":2,"revision":1,"signatures":[]}`)
	if err := discoveryEngine(context.Background(), map[string]any{"op": "compile", "catalog": duplicate}, nil); err == nil {
		t.Fatal("duplicate JSON key accepted")
	}
}

func TestDiscoveryWASMCorrelatesHTTPResponsesWithoutSendingBodies(t *testing.T) {
	snapshot := map[string]any{"version": 1, "scope": "endpoint", "sequence": 1, "observed_at": 100, "complete": false, "entities": []any{map[string]string{"id": "endpoint/fixture", "kind": "endpoint"}}, "facts": []any{}, "relations": []any{}, "coverage": []any{}}
	fact := func(id, path, body string) map[string]any {
		return map[string]any{"id": id, "entity_id": "endpoint/fixture", "source": "http", "observed_at": 100, "fields": map[string]any{"http_path": []string{path}, "http_status": []string{"200"}, "http_content_type": []string{"application/json"}, "http_body": []string{body}}}
	}
	first := fact("response/root", "/", "<title>LibreChat</title> PRIVATE_FIXTURE")
	second := fact("response/config", "/api/config", "{\"url\":\"https://librechat.ai\"}")
	evaluate := func(facts []any) []discoveryMatch {
		t.Helper()
		snapshot["facts"] = facts
		var out struct {
			Result struct {
				Identifications []discoveryMatch `json:"identifications"`
			} `json:"result"`
		}
		if err := discoveryEngine(context.Background(), map[string]any{"op": "evaluate", "catalog": discoveryFactory, "snapshot": snapshot}, &out); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(out)
		if bytes.Contains(raw, []byte("PRIVATE_FIXTURE")) {
			t.Fatal("response body escaped the engine")
		}
		return out.Result.Identifications
	}
	if len(evaluate([]any{first})) != 0 {
		t.Fatal("one response identified a conjunctive fingerprint")
	}
	found := evaluate([]any{first, second})
	if len(found) != 1 || found[0].SignatureID != "librechat.http" || len(found[0].Evidence) != 2 {
		t.Fatalf("incorrect correlation: %+v", found)
	}
	snapshot["entities"] = []any{map[string]string{"id": "endpoint/fixture", "kind": "endpoint"}, map[string]string{"id": "endpoint/other", "kind": "endpoint"}}
	second["entity_id"] = "endpoint/other"
	if len(evaluate([]any{first, second})) != 0 {
		t.Fatal("responses from different endpoints were combined")
	}
}

func TestDiscoveryYAMLUsesSyntaxNotMarkerSearch(t *testing.T) {
	for _, source := range []string{
		"value: 'text &anchor *alias !tag <<: inside a string'\n",
		"value: |\n  &anchor *alias !tag <<: inside block text\n",
		"value: text &anchor inside a plain string\n",
	} {
		raw, err := discoveryJSON(source)
		if err != nil || !json.Valid(raw) {
			t.Fatalf("valid literal rejected: %v", err)
		}
	}
	for _, source := range []string{
		"version: 1\n---\nversion: 2\n",
		"version: 1\n---\ninvalid: [\n",
		"value: &anchor data\nother: *anchor\n",
		"value: !!str data\n",
		"value: !custom data\n",
		"outer: { value: one, value: two }\n",
		"outer: { <<: {key: value} }\n",
		"value: 2026-10-26\n",
	} {
		if _, err := discoveryJSON(source); err == nil {
			t.Fatalf("unsupported YAML accepted: %q", source)
		}
	}
}

func TestDiscoveryCatalogBoundsTheRepresentationDeliveredInPolicies(t *testing.T) {
	// Each rule is valid on its own. Escaping HTML expands an otherwise small
	// catalogue beyond the transport budget used by endpoint authorization.
	rules := make([]string, 80)
	for i := range rules {
		rules[i] = fmt.Sprintf(`{"id":"fixture.%d","application_id":"fixture","name":"Fixture","revision":1,"sources":["http"],"state":"interface_recognized","condition":{"op":"contains","field":"http_body","value":"%s"},"provenance":"fixture"}`, i, strings.Repeat("<", 512))
	}
	compact := `{"version":1,"revision":1,"signatures":[` + strings.Join(rules, ",") + `]}`
	if len(compact) >= 96<<10 {
		t.Fatal("fixture must fit the source budget")
	}
	if err := discoveryEngine(context.Background(), map[string]any{"op": "compile", "catalog": json.RawMessage(compact)}, nil); err != nil {
		t.Fatalf("fixture must be a valid catalogue: %v", err)
	}
	for _, source := range []string{compact, "value: \"" + strings.Repeat(`\0`, 20000) + "\"\n"} {
		if _, err := discoveryJSON(source); err == nil {
			t.Fatal("accepted a catalogue which expands beyond its serialized budget")
		}
	}
	raw, err := discoveryJSON(`{"value":"<title>Small</title>"}`)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]string
	if json.Unmarshal(raw, &decoded) != nil || decoded["value"] != "<title>Small</title>" {
		t.Fatal("canonicalization changed a valid literal")
	}
}

func TestDiscoveryVMNetworkDoesNotIdentifyGuestApplication(t *testing.T) {
	snapshot := json.RawMessage(`{"version":1,"scope":"endpoint","sequence":1,"observed_at":100,"complete":false,"entities":[{"id":"vm/fixture","kind":"vm"}],"facts":[{"id":"fact/1","entity_id":"vm/fixture","source":"vm_flow","observed_at":100,"fields":{"remote_host":["api.openai.com"],"remote_port":["443"]}}],"relations":[],"coverage":[]}`)
	var out struct {
		Result struct {
			Identifications []json.RawMessage `json:"identifications"`
			Communications  []struct {
				EntityID string `json:"entity_id"`
				Provider string `json:"provider"`
			} `json:"communications"`
		} `json:"result"`
	}
	if err := discoveryEngine(context.Background(), map[string]any{"op": "evaluate", "catalog": discoveryFactory, "snapshot": snapshot}, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Result.Identifications) != 0 || len(out.Result.Communications) != 1 || out.Result.Communications[0].EntityID != "vm/fixture" || out.Result.Communications[0].Provider != "openai" {
		t.Fatalf("incorrect VM attribution: %+v", out)
	}
}

func TestDiscoverySourceConsentAndMalformedConfiguration(t *testing.T) {
	for _, configuration := range []DiscoverySettings{{IntervalSeconds: 1}, {IntervalSeconds: 3601}, {IntervalSeconds: 300, GuestExecute: true}, {IntervalSeconds: 300, GuestRead: true}, {IntervalSeconds: 300, HTTP: true}} {
		if configuration.validate() == nil {
			t.Fatalf("accepted invalid configuration: %+v", configuration)
		}
	}
	enabled := DiscoverySettings{Host: true, Containers: true, VirtualMachines: true, GuestRead: true, HTTP: true, Network: true, IntervalSeconds: 300}
	if err := enabled.validate(); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"installation", "host_process", "guest_process", "container_process", "container_metadata", "http", "vm_flow", "host_flow", "runtime_flow", "container_flow", "host_dns_query"} {
		if !discoverySourceAllowed(source, enabled) || discoverySourceAllowed(source, DiscoverySettings{}) {
			t.Fatalf("wrong consent decision for %s", source)
		}
	}
	if discoverySourceAllowed("arbitrary-exec", enabled) {
		t.Fatal("unknown source accepted")
	}
}

func TestDiscoveryPaginationRejectsImagesAndExcessiveValues(t *testing.T) {
	for _, query := range []string{"?limit=0", "?limit=-1", "?limit=101", "?limit=data:image/png", "?cursor=not_base64!", "?cursor=" + strings.Repeat("A", 1025)} {
		if _, _, err := discoveryPage(httptest.NewRequest("GET", "/api/discovery/applications"+query, nil)); err == nil {
			t.Fatal("accepted invalid pagination", query)
		}
	}
	cursor := discoveryCursor("openclaw")
	limit, parts, err := discoveryPage(httptest.NewRequest("GET", "/api/discovery/applications?limit=20&cursor="+cursor, nil))
	if err != nil || limit != 20 || len(parts) != 1 || parts[0] != "openclaw" {
		t.Fatal(limit, parts, err)
	}
}

func TestDiscoveryWASMResourcesReleasedAfterFailures(t *testing.T) {
	good := map[string]any{"op": "compile", "catalog": discoveryFactory}
	for range 5 {
		if err := discoveryEngine(context.Background(), good, nil); err != nil {
			t.Fatal(err)
		}
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range 60 {
		if err := discoveryEngine(context.Background(), good, nil); err != nil {
			t.Fatal(err)
		}
		if err := discoveryEngine(context.Background(), map[string]any{"op": "compile", "catalog": "data:image/png"}, nil); err == nil {
			t.Fatal("invalid type accepted")
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := discoveryEngine(ctx, good, nil); err == nil {
			t.Fatal("cancelled evaluation succeeded")
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if after.HeapAlloc > before.HeapAlloc+(8<<20) {
		t.Fatalf("retained WASM memory increased: %d -> %d", before.HeapAlloc, after.HeapAlloc)
	}
	shared, err := sharedDiscoveryRuntime()
	if err != nil {
		t.Fatal(err)
	}
	if len(shared.capacity) != 0 {
		t.Fatal("discovery worker capacity leaked")
	}
}
