package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryPublishedGuestHTTPCatalogueReachesSignedPolicyAndInventory(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	credential := randomToken()
	var device string
	if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,kind,capabilities) VALUES($1,$2,'Synthetic catalogue host','test','0.7.0','approved','browser','["discovery-v1"]') RETURNING id`, f.org, hash(credential)).Scan(&device); err != nil {
		t.Fatal(err)
	}
	configuration := DiscoverySettings{VirtualMachines: true, GuestRead: true, GuestExecute: true, HTTP: true, IntervalSeconds: 300}
	rawConfiguration, _ := json.Marshal(configuration)
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_settings(organization_id,revision,configuration) VALUES($1,700,$2)`, f.org, rawConfiguration); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `UPDATE sessions SET mfa_verified_at=now() WHERE user_id=$1`, f.user); err != nil {
		t.Fatal(err)
	}
	source := `version: 1
revision: 1
http_paths: [/health]
signatures:
  - id: fixture.private-http
    application_id: fixture-http
    name: Synthetic private service
    revision: 1
    sources: [http]
    state: interface_recognized
    condition:
      op: all
      args:
        - {op: eq, field: http_path, value: /health}
        - {op: eq, field: http_status, value: "200"}
        - {op: eq, field: http_body, value: PRIVATE_HTTP_BODY}
    provenance: Synthetic qualification signature
`
	saved := f.call("PUT", "/api/discovery/catalog/draft", map[string]any{"source": source, "revision": 0}, f.csrf)
	requireHTTP(t, saved, 200)
	var draft struct {
		Revision int64 `json:"revision"`
	}
	if err := json.Unmarshal(saved.Body.Bytes(), &draft); err != nil || draft.Revision <= 0 {
		t.Fatal("missing draft revision", err)
	}
	published := f.call("POST", "/api/discovery/catalog/publish", map[string]any{"revision": draft.Revision, "reason": "Synthetic catalogue journey"}, f.csrf)
	requireHTTP(t, published, 200)
	var publication struct {
		Revision int64 `json:"revision"`
	}
	if err := json.Unmarshal(published.Body.Bytes(), &publication); err != nil || publication.Revision <= 1 {
		t.Fatal("missing publication revision", err)
	}
	call := func(method, path string, body any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		request := httptest.NewRequest(method, path, bytes.NewReader(raw))
		request.Header.Set("Authorization", "Bearer "+credential)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		f.a.Handler().ServeHTTP(response, request)
		return response
	}
	response := call("GET", "/v1/discovery/policy", nil)
	requireHTTP(t, response, 200)
	var envelope map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope["payload"])
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.DecodeString(envelope["signature"])
	if err != nil || !ed25519.Verify(f.a.policyKey(f.org).Public().(ed25519.PublicKey), payload, signature) {
		t.Fatal("policy signature does not verify")
	}
	var policy struct {
		DeviceID string          `json:"device_id"`
		Revision int64           `json:"revision"`
		Catalog  json.RawMessage `json:"catalog"`
	}
	if err := json.Unmarshal(payload, &policy); err != nil || policy.DeviceID != device || policy.Revision <= 0 {
		t.Fatal("policy lost its device scope", err)
	}
	var delivered struct {
		Revision  int64    `json:"revision"`
		HTTPPaths []string `json:"http_paths"`
	}
	if err := json.Unmarshal(policy.Catalog, &delivered); err != nil || delivered.Revision != publication.Revision || len(delivered.HTTPPaths) != 1 || delivered.HTTPPaths[0] != "/health" {
		t.Fatal("published plan did not reach the signed policy", err)
	}
	now := time.Now().Unix()
	entities := []any{map[string]any{"id": "vm/fixture", "kind": "vm", "display": map[string]string{"name": "Synthetic private guest"}}, map[string]any{"id": "endpoint/fixture", "kind": "endpoint", "display": map[string]any{"address": "127.0.0.1:32145"}}}
	relations := []any{map[string]string{"from": "vm/fixture", "to": "endpoint/fixture", "kind": "observed_origin", "source": "guest-channel-http-connection"}}
	coverage := []any{map[string]any{"scope": "vm/fixture", "adapter": "guest-http", "status": "partial", "checked_at": now, "complete": false}}
	snapshot := map[string]any{"version": 1, "scope": "endpoint", "sequence": 1, "observed_at": now, "complete": false, "entities": entities, "relations": relations, "coverage": coverage,
		"facts": []any{map[string]any{"id": "http/fixture", "entity_id": "endpoint/fixture", "source": "http", "observed_at": now, "fields": map[string]any{"http_path": []string{"/health"}, "http_status": []string{"200"}, "http_body": []string{"PRIVATE_HTTP_BODY"}}}}}
	// Exercise the shipped WASM engine through the same simulation API as the editor.
	evaluated := f.call("POST", "/api/discovery/catalog/evaluate", map[string]any{"source": string(policy.Catalog), "snapshot": snapshot}, f.csrf)
	requireHTTP(t, evaluated, 200)
	var evaluation struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(evaluated.Body.Bytes(), &evaluation); err != nil || len(evaluation.Result) == 0 {
		t.Fatal("missing evaluated result", err)
	}
	if bytes.Contains(evaluation.Result, []byte("PRIVATE_HTTP_BODY")) {
		t.Fatal("HTTP body escaped the engine")
	}
	var matches struct {
		Identifications []discoveryMatch `json:"identifications"`
	}
	if err := json.Unmarshal(evaluation.Result, &matches); err != nil || len(matches.Identifications) != 1 || matches.Identifications[0].State != "interface_recognized" {
		t.Fatal("custom signature was not recognized", err)
	}
	report := map[string]any{"version": 1, "catalog_revision": 1, "settings_revision": policy.Revision, "run_id": nil, "scope": "endpoint", "sequence": 1, "page": 0, "pages": 1, "observed_at": now, "complete": false,
		"entities": entities, "relations": relations, "coverage": coverage, "result": evaluation.Result}
	requireHTTP(t, call("POST", "/v1/discovery/reports", report), 400)
	report["catalog_revision"] = publication.Revision
	requireHTTP(t, call("POST", "/v1/discovery/reports", report), 200)
	for _, path := range []string{"/api/discovery/applications", "/api/discovery/applications/fixture-http/instances", "/api/discovery/applications/fixture-http/locations", "/api/discovery/events", "/api/discovery/coverage", "/api/discovery/environments/vm%2Ffixture?device_id=" + device + "&scope=endpoint"} {
		view := f.call("GET", path, nil, "")
		requireHTTP(t, view, 200)
		if strings.Contains(view.Body.String(), "PRIVATE_HTTP_BODY") || strings.Contains(view.Body.String(), `"http_body":`) {
			t.Fatal("raw HTTP body escaped into an inventory view", path)
		}
		if strings.HasSuffix(path, "/instances") && !strings.Contains(view.Body.String(), "interface_recognized") {
			t.Fatal("proof state missing from instances")
		}
		if strings.HasSuffix(path, "/locations") && !strings.Contains(view.Body.String(), device) {
			t.Fatal("device group missing from locations")
		}
		if strings.Contains(path, "/environments/") && (!strings.Contains(view.Body.String(), "Synthetic private guest") || !strings.Contains(view.Body.String(), "endpoint/fixture")) {
			t.Fatal("guest origin missing from environment details")
		}
	}
}
