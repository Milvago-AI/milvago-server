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

func TestDiscoveryIngestionPagesConsentAndVMEvidence(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	credential := randomToken()
	var device string
	if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,kind,capabilities) VALUES($1,$2,'Discovery fixture','test','0.7.0','approved','browser','["discovery-v1"]') RETURNING id`, f.org, hash(credential)).Scan(&device); err != nil {
		t.Fatal(err)
	}
	configuration := DiscoverySettings{Host: true, Containers: true, VirtualMachines: true, GuestRead: true, HTTP: true, Network: true, IntervalSeconds: 300}
	rawConfiguration, _ := json.Marshal(configuration)
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_settings(organization_id,revision,configuration) VALUES($1,700,$2)`, f.org, rawConfiguration); err != nil {
		t.Fatal(err)
	}
	call := func(method, path string, body any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(method, path, bytes.NewReader(raw))
		r.Header.Set("Authorization", "Bearer "+credential)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.a.Handler().ServeHTTP(w, r)
		return w
	}
	signed := call("GET", "/v1/discovery/policy", nil)
	requireHTTP(t, signed, 200)
	var envelope map[string]string
	if json.Unmarshal(signed.Body.Bytes(), &envelope) != nil {
		t.Fatal("invalid policy envelope")
	}
	payload, _ := base64.StdEncoding.DecodeString(envelope["payload"])
	signature, _ := base64.StdEncoding.DecodeString(envelope["signature"])
	if !ed25519.Verify(f.a.policyKey(f.org).Public().(ed25519.PublicKey), payload, signature) {
		t.Fatal("discovery policy signature is invalid")
	}
	var delivered struct {
		Revision int64 `json:"revision"`
	}
	if json.Unmarshal(payload, &delivered) != nil || delivered.Revision <= 0 {
		t.Fatal("missing discovery authorization revision")
	}
	now := time.Now().Unix()
	base := map[string]any{"version": 1, "catalog_revision": discoveryFixtureCatalogRevision, "settings_revision": delivered.Revision, "run_id": nil, "scope": "endpoint", "sequence": 100, "page": 0, "pages": 2, "observed_at": now, "complete": true, "coverage": []any{}, "relations": []any{}}
	base["entities"] = []any{map[string]string{"id": "process/1/start-1", "kind": "process"}}
	base["result"] = map[string]any{"identifications": []any{map[string]any{"application_id": "openclaw", "signature_id": "openclaw.process", "signature_revision": 1, "entity_id": "process/1/start-1", "state": "executed", "evidence": []any{map[string]any{"fact_id": "fact/1", "source": "host_process", "observed_at": now, "fields": []string{"executable"}}}}}, "communications": []any{}, "evaluated_facts": 0, "unknown_conditions": 0}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_entities(organization_id,device_id,scope,id,kind,sequence) VALUES($1,$2,'endpoint','process/old','process',99)`, f.org, device); err != nil {
		t.Fatal(err)
	}
	requireHTTP(t, call("POST", "/v1/discovery/reports", base), 200)
	var old int
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM discovery_entities WHERE id='process/old'`).Scan(&old); err != nil || old != 1 {
		t.Fatal("incomplete snapshot erased older evidence", old, err)
	}
	requireHTTP(t, call("POST", "/v1/discovery/reports", base), 200)
	page := map[string]any{}
	for key, value := range base {
		page[key] = value
	}
	page["page"] = 1
	page["entities"] = []any{map[string]any{"id": "vm/hidden", "kind": "vm", "display": map[string]string{"name": "Synthetic guest"}}}
	page["result"] = map[string]any{"identifications": []any{}, "communications": []any{map[string]any{"entity_id": "vm/hidden", "provider": "openai", "evidence": map[string]any{"fact_id": "fact/2", "source": "vm_flow", "observed_at": now, "fields": []string{"remote_host"}}}}, "evaluated_facts": 0, "unknown_conditions": 0}
	requireHTTP(t, call("POST", "/v1/discovery/reports", page), 200)
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM discovery_entities WHERE id='process/old'`).Scan(&old); err != nil || old != 0 {
		t.Fatal("complete snapshot did not retire old entities", old, err)
	}
	var identified, communications int
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM discovery_identifications WHERE entity_id='vm/hidden'`).Scan(&identified); err != nil || identified != 0 {
		t.Fatal("network-only VM became an application", identified, err)
	}
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM discovery_communications WHERE entity_id='vm/hidden' AND provider='openai'`).Scan(&communications); err != nil || communications != 1 {
		t.Fatal("VM communication missing", communications, err)
	}
	requireHTTP(t, f.call("GET", "/api/discovery/applications", nil, ""), 200)
	requireHTTP(t, f.call("GET", "/api/discovery/environments", nil, ""), 200)
	environment := f.call("GET", "/api/discovery/environments/vm%2Fhidden?device_id="+device+"&scope=endpoint", nil, "")
	requireHTTP(t, environment, 200)
	if !strings.Contains(environment.Body.String(), "Synthetic guest") {
		t.Fatal("environment display metadata was not retained")
	}
	history := f.call("GET", "/api/discovery/events", nil, "")
	requireHTTP(t, history, 200)
	if strings.Contains(history.Body.String(), "hostname") || strings.Contains(history.Body.String(), "CommandLine") || strings.Contains(history.Body.String(), "http_body") {
		t.Fatal("raw collection content escaped into the activity view")
	}
	base["complete"] = false
	requireHTTP(t, call("POST", "/v1/discovery/reports", base), 409)
	base["complete"] = true
	base["sequence"] = 99
	requireHTTP(t, call("POST", "/v1/discovery/reports", base), 409)
	if _, err := f.admin.Exec(ctx, `UPDATE discovery_settings SET revision=701 WHERE organization_id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	page["sequence"] = 101
	requireHTTP(t, call("POST", "/v1/discovery/reports", page), 409)
	// Even a new authorization revision cannot authorize a disabled source.
	configuration.Host = false
	rawConfiguration, _ = json.Marshal(configuration)
	if _, err := f.admin.Exec(ctx, `UPDATE discovery_settings SET configuration=$2 WHERE organization_id=$1`, f.org, rawConfiguration); err != nil {
		t.Fatal(err)
	}
	fresh := call("GET", "/v1/discovery/policy", nil)
	requireHTTP(t, fresh, 200)
	if json.Unmarshal(fresh.Body.Bytes(), &envelope) != nil {
		t.Fatal("invalid discovery envelope")
	}
	payload, _ = base64.StdEncoding.DecodeString(envelope["payload"])
	if json.Unmarshal(payload, &delivered) != nil {
		t.Fatal("invalid discovery authorization")
	}
	base["settings_revision"] = delivered.Revision
	base["sequence"] = 101
	requireHTTP(t, call("POST", "/v1/discovery/reports", base), 403)
}

func TestDiscoveryEnvironmentScopeAndRelationshipPagination(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	var device string
	if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,kind) VALUES($1,$2,'Synthetic paging host','test','0.7.0','approved','browser') RETURNING id`, f.org, hash(randomToken())).Scan(&device); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_entities(organization_id,device_id,scope,id,kind,sequence,display) VALUES ($1,$2,'first','vm/shared','vm',1,'{"name":"First guest"}'),($1,$2,'second','vm/shared','vm',1,'{"name":"Second guest"}')`, f.org, device); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_entities(organization_id,device_id,scope,id,kind,sequence) SELECT $1,$2,'first','process/'||lpad(n::text,3,'0'),'process',1 FROM generate_series(1,102) n`, f.org, device); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_relations(organization_id,device_id,scope,source_id,target_id,kind,source,sequence) SELECT $1,$2,'first','vm/shared','process/'||lpad(n::text,3,'0'),'contains','fixture',1 FROM generate_series(1,102) n`, f.org, device); err != nil {
		t.Fatal(err)
	}
	path := "/api/discovery/environments/vm%2Fshared?device_id=" + device
	other := f.call("GET", path+"&scope=second", nil, "")
	requireHTTP(t, other, 200)
	if !strings.Contains(other.Body.String(), "Second guest") || strings.Contains(other.Body.String(), "process/") {
		t.Fatal("requested environment scope was ignored")
	}
	cursor := ""
	seen := map[string]bool{}
	for page := 0; page < 3; page++ {
		response := f.call("GET", path+"&scope=first&limit=50&cursor="+cursor, nil, "")
		requireHTTP(t, response, 200)
		var body struct {
			Relations []struct {
				To string `json:"to"`
			} `json:"relations"`
			Next string `json:"relations_next_cursor"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if len(body.Relations) > 50 {
			t.Fatal("unbounded relationship page")
		}
		for _, row := range body.Relations {
			if seen[row.To] {
				t.Fatal("duplicate relationship across cursor pages")
			}
			seen[row.To] = true
		}
		cursor = body.Next
		if (page < 2) != (cursor != "") {
			t.Fatal("incorrect relationship continuation")
		}
	}
	if len(seen) != 102 {
		t.Fatal("relationships were silently truncated", len(seen))
	}
	requireHTTP(t, f.call("GET", path+"&scope=missing", nil, ""), 404)
	requireHTTP(t, f.call("GET", path+"&scope=first&cursor="+discoveryCursor("bad"), nil, ""), 400)
}

func TestDiscoveryDraftRevisionAndSensitiveWrites(t *testing.T) {
	f := newObservabilityFixture(t)
	draft := map[string]any{"source": string(discoveryFactory), "revision": 0}
	saved := f.call("PUT", "/api/discovery/catalog/draft", draft, f.csrf)
	requireHTTP(t, saved, 200)
	var result struct {
		Revision int64 `json:"revision"`
	}
	if json.Unmarshal(saved.Body.Bytes(), &result) != nil || result.Revision == 0 {
		t.Fatal("draft revision missing")
	}
	requireHTTP(t, f.call("PUT", "/api/discovery/catalog/draft", draft, f.csrf), 409)
	draft["revision"] = result.Revision
	requireHTTP(t, f.call("PUT", "/api/discovery/catalog/draft", draft, f.csrf), 200)
	// A save-only credential must not turn publication into a non-interactive operation.
	request := httptest.NewRequest("POST", "/api/discovery/catalog/publish", strings.NewReader(`{"revision":1,"reason":"fixture publication"}`))
	request.Header.Set("Authorization", "Bearer invalid")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	f.a.Handler().ServeHTTP(response, request)
	if response.Code != 403 || !strings.Contains(response.Body.String(), "session_required") {
		t.Fatalf("publication did not require a session: %d %s", response.Code, response.Body.String())
	}
}

func TestDiscoverySensitiveChangesRequireFreshMFAAndKeepAuditReason(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	configuration := DiscoverySettings{Host: true, IntervalSeconds: 300}
	body := map[string]any{"revision": 0, "configuration": configuration, "reason": "Synthetic inventory activation"}
	requireHTTP(t, f.call("PUT", "/api/discovery/settings", body, f.csrf), 403)
	if _, err := f.admin.Exec(ctx, `UPDATE sessions SET mfa_verified_at=now() WHERE user_id=$1`, f.user); err != nil {
		t.Fatal(err)
	}
	requireHTTP(t, f.call("PUT", "/api/discovery/settings", body, f.csrf), 200)
	var count int
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM audit WHERE organization_id=$1 AND action='discovery.settings.update' AND details->>'reason'='Synthetic inventory activation' AND details->'configuration'->>'host'='true'`, f.org).Scan(&count); err != nil || count != 1 {
		t.Fatal("activation reason/configuration not audited", count, err)
	}
	draft := f.call("GET", "/api/discovery/catalog/draft", nil, "")
	requireHTTP(t, draft, 200)
	var decoded struct {
		Published json.RawMessage `json:"published"`
	}
	if json.Unmarshal(draft.Body.Bytes(), &decoded) != nil || len(decoded.Published) == 0 {
		t.Fatal("published catalogue missing from preview")
	}
	saved := f.call("PUT", "/api/discovery/catalog/draft", map[string]any{"source": string(discoveryFactory), "revision": 0}, f.csrf)
	requireHTTP(t, saved, 200)
	var revision struct {
		Revision int64 `json:"revision"`
	}
	if json.Unmarshal(saved.Body.Bytes(), &revision) != nil {
		t.Fatal("invalid draft revision")
	}
	requireHTTP(t, f.call("POST", "/api/discovery/catalog/publish", map[string]any{"revision": revision.Revision, "reason": "Synthetic catalogue publication"}, f.csrf), 200)
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM audit WHERE organization_id=$1 AND action='discovery.catalog.publish' AND details->>'reason'='Synthetic catalogue publication' AND (details->>'revision')::bigint>0`, f.org).Scan(&count); err != nil || count != 1 {
		t.Fatal("publication reason/revision not audited", count, err)
	}
}
