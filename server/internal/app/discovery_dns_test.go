package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryDNSHintsAreNotContactsAndRequireNetworkConsent(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	credential := randomToken()
	var device string
	if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,kind,capabilities) VALUES($1,$2,'Synthetic DNS host','test','0.7.0','approved','browser','["discovery-v1"]') RETURNING id`, f.org, hash(credential)).Scan(&device); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_settings(organization_id,revision,configuration) VALUES($1,1,'{"host":true,"containers":false,"virtual_machines":false,"guest_read":false,"guest_execute":false,"http":false,"network":true,"interval_seconds":300}')`, f.org); err != nil {
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
	revision := func() int64 {
		w := call("GET", "/v1/discovery/policy", nil)
		requireHTTP(t, w, 200)
		var envelope map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
			t.Fatal(err)
		}
		raw, err := base64.StdEncoding.DecodeString(envelope["payload"])
		if err != nil {
			t.Fatal(err)
		}
		var payload struct {
			Revision int64 `json:"revision"`
		}
		if err := json.Unmarshal(raw, &payload); err != nil || payload.Revision == 0 {
			t.Fatal("missing revision", err)
		}
		return payload.Revision
	}
	rev := revision()
	now := time.Now().Unix()
	makeReport := func(sequence int) map[string]any {
		return map[string]any{"version": 1, "catalog_revision": discoveryFixtureCatalogRevision, "settings_revision": rev, "run_id": nil, "scope": "endpoint", "sequence": sequence, "page": 0, "pages": 1, "observed_at": now, "complete": false,
			"entities": []any{map[string]any{"id": "host/fixture", "kind": "host"}}, "relations": []any{}, "coverage": []any{},
			"result": map[string]any{"identifications": []any{}, "communications": []any{}, "queries": []any{map[string]any{"entity_id": "host/fixture", "provider": "openai", "evidence": map[string]any{"fact_id": "fact/dns", "source": "host_dns_query", "observed_at": now, "fields": []string{"remote_host"}}}}, "evaluated_facts": 0, "unknown_conditions": 0}}
	}
	body := makeReport(1)
	requireHTTP(t, call("POST", "/v1/discovery/reports", body), 200)
	requireHTTP(t, call("POST", "/v1/discovery/reports", body), 200)
	requireHTTP(t, call("POST", "/v1/discovery/reports", makeReport(2)), 200)
	var count, contacts, matches int
	var retention float64
	if err := f.admin.QueryRow(ctx, `SELECT count(*),coalesce(max(extract(epoch FROM expires_at-occurred_at)),0) FROM discovery_events WHERE organization_id=$1 AND device_id=$2 AND kind='provider_domain_queried'`, f.org, device).Scan(&count, &retention); err != nil || count != 1 || retention != 48*3600 {
		t.Fatal("DNS dedup/retention", count, retention, err)
	}
	if err := f.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM discovery_communications WHERE organization_id=$1 AND device_id=$2),(SELECT count(*) FROM discovery_identifications WHERE organization_id=$1 AND device_id=$2)`, f.org, device).Scan(&contacts, &matches); err != nil || contacts != 0 || matches != 0 {
		t.Fatal("DNS upgraded into contact/application", contacts, matches, err)
	}
	events := f.call("GET", "/api/discovery/events", nil, "")
	requireHTTP(t, events, 200)
	if !strings.Contains(events.Body.String(), "provider_domain_queried") {
		t.Fatal("missing DNS hint in activity")
	}
	for i, mutation := range []string{"contact", "guest", "port", "provider", "duplicate", "old", "image"} {
		body := makeReport(10 + i)
		result := body["result"].(map[string]any)
		query := result["queries"].([]any)[0].(map[string]any)
		evidence := query["evidence"].(map[string]any)
		switch mutation {
		case "contact":
			result["communications"] = result["queries"]
			result["queries"] = []any{}
		case "guest":
			body["entities"].([]any)[0].(map[string]any)["kind"] = "vm"
		case "port":
			evidence["fields"] = []string{"remote_host", "remote_port"}
		case "provider":
			query["provider"] = "unknown"
		case "duplicate":
			result["queries"] = []any{query, query}
		case "old":
			evidence["observed_at"] = now - 3601
		case "image":
			result["queries"] = "data:image/png"
		}
		w := call("POST", "/v1/discovery/reports", body)
		if w.Code < 400 {
			t.Fatalf("accepted %s: %d", mutation, w.Code)
		}
	}
	// A same-day refresh remains admissible at the event ceiling. A new hint is rejected.
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_events(organization_id,device_id,scope,entity_id,kind) SELECT $1,$2,'endpoint','host/fixture','identified' FROM generate_series(1,49999)`, f.org, device); err != nil {
		t.Fatal(err)
	}
	requireHTTP(t, call("POST", "/v1/discovery/reports", makeReport(30)), 200)
	body = makeReport(31)
	body["result"].(map[string]any)["queries"].([]any)[0].(map[string]any)["provider"] = "anthropic"
	w := call("POST", "/v1/discovery/reports", body)
	requireHTTP(t, w, 409)
	if !strings.Contains(w.Body.String(), "discovery_capacity") {
		t.Fatal("query bypassed event quota", w.Body.String())
	}
	// Move the previous event to another UTC day, making today's query a new observation.
	for _, sql := range []string{`DELETE FROM discovery_events WHERE organization_id=$1 AND device_id=$2 AND kind='identified'`, `UPDATE discovery_events SET occurred_at=occurred_at-interval '1 day',expires_at=expires_at-interval '1 day' WHERE organization_id=$1 AND device_id=$2`} {
		if _, err := f.admin.Exec(ctx, sql, f.org, device); err != nil {
			t.Fatal(err)
		}
	}
	requireHTTP(t, call("POST", "/v1/discovery/reports", makeReport(32)), 200)
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM discovery_events WHERE organization_id=$1 AND device_id=$2 AND kind='provider_domain_queried'`, f.org, device).Scan(&count); err != nil || count != 2 {
		t.Fatal("UTC day dedup", count, err)
	}
	if _, err := f.admin.Exec(ctx, `UPDATE discovery_events SET expires_at=now()-interval '1 second' WHERE organization_id=$1 AND device_id=$2`, f.org, device); err != nil {
		t.Fatal(err)
	}
	requireHTTP(t, call("POST", "/v1/discovery/reports", makeReport(33)), 200)
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM discovery_events WHERE organization_id=$1 AND device_id=$2`, f.org, device).Scan(&count); err != nil || count != 1 {
		t.Fatal("expired query cleanup", count, err)
	}
	if _, err := f.admin.Exec(ctx, `UPDATE discovery_settings SET revision=revision+1,configuration=jsonb_set(configuration,'{network}','false') WHERE organization_id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	rev = revision()
	w = call("POST", "/v1/discovery/reports", makeReport(34))
	requireHTTP(t, w, 403)
}
