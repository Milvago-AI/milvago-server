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

func TestDiscoveryCapacityBoundsEveryMetadataFamilyAndPublishesRejections(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	credential := randomToken()
	var device string
	if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,kind,capabilities) VALUES($1,$2,'Synthetic capacity host','test','0.7.0','approved','browser','["discovery-v1"]') RETURNING id`, f.org, hash(credential)).Scan(&device); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_settings(organization_id,revision,configuration) VALUES($1,1,'{"host":true,"containers":false,"virtual_machines":false,"guest_read":false,"guest_execute":false,"http":true,"network":true,"interval_seconds":300}')`, f.org); err != nil {
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
	policy := call("GET", "/v1/discovery/policy", nil)
	requireHTTP(t, policy, 200)
	var envelope map[string]string
	if json.Unmarshal(policy.Body.Bytes(), &envelope) != nil {
		t.Fatal("bad synthetic policy")
	}
	payload, _ := base64.StdEncoding.DecodeString(envelope["payload"])
	var delivered struct {
		Revision int64 `json:"revision"`
	}
	if json.Unmarshal(payload, &delivered) != nil || delivered.Revision == 0 {
		t.Fatal("missing synthetic revision")
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_entities(organization_id,device_id,scope,id,kind,sequence) SELECT $1,$2,'endpoint','host/'||n,'host',1 FROM generate_series(0,23899)n`, f.org, device); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_entities(organization_id,device_id,scope,id,kind,sequence) SELECT $1,$2,'endpoint','endpoint/'||n,'endpoint',1 FROM generate_series(0,99)n`, f.org, device); err != nil {
		t.Fatal(err)
	}
	makeReport := func(sequence int) map[string]any {
		return map[string]any{
			"version": 1, "catalog_revision": discoveryFixtureCatalogRevision, "settings_revision": delivered.Revision, "run_id": nil, "scope": "endpoint", "sequence": sequence, "page": 0, "pages": 1, "observed_at": time.Now().Unix(), "complete": false,
			"entities": []any{map[string]string{"id": "host/20000", "kind": "host"}, map[string]string{"id": "endpoint/99", "kind": "endpoint"}}, "relations": []any{}, "coverage": []any{},
			"result": map[string]any{"identifications": []any{}, "communications": []any{}, "evaluated_facts": 0, "unknown_conditions": 0},
		}
	}
	match := func() map[string]any {
		return map[string]any{"application_id": "ollama", "signature_id": "ollama.installation", "signature_revision": 1, "entity_id": "host/20000", "state": "installed", "evidence": []any{map[string]any{"fact_id": "fact/package", "source": "installation", "observed_at": time.Now().Unix(), "fields": []string{"package"}}}}
	}
	cases := []struct {
		name, seed string
		change     func(map[string]any)
	}{
		{"entities", "", func(body map[string]any) {
			body["entities"] = []any{map[string]string{"id": "process/new", "kind": "process"}}
		}},
		{"identifications", `INSERT INTO discovery_identifications(organization_id,device_id,scope,entity_id,application_id,signature_id,signature_revision,state,evidence,sequence) SELECT $1,$2,'endpoint','host/'||n,app,app||'.installation',1,'installed','[]',1 FROM generate_series(0,15999)n CROSS JOIN unnest(ARRAY['ollama','openclaw','hermes'])app`, func(body map[string]any) { body["result"].(map[string]any)["identifications"] = []any{match()} }},
		{"communications", `INSERT INTO discovery_communications(organization_id,device_id,scope,entity_id,provider,sequence,last_seen,evidence) SELECT $1,$2,'endpoint','host/'||n,'openai',1,now(),'{}' FROM generate_series(0,15999)n`, func(body map[string]any) {
			body["result"].(map[string]any)["communications"] = []any{map[string]any{"entity_id": "host/20000", "provider": "openai", "evidence": map[string]any{"fact_id": "fact/network", "source": "host_flow", "observed_at": time.Now().Unix(), "fields": []string{"remote_host"}}}}
		}},
		{"relationships", `INSERT INTO discovery_relations(organization_id,device_id,scope,source_id,target_id,kind,source,sequence) SELECT $1,$2,'endpoint','host/'||h,'endpoint/'||e,'observed_origin','fixture',1 FROM generate_series(0,499)h CROSS JOIN generate_series(0,95)e`, func(body map[string]any) {
			body["relations"] = []any{map[string]string{"from": "host/20000", "to": "endpoint/99", "kind": "observed_origin", "source": "fixture"}}
		}},
		{"visibility", `INSERT INTO discovery_coverage(organization_id,device_id,scope,adapter,status,complete,checked_at,sequence) SELECT $1,$2,'endpoint','fixture/'||n,'partial',false,now(),1 FROM generate_series(0,2047)n`, func(body map[string]any) {
			body["coverage"] = []any{map[string]any{"scope": "endpoint", "adapter": "fixture/new", "status": "partial", "complete": false, "checked_at": time.Now().Unix()}}
		}},
		{"history", `INSERT INTO discovery_events(organization_id,device_id,scope,entity_id,kind) SELECT $1,$2,'endpoint','host/0','identified' FROM generate_series(1,50000)`, func(body map[string]any) { body["result"].(map[string]any)["identifications"] = []any{match()} }},
	}
	for index, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			for _, table := range []string{"discovery_identifications", "discovery_communications", "discovery_relations", "discovery_coverage", "discovery_events"} {
				if _, err := f.admin.Exec(ctx, `DELETE FROM `+table+` WHERE organization_id=$1 AND device_id=$2`, f.org, device); err != nil {
					t.Fatal(err)
				}
			}
			if test.seed != "" {
				if _, err := f.admin.Exec(ctx, test.seed, f.org, device); err != nil {
					t.Fatal(err)
				}
			}
			body := makeReport(100 + index)
			test.change(body)
			response := call("POST", "/v1/discovery/reports", body)
			requireHTTP(t, response, 409)
			if !strings.Contains(response.Body.String(), "discovery_capacity") {
				t.Fatal("unexpected rejection", response.Body.String())
			}
			var markers, scans int
			if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM discovery_coverage WHERE organization_id=$1 AND device_id=$2 AND scope='server' AND adapter='ingest-capacity' AND status='saturated' AND NOT complete`, f.org, device).Scan(&markers); err != nil || markers != 1 {
				t.Fatal("capacity rejection was not visible", markers, err)
			}
			if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM discovery_scans WHERE organization_id=$1 AND device_id=$2`, f.org, device).Scan(&scans); err != nil || scans != 0 {
				t.Fatal("rejected page advanced its ledger", scans, err)
			}
		})
	}
	for _, table := range []string{"discovery_identifications", "discovery_communications", "discovery_relations", "discovery_events"} {
		if _, err := f.admin.Exec(ctx, `DELETE FROM `+table+` WHERE organization_id=$1 AND device_id=$2`, f.org, device); err != nil {
			t.Fatal(err)
		}
	}
	// A refresh at the entity ceiling is still accepted; an identity cannot
	// change kind, and an endpoint cannot forge the server-owned visibility row.
	body := makeReport(200)
	body["entities"] = []any{map[string]string{"id": "host/20000", "kind": "process"}}
	response := call("POST", "/v1/discovery/reports", body)
	requireHTTP(t, response, 409)
	if !strings.Contains(response.Body.String(), "discovery_identity_conflict") {
		t.Fatal("entity identity was allowed to change kind")
	}
	requireHTTP(t, call("POST", "/v1/discovery/reports", makeReport(201)), 200)
	var markers int
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM discovery_coverage WHERE organization_id=$1 AND device_id=$2 AND scope='server'`, f.org, device).Scan(&markers); err != nil || markers != 0 {
		t.Fatal("capacity recovery retained its warning", err)
	}
	body = makeReport(202)
	body["scope"] = "server"
	requireHTTP(t, call("POST", "/v1/discovery/reports", body), 400)
}
