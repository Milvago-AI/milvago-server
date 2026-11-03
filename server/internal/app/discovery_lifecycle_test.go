package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDiscoveryCompleteProcessSourcesRetireOnlyTheirOwnEvidenceAfterAllPages(t *testing.T) {
	for _, scenario := range []struct {
		platform            string
		interpreterComplete bool
		retireHost          bool
		guestAdapter        string
		retireGuest         bool
		evaluationFailed    bool
	}{
		{"linux", false, true, "libvirt-guest", true, false}, {"windows", false, false, "hyper-v-guest", true, false}, {"windows", true, true, "virtualbox-guest", true, false}, {"unknown", true, false, "libvirt-guest", true, false},
		{"unknown", false, false, "unrecognized-guest", false, false},
		{"windows", true, true, "vmware-guest", true, false},
		{"linux", false, false, "libvirt-guest", false, true},
	} {
		t.Run(scenario.platform+map[bool]string{true: "/interpreter-complete", false: "/interpreter-partial"}[scenario.interpreterComplete], func(t *testing.T) {
			f := newObservabilityFixture(t)
			ctx := context.Background()
			credential := randomToken()
			var device string
			if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,capabilities) VALUES($1,$2,'Synthetic lifecycle host',$3,'0.7.0','approved','["discovery-v1"]') RETURNING id`, f.org, hash(credential), scenario.platform).Scan(&device); err != nil {
				t.Fatal(err)
			}
			if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_settings(organization_id,revision,configuration) VALUES($1,1,'{"host":true,"containers":false,"virtual_machines":true,"guest_read":true,"guest_execute":true,"http":false,"network":true,"interval_seconds":300}')`, f.org); err != nil {
				t.Fatal(err)
			}
			call := func(path string, body any) *httptest.ResponseRecorder {
				raw, _ := json.Marshal(body)
				method := "POST"
				if body == nil {
					method = "GET"
				}
				r := httptest.NewRequest(method, path, bytes.NewReader(raw))
				r.Header.Set("Authorization", "Bearer "+credential)
				r.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				f.a.Handler().ServeHTTP(w, r)
				return w
			}
			policy := call("/v1/discovery/policy", nil)
			requireHTTP(t, policy, 200)
			var envelope struct {
				Payload string `json:"payload"`
			}
			if err := json.Unmarshal(policy.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
			if err != nil {
				t.Fatal(err)
			}
			var authorization struct {
				Revision int64 `json:"revision"`
			}
			if err = json.Unmarshal(payload, &authorization); err != nil {
				t.Fatal(err)
			}
			for _, statement := range []string{
				`INSERT INTO discovery_entities(organization_id,device_id,scope,id,kind,sequence) VALUES($1,$2,'endpoint','host/root','host',1),($1,$2,'endpoint','vm/one','vm',1),($1,$2,'endpoint','vm/two','vm',1),($1,$2,'endpoint','process/host','process',1),($1,$2,'endpoint','process/guest-one','process',1),($1,$2,'endpoint','process/guest-two','process',1)`,
				`INSERT INTO discovery_relations(organization_id,device_id,scope,source_id,target_id,kind,source,sequence) VALUES($1,$2,'endpoint','vm/one','process/guest-one','contains','guest-tools',1),($1,$2,'endpoint','vm/two','process/guest-two','contains','guest-tools',1)`,
				`INSERT INTO discovery_identifications(organization_id,device_id,scope,entity_id,application_id,signature_id,signature_revision,state,evidence,sequence) VALUES
($1,$2,'endpoint','process/host','openclaw','openclaw.process',1,'executed','[{"fact_id":"old/host","source":"host_process","observed_at":1,"fields":["executable"]}]',1),
($1,$2,'endpoint','process/guest-one','openclaw','openclaw.process',1,'executed','[{"fact_id":"old/guest-one","source":"guest_process","observed_at":1,"fields":["executable"]}]',1),
($1,$2,'endpoint','process/guest-two','openclaw','openclaw.process',1,'executed','[{"fact_id":"old/guest-two","source":"guest_process","observed_at":1,"fields":["executable"]}]',1)`,
				`INSERT INTO discovery_communications(organization_id,device_id,scope,entity_id,provider,sequence,last_seen,evidence,expires_at) VALUES($1,$2,'endpoint','vm/one','openai',1,now(),'{}',now()+interval '1 hour')`,
			} {
				if _, err = f.admin.Exec(ctx, statement, f.org, device); err != nil {
					t.Fatal(err)
				}
			}
			remaining := func(entity string) int {
				t.Helper()
				var count int
				if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM discovery_identifications WHERE organization_id=$1 AND device_id=$2 AND entity_id=$3`, f.org, device, entity).Scan(&count); err != nil {
					t.Fatal(err)
				}
				return count
			}
			now := time.Now().Unix()
			coverage := func(scope, adapter, status string, complete bool) map[string]any {
				return map[string]any{"scope": scope, "adapter": adapter, "status": status, "complete": complete, "checked_at": now}
			}
			report := map[string]any{"version": 1, "catalog_revision": discoveryFixtureCatalogRevision, "settings_revision": authorization.Revision, "run_id": nil, "scope": "endpoint", "sequence": 2, "page": 0, "pages": 2, "observed_at": now, "complete": false, "entities": []any{map[string]string{"id": "host/root", "kind": "host"}, map[string]string{"id": "vm/one", "kind": "vm"}, map[string]string{"id": "vm/two", "kind": "vm"}}, "relations": []any{}, "result": map[string]any{"identifications": []any{}, "communications": []any{}, "evaluated_facts": 0, "unknown_conditions": 0}}
			report["coverage"] = []any{coverage("endpoint", "host", "available", true), coverage("endpoint", "windows-interpreter-entries", map[bool]string{true: "available", false: "partial"}[scenario.interpreterComplete], scenario.interpreterComplete)}
			if scenario.evaluationFailed {
				report["coverage"] = append(report["coverage"].([]any), coverage("endpoint", "detection-engine", "saturated", false))
			}
			requireHTTP(t, call("/v1/discovery/reports", report), 200)
			if remaining("process/host") != 1 {
				t.Fatal("an incomplete delivery retired host evidence")
			}
			report["page"] = 1
			report["coverage"] = []any{coverage("vm/one", scenario.guestAdapter, "denied", false)}
			requireHTTP(t, call("/v1/discovery/reports", report), 200)
			if (remaining("process/host") == 0) != scenario.retireHost || remaining("process/guest-one") != 1 || remaining("process/guest-two") != 1 {
				t.Fatal("source failure or another platform altered retirement scope")
			}
			report["sequence"] = 3
			report["page"] = 0
			report["pages"] = 1
			report["coverage"] = []any{coverage("endpoint", "host", "partial", false), coverage("vm/one", scenario.guestAdapter, "available", true)}
			if scenario.evaluationFailed {
				report["coverage"] = append(report["coverage"].([]any), coverage("endpoint", "detection-engine", "saturated", false))
			}
			requireHTTP(t, call("/v1/discovery/reports", report), 200)
			if (remaining("process/guest-one") == 0) != scenario.retireGuest || remaining("process/guest-two") != 1 {
				t.Fatal("guest completeness crossed VM boundaries or failed to retire old execution")
			}
			var communications int
			if err = f.admin.QueryRow(ctx, `SELECT count(*) FROM discovery_communications WHERE organization_id=$1 AND device_id=$2`, f.org, device).Scan(&communications); err != nil || communications != 1 {
				t.Fatal("process inventory manufactured absence of provider traffic", err)
			}
		})
	}
}
