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

func TestDiscoveryGuestHTTPReportRequiresEveryGuestPermission(t *testing.T) {
	for _, input := range []string{
		`{"relations":[{"from":"vm/fixture","to":"endpoint/fixture","kind":"observed_origin","source":"guest-channel-http-connection"}]}`,
		`{"coverage":[{"scope":"vm/fixture","adapter":"guest-http","status":"partial","checked_at":100,"complete":false}]}`,
	} {
		var report discoveryReport
		if err := json.Unmarshal([]byte(input), &report); err != nil {
			t.Fatal(err)
		}
		for mask := 0; mask < 16; mask++ {
			configuration := DiscoverySettings{VirtualMachines: mask&1 != 0, GuestRead: mask&2 != 0, GuestExecute: mask&4 != 0, HTTP: mask&8 != 0}
			if got := discoveryGuestHTTPReportAllowed(report, configuration); got != (mask == 15) {
				t.Fatalf("guest HTTP permission decision for mask %d: %v", mask, got)
			}
		}
	}
	// Ordinary host HTTP does not acquire guest execution requirements.
	var host discoveryReport
	if err := json.Unmarshal([]byte(`{"relations":[{"from":"host/fixture","to":"endpoint/fixture","kind":"owns_endpoint","source":"socket-map"}],"coverage":[{"scope":"host/fixture","adapter":"http","status":"available","checked_at":100,"complete":true}]}`), &host); err != nil {
		t.Fatal(err)
	}
	if !discoveryGuestHTTPReportAllowed(host, DiscoverySettings{Host: true, HTTP: true}) {
		t.Fatal("host HTTP incorrectly required guest permissions")
	}
	var exposed discoveryReport
	if err := json.Unmarshal([]byte(`{"relations":[{"from":"vm/fixture","to":"endpoint/fixture","kind":"observed_origin","source":"libvirt-tap-http-connection"}]}`), &exposed); err != nil {
		t.Fatal(err)
	}
	if !discoveryGuestHTTPReportAllowed(exposed, DiscoverySettings{VirtualMachines: true, HTTP: true}) {
		t.Fatal("an exposed VM endpoint incorrectly required guest tools access")
	}
}

func TestDiscoveryGuestHTTPIngestionRejectsAnUnconsentedChannelBeforeStorage(t *testing.T) {
	for _, proof := range []string{"relation", "coverage"} {
		t.Run(proof, func(t *testing.T) {
			f := newObservabilityFixture(t)
			ctx := context.Background()
			credential := randomToken()
			var device string
			if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,kind,capabilities) VALUES($1,$2,'Synthetic guest HTTP host','test','0.7.0','approved','browser','["discovery-v1"]') RETURNING id`, f.org, hash(credential)).Scan(&device); err != nil {
				t.Fatal(err)
			}
			configuration := DiscoverySettings{VirtualMachines: true, GuestRead: true, HTTP: true, IntervalSeconds: 300}
			rawConfiguration, _ := json.Marshal(configuration)
			if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_settings(organization_id,revision,configuration) VALUES($1,700,$2)`, f.org, rawConfiguration); err != nil {
				t.Fatal(err)
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
			policyRevision := func() int64 {
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
				var policy struct {
					Revision int64 `json:"revision"`
				}
				if err := json.Unmarshal(payload, &policy); err != nil || policy.Revision <= 0 {
					t.Fatal("invalid discovery policy revision", err)
				}
				return policy.Revision
			}
			now := time.Now().Unix()
			report := map[string]any{"version": 1, "catalog_revision": discoveryFixtureCatalogRevision, "settings_revision": policyRevision(), "run_id": nil, "scope": "endpoint", "sequence": 1, "page": 0, "pages": 1, "observed_at": now, "complete": false,
				"entities":  []any{map[string]string{"id": "vm/fixture", "kind": "vm"}, map[string]string{"id": "endpoint/fixture", "kind": "endpoint"}},
				"relations": []any{}, "coverage": []any{},
				"result": map[string]any{"identifications": []any{}, "communications": []any{}, "evaluated_facts": 0, "unknown_conditions": 0}}
			if proof == "relation" {
				report["relations"] = []any{map[string]string{"from": "vm/fixture", "to": "endpoint/fixture", "kind": "observed_origin", "source": "guest-channel-http-connection"}}
			} else {
				report["coverage"] = []any{map[string]any{"scope": "vm/fixture", "adapter": "guest-http", "status": "partial", "checked_at": now, "complete": false}}
			}
			requireHTTP(t, call("POST", "/v1/discovery/reports", report), 403)
			var stored int
			if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM discovery_entities WHERE organization_id=$1 AND device_id=$2`, f.org, device).Scan(&stored); err != nil || stored != 0 {
				t.Fatal("unconsented guest data was stored", stored, err)
			}
			configuration.GuestExecute = true
			rawConfiguration, _ = json.Marshal(configuration)
			if _, err := f.admin.Exec(ctx, `UPDATE discovery_settings SET revision=701,configuration=$2 WHERE organization_id=$1`, f.org, rawConfiguration); err != nil {
				t.Fatal(err)
			}
			requireHTTP(t, call("POST", "/v1/discovery/reports", report), 409)
			report["settings_revision"] = policyRevision()
			requireHTTP(t, call("POST", "/v1/discovery/reports", report), 200)
			if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM discovery_entities WHERE organization_id=$1 AND device_id=$2`, f.org, device).Scan(&stored); err != nil || stored != 2 {
				t.Fatal("authorized guest scope was not stored", stored, err)
			}
		})
	}
}
