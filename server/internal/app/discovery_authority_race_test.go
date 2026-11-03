package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// This test is intentionally non-parallel: the real runtime factory is wrapped
// for this test alone, without replacing its compiled module or capacity limit.
func TestDiscoveryReportRechecksAuthorityAfterUnlockedValidation(t *testing.T) {
	for _, mutation := range []string{"unrelated_device_metadata", "revoked_device", "collection_withdrawal", "catalog_same_revision"} {
		t.Run(mutation, func(t *testing.T) {
			gate := installDiscoveryAuthorityGate(t)
			f := newObservabilityFixture(t)
			ctx := context.Background()
			credential := randomToken()
			var device string
			if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,kind,capabilities) VALUES($1,$2,'Synthetic authority fixture','test','0.7.0','approved','browser','["discovery-v1"]') RETURNING id`, f.org, hash(credential)).Scan(&device); err != nil {
				t.Fatal(err)
			}
			configuration := DiscoverySettings{Host: true, IntervalSeconds: 300}
			encodedConfiguration, err := json.Marshal(configuration)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.admin.Exec(ctx, `INSERT INTO discovery_settings(organization_id,revision,configuration) VALUES($1,700,$2)`, f.org, encodedConfiguration); err != nil {
				t.Fatal(err)
			}
			if _, err = f.admin.Exec(ctx, `INSERT INTO discovery_catalogs(organization_id,revision,content) VALUES($1,700,$2)`, f.org, discoveryFactory); err != nil {
				t.Fatal(err)
			}
			if _, err = f.admin.Exec(ctx, `INSERT INTO shadow_settings(organization_id,configuration) VALUES($1,'{"collection":{"enabled":true}}') ON CONFLICT(organization_id) DO UPDATE SET configuration=shadow_settings.configuration||'{"collection":{"enabled":true}}'::jsonb`, f.org); err != nil {
				t.Fatal(err)
			}
			policyRequest := httptest.NewRequest("GET", "/v1/discovery/policy", nil)
			policyRequest.Header.Set("Authorization", "Bearer "+credential)
			policyResponse := httptest.NewRecorder()
			f.a.Handler().ServeHTTP(policyResponse, policyRequest)
			requireHTTP(t, policyResponse, 200)
			var envelope map[string]string
			if err = json.Unmarshal(policyResponse.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			payload, err := base64.StdEncoding.DecodeString(envelope["payload"])
			if err != nil {
				t.Fatal(err)
			}
			var authorization struct {
				Revision int64 `json:"revision"`
			}
			if err = json.Unmarshal(payload, &authorization); err != nil || authorization.Revision <= 0 {
				t.Fatal("missing delivered discovery authorization", err)
			}
			// This race concerns authority changes, independently of the one-time
			// runtime compilation cost that precedes the bounded report check.
			if err = discoveryEngine(ctx, map[string]any{"op": "compile", "catalog": json.RawMessage(discoveryFactory)}, nil); err != nil {
				t.Fatal(err)
			}
			now := time.Now().Unix()
			report := map[string]any{
				"version": 1, "catalog_revision": discoveryFixtureCatalogRevision, "settings_revision": authorization.Revision,
				"run_id": nil, "scope": "endpoint", "sequence": 100, "page": 0, "pages": 1, "observed_at": now, "complete": false,
				"entities": []any{map[string]string{"id": "process/authority", "kind": "process"}}, "relations": []any{}, "coverage": []any{},
				"result": map[string]any{"identifications": []any{map[string]any{
					"application_id": "openclaw", "signature_id": "openclaw.process", "signature_revision": 1, "entity_id": "process/authority", "state": "executed",
					"evidence": []any{map[string]any{"fact_id": "fact/authority", "source": "host_process", "observed_at": now, "fields": []string{"executable"}}},
				}}, "communications": []any{}, "evaluated_facts": 1, "unknown_conditions": 0},
			}
			raw, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			requestContext, cancelRequest := context.WithTimeout(ctx, 10*time.Second)
			request := httptest.NewRequest("POST", "/v1/discovery/reports", bytes.NewReader(raw)).WithContext(requestContext)
			request.Header.Set("Authorization", "Bearer "+credential)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			done := make(chan struct{})
			t.Cleanup(func() {
				gate.release()
				cancelRequest()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					t.Error("discovery report worker did not stop")
				}
			})
			go func() {
				defer close(done)
				f.a.Handler().ServeHTTP(response, request)
			}()
			select {
			case <-gate.entered:
			case <-done:
				t.Fatalf("report ended before real prevalidated WASM call: %d", response.Code)
			case <-time.After(5 * time.Second):
				t.Fatal("real prevalidated WASM call was not reached")
			}
			if len(f.a.eventSlots) != 0 {
				t.Error("CPU validation retained an event transaction slot")
			}
			// A committed writer, rather than a launched goroutine, proves the
			// original authority locks were released before CPU validation.
			writerContext, cancelWriter := context.WithTimeout(ctx, time.Second)
			err = mutateDiscoveryAuthority(writerContext, f, device, mutation)
			cancelWriter()
			if err != nil {
				t.Fatalf("authority writer did not commit while validation was blocked: %v", err)
			}
			select {
			case <-done:
				t.Fatal("report ended while its real WASM call was still gated")
			default:
			}
			var committed bool
			switch mutation {
			case "unrelated_device_metadata":
				err = f.admin.QueryRow(ctx, `SELECT hostname='Synthetic updated fixture' FROM devices WHERE organization_id=$1 AND id=$2`, f.org, device).Scan(&committed)
			case "revoked_device":
				err = f.admin.QueryRow(ctx, `SELECT status='revoked' FROM devices WHERE organization_id=$1 AND id=$2`, f.org, device).Scan(&committed)
			case "collection_withdrawal":
				err = f.admin.QueryRow(ctx, `SELECT configuration->'collection'->>'enabled'='false' FROM shadow_settings WHERE organization_id=$1`, f.org).Scan(&committed)
			case "catalog_same_revision":
				err = f.admin.QueryRow(ctx, `SELECT revision=700 AND (content->>'revision')::bigint=$2 AND content->'signatures'->0->>'name'='Synthetic changed catalog' FROM discovery_catalogs WHERE organization_id=$1`, f.org, discoveryFixtureCatalogRevision).Scan(&committed)
			}
			if err != nil || !committed {
				t.Fatal("authority mutation was not visible before gate release", err)
			}
			gate.release()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("report did not finish after gate release")
			}
			wantStatus, wantRows := 409, 0
			if mutation == "revoked_device" {
				wantStatus = 401
			} else if mutation == "unrelated_device_metadata" {
				wantStatus, wantRows = 200, 1
			}
			requireHTTP(t, response, wantStatus)
			for _, table := range []string{"discovery_scans", "discovery_entities", "discovery_identifications", "discovery_events"} {
				var rows int
				if err = f.admin.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE organization_id=$1 AND device_id=$2", f.org, device).Scan(&rows); err != nil || rows != wantRows {
					t.Fatalf("%s retained %d rows, expected %d: %v", table, rows, wantRows, err)
				}
			}
			for _, table := range []string{"discovery_relations", "discovery_coverage", "discovery_communications"} {
				var rows int
				if err = f.admin.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE organization_id=$1 AND device_id=$2", f.org, device).Scan(&rows); err != nil || rows != 0 {
					t.Fatalf("%s unexpectedly retained %d rows: %v", table, rows, err)
				}
			}
			var charged int
			if err = f.admin.QueryRow(ctx, `SELECT coalesce(sum(hits),0)::integer FROM rate_counters WHERE family=1 AND key_hash=$1`, hash(device+" /v1/discovery/reports")).Scan(&charged); err != nil || charged != 1 {
				t.Fatal("one report did not charge exactly one route budget", charged, err)
			}
			if len(f.a.eventSlots) != 0 {
				t.Fatal("completed or refused report retained an event slot")
			}
		})
	}
}

func mutateDiscoveryAuthority(ctx context.Context, f *observabilityFixture, device, mutation string) error {
	tx, err := tenantTx(ctx, f.admin, f.org)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Match real administrative writers' privacy-before-policy lock order.
	if err = sharedBarrier(ctx, tx, f.org, false); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(`+barrierKeySQL+`)`, f.org); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7069202)`); err != nil {
		return err
	}
	switch mutation {
	case "unrelated_device_metadata":
		_, err = tx.Exec(ctx, `UPDATE devices SET hostname='Synthetic updated fixture' WHERE organization_id=$1 AND id=$2`, f.org, device)
	case "revoked_device":
		_, err = tx.Exec(ctx, `UPDATE devices SET status='revoked' WHERE organization_id=$1 AND id=$2`, f.org, device)
	case "collection_withdrawal":
		_, err = tx.Exec(ctx, `UPDATE shadow_settings SET configuration=configuration||'{"collection":{"enabled":false}}'::jsonb WHERE organization_id=$1`, f.org)
	case "catalog_same_revision":
		_, err = tx.Exec(ctx, `UPDATE discovery_catalogs SET content=jsonb_set(content,'{signatures,0,name}','"Synthetic changed catalog"'::jsonb) WHERE organization_id=$1`, f.org)
	default:
		return errors.New("unknown synthetic authority mutation")
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type discoveryAuthorityGate struct {
	entered     chan struct{}
	proceed     chan struct{}
	enteredOnce sync.Once
	releaseOnce sync.Once
}

func (gate *discoveryAuthorityGate) release() { gate.releaseOnce.Do(func() { close(gate.proceed) }) }
func (gate *discoveryAuthorityGate) wait(ctx context.Context) error {
	gate.enteredOnce.Do(func() { close(gate.entered) })
	select {
	case <-gate.proceed:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func installDiscoveryAuthorityGate(t *testing.T) *discoveryAuthorityGate {
	t.Helper()
	gate := &discoveryAuthorityGate{entered: make(chan struct{}), proceed: make(chan struct{})}
	original := sharedDiscoveryRuntime
	sharedDiscoveryRuntime = func() (*dlpRuntime, error) {
		base, err := original()
		if err != nil {
			return base, err
		}
		copy := *base
		copy.runtime = &discoveryAuthorityRuntime{Runtime: base.runtime, gate: gate}
		return &copy, nil
	}
	// Registered before the fixture and its worker cleanup, restored after them.
	t.Cleanup(func() { sharedDiscoveryRuntime = original })
	return gate
}

type discoveryAuthorityRuntime struct {
	wazero.Runtime
	gate *discoveryAuthorityGate
}

func (runtime *discoveryAuthorityRuntime) InstantiateModule(ctx context.Context, compiled wazero.CompiledModule, config wazero.ModuleConfig) (api.Module, error) {
	module, err := runtime.Runtime.InstantiateModule(ctx, compiled, config)
	if module == nil {
		return module, err
	}
	return &discoveryAuthorityModule{Module: module, gate: runtime.gate}, err
}

type discoveryAuthorityModule struct {
	api.Module
	gate *discoveryAuthorityGate
}

func (module *discoveryAuthorityModule) ExportedFunction(name string) api.Function {
	function := module.Module.ExportedFunction(name)
	if function == nil || name != "discovery_call_prevalidated_report" {
		return function
	}
	return &discoveryAuthorityFunction{Function: function, gate: module.gate}
}

type discoveryAuthorityFunction struct {
	api.Function
	gate *discoveryAuthorityGate
}

func (function *discoveryAuthorityFunction) Call(ctx context.Context, args ...uint64) ([]uint64, error) {
	if err := function.gate.wait(ctx); err != nil {
		return nil, err
	}
	return function.Function.Call(ctx, args...)
}

func (function *discoveryAuthorityFunction) CallWithStack(ctx context.Context, stack []uint64) error {
	if err := function.gate.wait(ctx); err != nil {
		return err
	}
	return function.Function.CallWithStack(ctx, stack)
}

var _ wazero.Runtime = (*discoveryAuthorityRuntime)(nil)
var _ api.Module = (*discoveryAuthorityModule)(nil)
var _ api.Function = (*discoveryAuthorityFunction)(nil)
