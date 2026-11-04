package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestDiscoveryDuplicateAcknowledgementEndsTransactionBeforeIO(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	credential := randomToken()
	var device string
	if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,kind,capabilities) VALUES($1,$2,'Synthetic replay fixture','test','0.7.0','approved','browser','["discovery-v1"]') RETURNING id`, f.org, hash(credential)).Scan(&device); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_settings(organization_id,revision,configuration) VALUES($1,700,'{"host":true,"interval_seconds":300}')`, f.org); err != nil {
		t.Fatal(err)
	}
	policyRequest := httptest.NewRequest("GET", "/v1/discovery/policy", nil)
	policyRequest.Header.Set("Authorization", "Bearer "+credential)
	policyResponse := httptest.NewRecorder()
	f.a.Handler().ServeHTTP(policyResponse, policyRequest)
	requireHTTP(t, policyResponse, 200)
	var envelope map[string]string
	if err := json.Unmarshal(policyResponse.Body.Bytes(), &envelope); err != nil {
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
	now := time.Now().Unix()
	report := map[string]any{
		"version": 1, "catalog_revision": discoveryFixtureCatalogRevision, "settings_revision": authorization.Revision,
		"run_id": nil, "scope": "endpoint", "sequence": 100, "page": 0, "pages": 1, "observed_at": now, "complete": false,
		"entities": []any{map[string]string{"id": "process/1/start-1", "kind": "process"}}, "relations": []any{}, "coverage": []any{},
		"result": map[string]any{"identifications": []any{map[string]any{
			"application_id": "openclaw", "signature_id": "openclaw.process", "signature_revision": 1, "entity_id": "process/1/start-1", "state": "executed",
			"evidence": []any{map[string]any{"fact_id": "fact/1", "source": "host_process", "observed_at": now, "fields": []string{"executable"}}},
		}}, "communications": []any{}, "evaluated_facts": 0, "unknown_conditions": 0},
	}
	// Marshal once: both authenticated HTTP requests carry the exact same bytes.
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	request := func() *http.Request {
		r := httptest.NewRequest("POST", "/v1/discovery/reports", bytes.NewReader(raw))
		r.Header.Set("Authorization", "Bearer "+credential)
		r.Header.Set("Content-Type", "application/json")
		return r
	}
	first := httptest.NewRecorder()
	f.a.Handler().ServeHTTP(first, request())
	requireHTTP(t, first, 200)
	snapshot := func() map[string]string {
		out := map[string]string{}
		for _, table := range []string{"discovery_scans", "discovery_entities", "discovery_identifications", "discovery_events", "discovery_relations", "discovery_coverage", "discovery_communications"} {
			var stored string
			if err := f.admin.QueryRow(ctx, "SELECT coalesce(jsonb_agg(to_jsonb(stored) ORDER BY to_jsonb(stored)::text),'[]'::jsonb)::text FROM "+table+" stored WHERE organization_id=$1 AND device_id=$2", f.org, device).Scan(&stored); err != nil {
				t.Fatal(err)
			}
			out[table] = stored
		}
		return out
	}
	before := snapshot()
	for _, table := range []string{"discovery_scans", "discovery_entities", "discovery_identifications", "discovery_events"} {
		var rows []json.RawMessage
		if err := json.Unmarshal([]byte(before[table]), &rows); err != nil || len(rows) != 1 {
			t.Fatal("initial acknowledgement did not persist its report", table, err)
		}
	}
	var finalized bool
	if err := f.admin.QueryRow(ctx, `SELECT finalized AND sequence=100 AND page_hashes ? '0' FROM discovery_scans WHERE organization_id=$1 AND device_id=$2 AND scope='endpoint'`, f.org, device).Scan(&finalized); err != nil || !finalized {
		t.Fatal("initial page acknowledgement was not durable", finalized, err)
	}
	writer := &discoveryDeniedBlockingWriter{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), proceed: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(writer.proceed) }) }
	requestContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	done := make(chan struct{})
	t.Cleanup(func() {
		release()
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("duplicate request worker did not stop")
		}
	})
	go func() {
		defer close(done)
		f.a.Handler().ServeHTTP(writer, request().WithContext(requestContext))
	}()
	select {
	case <-writer.entered:
	case <-done:
		t.Fatal("duplicate request ended before response I/O")
	case <-time.After(5 * time.Second):
		t.Fatal("duplicate acknowledgement did not reach response I/O")
	}
	if f.a.db.Stat().AcquiredConns() != 0 || len(f.a.eventSlots) != 0 {
		t.Fatal("duplicate acknowledgement retained a transaction or event slot during client I/O", f.a.db.Stat().AcquiredConns(), len(f.a.eventSlots))
	}
	probe, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Rollback(ctx)
	if _, err = probe.Exec(ctx, `SET LOCAL lock_timeout='500ms'`); err != nil {
		t.Fatal(err)
	}
	if _, err = probe.Exec(ctx, `SELECT pg_advisory_xact_lock(`+barrierKeySQL+`)`, f.org); err != nil {
		t.Fatal("duplicate acknowledgement retained the privacy barrier", err)
	}
	if err = probe.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("duplicate response did not finish after releasing the client")
	}
	requireHTTP(t, writer.ResponseRecorder, 200)
	var acknowledgement struct {
		OK        bool `json:"ok"`
		Duplicate bool `json:"duplicate"`
	}
	if err = json.Unmarshal(writer.Body.Bytes(), &acknowledgement); err != nil || !acknowledgement.OK || !acknowledgement.Duplicate {
		t.Fatal("exact replay did not return the duplicate acknowledgement", err)
	}
	for table, after := range snapshot() {
		if after != before[table] {
			t.Fatal("exact replay changed persisted report data", table)
		}
	}
	var charged int
	if err = f.admin.QueryRow(ctx, `SELECT coalesce(sum(hits),0)::integer FROM rate_counters WHERE family=1 AND key_hash=$1`, hash(device+" /v1/discovery/reports")).Scan(&charged); err != nil || charged != 2 {
		t.Fatal("replay changed independently committed admission charges", charged, err)
	}
}
