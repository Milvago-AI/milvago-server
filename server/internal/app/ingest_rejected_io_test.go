package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"
)

// This blocks the handler's ResponseWriter directly. It establishes resource
// lifetime independently of transport buffering; it is not a network DoS test.
func TestRejectedIngestEndsTransactionBeforePermanentRejectIO(t *testing.T) {
	x := newIngestBatchFixture(t)
	events := append([]V2Event(nil), x.events...)
	expected := make([]string, len(events))
	for index := range events {
		events[index].Kind = "invalid-synthetic-kind"
		expected[index] = events[index].ID
	}
	raw, err := json.Marshal(map[string]any{"events": events})
	if err != nil || len(raw) > 128<<10 {
		t.Fatal("fixture must enter per-event validation within the real body limit", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	request := httptest.NewRequest("POST", "/v2/events", bytes.NewReader(raw)).WithContext(ctx)
	request.Header.Set("Authorization", "Bearer "+x.credential)
	request.Header.Set("Content-Type", "application/json")
	writer := &discoveryDeniedBlockingWriter{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), proceed: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(writer.proceed) }) }
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		release()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("rejected-ingest worker did not stop")
		}
	})
	go func() {
		defer close(done)
		x.f.a.Handler().ServeHTTP(writer, request)
	}()
	select {
	case <-writer.entered:
	case <-done:
		t.Fatal("request ended before its rejection response")
	case <-time.After(5 * time.Second):
		t.Fatal("permanent rejection did not reach client I/O")
	}
	if acquired := x.f.a.db.Stat().AcquiredConns(); acquired != 0 {
		t.Fatal("rejected ingest retained a pool connection during client I/O", acquired)
	}
	if slots := len(x.f.a.eventSlots); slots != 0 {
		t.Fatal("rejected ingest retained an event slot during client I/O", slots)
	}
	probeCtx, stopProbe := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopProbe()
	probe, err := x.f.admin.Begin(probeCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Rollback(probeCtx)
	if _, err = probe.Exec(probeCtx, `SET LOCAL lock_timeout='500ms'`); err != nil {
		t.Fatal(err)
	}
	if _, err = probe.Exec(probeCtx, `SELECT pg_advisory_xact_lock(`+barrierKeySQL+`)`, x.f.org); err != nil {
		t.Fatal("slow rejection response blocked the exclusive privacy barrier", err)
	}
	if _, err = probe.Exec(probeCtx, `SELECT pg_advisory_xact_lock(7069202)`); err != nil {
		t.Fatal("slow rejection response retained the policy barrier", err)
	}
	var device string
	if err = probe.QueryRow(probeCtx, `SELECT id::text FROM devices WHERE organization_id=$1 AND id=$2 FOR UPDATE`, x.f.org, x.device).Scan(&device); err != nil || device != x.device {
		t.Fatal("slow rejection response retained the device row", err)
	}
	if err = probe.Commit(probeCtx); err != nil {
		t.Fatal("an exclusive privacy/policy update could not complete while response I/O was blocked", err)
	}
	select {
	case <-done:
		t.Fatal("the writer was not still blocked during the independent transaction")
	default:
	}
	release()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("rejection did not finish after client I/O resumed")
	}
	requireHTTP(t, writer.ResponseRecorder, http.StatusBadRequest)
	var reply struct {
		Error string   `json:"error"`
		IDs   []string `json:"rejected_ids"`
	}
	if err = json.Unmarshal(writer.Body.Bytes(), &reply); err != nil || reply.Error != "invalid_event" || !slices.Equal(reply.IDs, expected) {
		t.Fatal("permanent reject must retain its exact validated event identities", err)
	}
	var retained int
	if err = x.f.admin.QueryRow(ctx, `SELECT count(*) FROM shadow_events WHERE organization_id=$1 AND device_id=$2`, x.f.org, x.device).Scan(&retained); err != nil || retained != 0 {
		t.Fatal("permanently rejected batch wrote event state", err, retained)
	}
}
