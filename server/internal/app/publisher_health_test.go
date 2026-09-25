package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPublisherHealthObservationWindowsAndRevisions(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	setTenant(t, f.admin, f.org)
	dayEnd := time.Now().UTC().Truncate(24 * time.Hour)
	since := dayEnd.Add(-3 * 24 * time.Hour)
	cfg := defaultPrivacy()
	cfg.ShareHealth = true
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tag, err := f.admin.Exec(ctx, "INSERT INTO privacy_settings(organization_id,configuration,updated_at) VALUES($1,$2,$3) ON CONFLICT(organization_id) DO UPDATE SET configuration=excluded.configuration,updated_at=excluded.updated_at", f.org, raw, since); err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("consent not installed: %v", err)
	}

	seedPublisherHealthObservations(t, f, ctx, dayEnd, since)
	tx, err := f.a.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	batch, consents, _, _, err := f.a.publisherSnapshot(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	if len(consents) != 1 || !consents[0].Health {
		t.Fatalf("wrong effective consent: %+v", consents)
	}
	if len(batch.ProviderHealth) != 3 {
		t.Fatalf("expected exactly three permitted revision rows: %+v", batch.ProviderHealth)
	}
	for i, want := range []struct {
		revision uint64
		state    string
		ratio    float64
	}{{7, "degraded_dom", .1}, {8, "ok", .9}, {10, "dom_only", -1}} {
		got := batch.ProviderHealth[i]
		if got.Provider != "claude" || got.CatalogRevision != want.revision || got.State != want.state {
			t.Fatalf("wrong revision verdict: %+v", got)
		}
		if want.ratio < 0 {
			if got.DOMCoverageRatio != nil {
				t.Fatal("DOM-only ratio must be absent")
			}
		} else if got.DOMCoverageRatio == nil || *got.DOMCoverageRatio != want.ratio {
			t.Fatalf("observation ratio contaminated: %+v", got)
		}
	}
}

func insertPublisherHealth(t *testing.T, f *observabilityFixture, ctx context.Context, device string, revision int, start, end, received time.Time, network, dom int) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"window_start": start, "window_end": end, "catalog_revision": revision, "providers": []map[string]any{{"provider": "claude", "navigations": 5, "prompts_network": network, "prompts_dom": dom}}})
	if err != nil {
		t.Fatal(err)
	}
	if tag, err := f.admin.Exec(ctx, "INSERT INTO detector_health(organization_id,device_id,id,payload,received_at) VALUES($1,$2,gen_random_uuid(),$3,$4)", f.org, device, payload, received); err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("health fixture not inserted: %v", err)
	}
}

func seedPublisherHealthObservations(t *testing.T, f *observabilityFixture, ctx context.Context, dayEnd, since time.Time) {
	for i := 0; i < 3; i++ {
		var device string
		if err := f.admin.QueryRow(ctx, "INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status) VALUES($1,$2,'synthetic-device','windows','0.5.0','approved') RETURNING id", f.org, hash(randomToken())).Scan(&device); err != nil {
			t.Fatal(err)
		}
		// Yesterday's observations arrived today: they still belong to yesterday.
		end := dayEnd.Add(-12 * time.Hour)
		insertPublisherHealth(t, f, ctx, device, 7, end.Add(-time.Hour), end, time.Now().UTC(), 10, 1)
		insertPublisherHealth(t, f, ctx, device, 8, end.Add(-time.Hour), end, time.Now().UTC(), 10, 9)
		insertPublisherHealth(t, f, ctx, device, 10, end.Add(-time.Hour), end, time.Now().UTC(), 0, 6)
		// Earlier observation must not inflate yesterday's ratio despite late receipt.
		previous := dayEnd.Add(-2 * 24 * time.Hour)
		insertPublisherHealth(t, f, ctx, device, 7, previous.Add(-time.Hour), previous, end, 1000, 1000)
		// Neither pre-consent nor consent-crossing windows may be shared.
		before := since.Add(-time.Hour)
		insertPublisherHealth(t, f, ctx, device, 9, before.Add(-time.Hour), before, end, 10, 10)
		insertPublisherHealth(t, f, ctx, device, 11, since.Add(-time.Minute), since.Add(time.Minute), end, 10, 10)
		// The unfinished current day is not part of the previous complete day.
		insertPublisherHealth(t, f, ctx, device, 12, dayEnd, dayEnd.Add(time.Minute), time.Now().UTC(), 10, 10)
	}
}

func TestPublisherQueueStatesAndCountedDiscards(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	setTenant(t, f.admin, f.org)
	var requests atomic.Int32
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(503) }))
	defer remote.Close()
	f.a.config.PublisherURL = remote.URL

	assertPublisherQueueState(t, f, "empty")
	for _, reason := range []string{"configuration_changed", "consent_changed", "expired"} {
		t.Run(reason, func(t *testing.T) {
			before := preparePublisherQueueDiscard(t, f, ctx, &requests)
			holdPublisherQueueDiscard(t, f, ctx, reason)
			assertPublisherQueueDiscard(t, f, ctx, &requests, before, reason)
		})
	}
}

func assertPublisherQueueState(t *testing.T, f *observabilityFixture, state string) {
	t.Helper()
	w := f.call("GET", "/api/publisher/preview", nil, "")
	requireHTTP(t, w, 200)
	var out struct {
		Queue struct {
			State    string `json:"state"`
			Attempts int    `json:"attempts"`
		} `json:"queue"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Queue.State != state {
		t.Fatalf("queue state = %s, want %s", out.Queue.State, state)
	}
}

func preparePublisherQueueDiscard(t *testing.T, f *observabilityFixture, ctx context.Context, requests *atomic.Int32) int32 {
	f.a.config.PublisherCredential = strings.Repeat("fixture", 6)
	cfg := defaultPrivacy()
	cfg.ShareFleet = true
	raw, _ := json.Marshal(cfg)
	if tag, err := f.admin.Exec(ctx, "INSERT INTO privacy_settings(organization_id,configuration) VALUES($1,$2) ON CONFLICT(organization_id) DO UPDATE SET configuration=excluded.configuration,revision=privacy_settings.revision+1", f.org, raw); err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("consent fixture: %v", err)
	}
	if _, err := f.admin.Exec(ctx, "UPDATE publisher_client_state SET last_telemetry_day=NULL"); err != nil {
		t.Fatal(err)
	}
	before := requests.Load()
	if err := f.a.publisherPass(ctx); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != before+1 {
		t.Fatal("failed send not exercised")
	}
	assertPublisherQueueState(t, f, "retrying")
	if tag, err := f.admin.Exec(ctx, "UPDATE publisher_client_outbox SET attempts=0,next_attempt=clock_timestamp()-interval '1 second'"); err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("queue fixture missing: %v", err)
	}
	assertPublisherQueueState(t, f, "pending")
	// Suppress a new daily batch; this pass should only dispose of the held one.
	if _, err := f.admin.Exec(ctx, "UPDATE publisher_client_state SET last_telemetry_day=$1", time.Now().UTC().Truncate(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	return before
}

func holdPublisherQueueDiscard(t *testing.T, f *observabilityFixture, ctx context.Context, reason string) {
	switch reason {
	case "configuration_changed":
		f.a.config.PublisherCredential = strings.Repeat("replacement", 4)
		assertPublisherQueueState(t, f, "held")
	case "consent_changed":
		raw, _ := json.Marshal(defaultPrivacy())
		if tag, err := f.admin.Exec(ctx, "UPDATE privacy_settings SET configuration=$1,revision=revision+1 WHERE organization_id=$2", raw, f.org); err != nil || tag.RowsAffected() != 1 {
			t.Fatalf("optout fixture: %v", err)
		}
		assertPublisherQueueState(t, f, "held")
	case "expired":
		var payload []byte
		if err := f.admin.QueryRow(ctx, "SELECT payload FROM publisher_client_outbox").Scan(&payload); err != nil {
			t.Fatal(err)
		}
		var batch publisherBatch
		if err := json.Unmarshal(payload, &batch); err != nil {
			t.Fatal(err)
		}
		batch.SentAt = time.Now().Add(-49 * time.Hour)
		payload, _ = json.Marshal(batch)
		if tag, err := f.admin.Exec(ctx, "UPDATE publisher_client_outbox SET payload=$1", payload); err != nil || tag.RowsAffected() != 1 {
			t.Fatalf("expiry fixture: %v", err)
		}
	}
}

func assertPublisherQueueDiscard(t *testing.T, f *observabilityFixture, ctx context.Context, requests *atomic.Int32, before int32, reason string) {
	if err := f.a.publisherPass(ctx); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != before+1 {
		t.Fatal("discarded batch was sent")
	}
	assertPublisherQueueState(t, f, "empty")
	var count, rows int
	if err := f.admin.QueryRow(ctx, "SELECT count(*),coalesce(sum((details->>'rows')::int),0) FROM audit WHERE action='publisher.outbox.discarded' AND details->>'reason'=$1", reason).Scan(&count, &rows); err != nil || count != 1 || rows != 1 {
		t.Fatalf("discard not counted: %d/%d %v", count, rows, err)
	}
	var status string
	if err := f.admin.QueryRow(ctx, "SELECT last_error FROM publisher_client_state").Scan(&status); err != nil || status != "outbox_discarded_"+reason {
		t.Fatalf("discard status hidden: %s %v", status, err)
	}
}

func TestPublisherDeleteRouteIsUnavailable(t *testing.T) {
	f := newObservabilityFixture(t)
	var requests atomic.Int32
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer remote.Close()
	f.a.config.PublisherURL = remote.URL
	f.a.config.PublisherCredential = strings.Repeat("fixture", 6)
	w := f.call("DELETE", "/api/publisher/telemetry", nil, f.csrf)
	if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("client DELETE was accepted: %d", w.Code)
	}
	if requests.Load() != 0 {
		t.Fatal("client DELETE reached the publisher")
	}
}
