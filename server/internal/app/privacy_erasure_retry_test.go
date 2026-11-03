package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestSubjectErasureTerminallyAcknowledgesExactRetry(t *testing.T) {
	x := newIngestBatchFixture(t)
	ctx := context.Background()
	event := x.events[50]
	event.Prompt = &x.prompt
	x.call(t, []V2Event{event}, 200)
	var subject string
	if err := x.f.admin.QueryRow(ctx, "SELECT collaborator_id FROM shadow_events WHERE organization_id=$1 AND device_id=$2 AND id=$3", x.f.org, x.device, event.ID).Scan(&subject); err != nil {
		t.Fatal("accepted dummy event must have subject attribution", err)
	}
	var contents int
	if err := x.f.admin.QueryRow(ctx, "SELECT count(*) FROM shadow_content WHERE organization_id=$1 AND device_id=$2 AND event_id=$3", x.f.org, x.device, event.ID).Scan(&contents); err != nil || contents != 1 {
		t.Fatal("retained-content control missing", err)
	}
	if tag, err := x.f.admin.Exec(ctx, "UPDATE sessions SET mfa_verified_at=clock_timestamp() WHERE token_hash=$1", hash(x.f.owner.Value)); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("fresh dummy session missing", err)
	}
	erased := x.f.call("DELETE", "/api/subjects/"+subject, nil, x.f.csrf)
	requireHTTP(t, erased, 200)
	var result struct {
		Erased bool  `json:"erased"`
		Events int64 `json:"events"`
	}
	if err := json.Unmarshal(erased.Body.Bytes(), &result); err != nil || !result.Erased || result.Events != 1 {
		t.Fatal("erasure must report actual removed-event count", err)
	}
	w := x.call(t, []V2Event{event}, 200)
	var accepted struct {
		IDs []string `json:"accepted_ids"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &accepted); err != nil || !slices.Equal(accepted.IDs, []string{event.ID}) {
		t.Fatal("exact erased retry must receive terminal acknowledgement", err)
	}
	assertErasedEventAbsent(t, x, event.ID)
	var markers int
	if err := x.f.admin.QueryRow(ctx, "SELECT count(*) FROM shadow_erased_events WHERE organization_id=$1 AND device_id=$2 AND event_id=$3", x.f.org, x.device, event.ID).Scan(&markers); err != nil || markers != 1 {
		t.Fatal("full-key marker missing", err)
	}
	requireHTTP(t, x.f.call("GET", "/api/shadow/events/"+event.ID+"?device_id="+x.device, nil, ""), 404)
	event.ID = "99999999-9999-4999-8999-999999999991"
	x.call(t, []V2Event{event}, 200)
	if err := x.f.admin.QueryRow(ctx, "SELECT count(*) FROM shadow_content WHERE organization_id=$1 AND device_id=$2 AND event_id=$3", x.f.org, x.device, event.ID).Scan(&contents); err != nil || contents != 1 {
		t.Fatal("genuinely new event must remain admissible", err)
	}
}

func TestErasedEventMarkerCleanupWaitsForAdmittedIngest(t *testing.T) {
	x := newIngestBatchFixture(t)
	ctx := context.Background()
	const event = "88888888-8888-4888-8888-888888888881"
	if _, err := x.f.admin.Exec(ctx, `INSERT INTO shadow_erased_events(organization_id,device_id,event_id,expires_at) VALUES($1,$2,$3,now()-interval '1 hour')`, x.f.org, x.device, event); err != nil {
		t.Fatal(err)
	}
	admitted, err := tenantTx(ctx, x.f.a.db, x.f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer admitted.Rollback(ctx)
	if err = sharedBarrier(ctx, admitted, x.f.org, true); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	joined := false
	go func() { finished <- x.f.a.purgeErasedEvents(ctx, x.f.org) }()
	defer func() {
		admitted.Rollback(ctx)
		if !joined {
			select {
			case <-finished:
			case <-time.After(5 * time.Second):
				t.Error("marker cleanup did not finish after admission ended")
			}
		}
	}()
	awaitLockWait(t, x.f, "advisory")
	var count int
	if err = admitted.QueryRow(ctx, "SELECT count(*) FROM shadow_erased_events WHERE device_id=$1 AND event_id=$2", x.device, event).Scan(&count); err != nil || count != 1 {
		t.Fatal("cleanup removed a marker while an earlier admission remained active", err)
	}
	admitted.Rollback(ctx)
	select {
	case err = <-finished:
		joined = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("marker cleanup remained blocked after admission ended")
	}
	if err = x.f.admin.QueryRow(ctx, "SELECT count(*) FROM shadow_erased_events WHERE organization_id=$1 AND device_id=$2 AND event_id=$3", x.f.org, x.device, event).Scan(&count); err != nil || count != 0 {
		t.Fatal("expired marker was not cleaned", err)
	}
}

func TestErasedEventMarkersUseTenantRLSAndMinimalRuntimeGrants(t *testing.T) {
	x := newIngestBatchFixture(t)
	ctx := context.Background()
	const event = "88888888-8888-4888-8888-888888888882"
	if _, err := x.f.admin.Exec(ctx, `INSERT INTO shadow_erased_events(organization_id,device_id,event_id,expires_at) VALUES($1,$2,$3,now()+interval '1 day')`, x.f.org, x.device, event); err != nil {
		t.Fatal(err)
	}
	var other string
	if err := x.f.admin.QueryRow(ctx, "INSERT INTO organizations(name,parent_id) VALUES('Synthetic marker tenant',$1) RETURNING id", x.f.org).Scan(&other); err != nil {
		t.Fatal(err)
	}
	foreign, err := tenantTx(ctx, x.f.a.db, other)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	err = foreign.QueryRow(ctx, "SELECT count(*) FROM shadow_erased_events WHERE event_id=$1", event).Scan(&count)
	foreign.Rollback(ctx)
	if err != nil || count != 0 {
		t.Fatal("marker leaked across tenant context", err)
	}
	if err = x.f.a.db.QueryRow(ctx, "SELECT count(*) FROM shadow_erased_events WHERE event_id=$1", event).Scan(&count); err != nil || count != 0 {
		t.Fatal("marker visible without tenant context", err)
	}
	owner, err := tenantTx(ctx, x.f.a.db, x.f.org)
	if err != nil {
		t.Fatal(err)
	}
	_, err = owner.Exec(ctx, "UPDATE shadow_erased_events SET expires_at=now() WHERE event_id=$1", event)
	owner.Rollback(ctx)
	var denied *pgconn.PgError
	if !errors.As(err, &denied) || denied.Code != "42501" {
		t.Fatal("runtime unexpectedly obtained marker UPDATE authority", err)
	}
	if err = x.f.a.purgeErasedEvents(ctx, x.f.org); err != nil {
		t.Fatal(err)
	}
	if err = x.f.admin.QueryRow(ctx, "SELECT count(*) FROM shadow_erased_events WHERE organization_id=$1 AND device_id=$2 AND event_id=$3", x.f.org, x.device, event).Scan(&count); err != nil || count != 1 {
		t.Fatal("cleanup removed an unexpired marker", err)
	}
}

func assertErasedEventAbsent(t *testing.T, x ingestBatchFixture, id string) {
	t.Helper()
	for _, query := range []string{
		"SELECT count(*) FROM shadow_events WHERE organization_id=$1 AND device_id=$2 AND id=$3",
		"SELECT count(*) FROM shadow_content WHERE organization_id=$1 AND device_id=$2 AND event_id=$3",
		"SELECT count(*) FROM dlp_decisions WHERE organization_id=$1 AND device_id=$2 AND event_id=$3",
	} {
		var count int
		if err := x.f.admin.QueryRow(context.Background(), query, x.f.org, x.device, id).Scan(&count); err != nil || count != 0 {
			t.Fatal("erased exact retry recreated retained data", count, err)
		}
	}
}

func TestSubjectErasureOrdersAgainstConcurrentIngest(t *testing.T) {
	for _, eraseFirst := range []bool{false, true} {
		name := "ingest-before-erase"
		if eraseFirst {
			name = "erase-before-retry"
		}
		t.Run(name, func(t *testing.T) {
			x := newIngestBatchFixture(t)
			ctx := context.Background()
			event := x.events[50]
			event.Prompt = &x.prompt
			var subject string
			if err := x.f.admin.QueryRow(ctx, "SELECT collaborator_id FROM device_collaborators WHERE device_id=$1", x.device).Scan(&subject); err != nil {
				t.Fatal(err)
			}
			if _, err := x.f.admin.Exec(ctx, "UPDATE sessions SET mfa_verified_at=clock_timestamp() WHERE token_hash=$1", hash(x.f.owner.Value)); err != nil {
				t.Fatal(err)
			}
			if eraseFirst {
				x.call(t, []V2Event{event}, 200)
			}
			holder := lockHolder(t)
			defer holder.Exec(ctx, "ROLLBACK")
			blockedTable := "shadow_events"
			if eraseFirst {
				blockedTable = "audit"
			}
			if _, err := holder.Exec(ctx, "LOCK TABLE "+blockedTable+" IN SHARE ROW EXCLUSIVE MODE"); err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(map[string]any{"events": []V2Event{event}})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest("POST", "/v2/events", bytes.NewReader(raw))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer "+x.credential)
			ingested := make(chan *httptest.ResponseRecorder, 1)
			erased := make(chan *httptest.ResponseRecorder, 1)
			startIngest := func() {
				go func() { w := httptest.NewRecorder(); x.f.a.Handler().ServeHTTP(w, request); ingested <- w }()
			}
			startErase := func() { go func() { erased <- x.f.call("DELETE", "/api/subjects/"+subject, nil, x.f.csrf) }() }
			if eraseFirst {
				startErase()
			} else {
				startIngest()
			}
			awaitLockWait(t, x.f, "relation")
			if eraseFirst {
				startIngest()
			} else {
				startErase()
			}
			awaitLockWait(t, x.f, "advisory")
			if _, err := holder.Exec(ctx, "ROLLBACK"); err != nil {
				t.Fatal(err)
			}
			requireHTTP(t, awaitPrivacyRequest(t, ingested), 200)
			requireHTTP(t, awaitPrivacyRequest(t, erased), 200)
			assertErasedEventAbsent(t, x, event.ID)
			var markers int
			if err := x.f.admin.QueryRow(ctx, "SELECT count(*) FROM shadow_erased_events WHERE organization_id=$1 AND device_id=$2 AND event_id=$3", x.f.org, x.device, event.ID).Scan(&markers); err != nil || markers != 1 {
				t.Fatal("ordered erasure must preserve its replay marker", err)
			}
		})
	}
}
