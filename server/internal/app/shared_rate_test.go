package app

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func rateStatus(err error) int {
	if err == nil {
		return 200
	}
	var response apiError
	if errors.As(err, &response) {
		return response.status
	}
	return 0
}

func TestSharedRateAcrossReplicas(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	replicas := make([]*App, 4)
	for i := range replicas {
		poolConfig := f.a.db.Config()
		poolConfig.MaxConns = 10
		pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		replicas[i] = &App{db: pool}
		if err := pool.Ping(ctx); err != nil {
			t.Fatal(err)
		}
	}
	assertSharedIngestQuota(t, ctx, f.admin, replicas)
	assertSharedRollbackQuota(t, ctx, f, replicas)
	assertSharedPeerQuota(t, f.admin, replicas)
	var owner, selectable, writable bool
	if err := f.a.db.QueryRow(ctx, "SELECT pg_has_role(current_user,pg_get_userbyid(relowner),'USAGE'),has_table_privilege(current_user,'rate_counters','SELECT'),has_table_privilege(current_user,'rate_counters','UPDATE') FROM pg_class WHERE oid='rate_counters'::regclass").Scan(&owner, &selectable, &writable); err != nil {
		t.Fatal(err)
	}
	if owner || selectable || writable {
		t.Fatal("runtime role can read or change quota storage")
	}
	var hasPublic bool
	if err := f.admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_proc p,aclexplode(p.proacl) acl WHERE p.oid='consume_rate_budget(smallint,bytea,integer)'::regprocedure AND acl.grantee=0)").Scan(&hasPublic); err != nil || hasPublic {
		t.Fatalf("public quota execution: %v %v", hasPublic, err)
	}
	// Closed database: fail temporarily, never admit using memory alone.
	pool, err := pgxpool.NewWithConfig(ctx, f.a.db.Config())
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	if got := rateStatus((&App{db: pool}).checkIngestRate(ctx, "new-key", 100)); got != 503 {
		t.Fatalf("outage admitted or revoked a caller: %d", got)
	}
}

func assertSharedIngestQuota(t *testing.T, ctx context.Context, admin *pgxpool.Pool, replicas []*App) {
	t.Helper()
	for attempt := range 3 {
		window := currentRateWindow(t, admin)
		key := fmt.Sprintf("shared-device-%d /v2/events", attempt)
		var wg sync.WaitGroup
		results := make(chan error, 100)
		for i := range 100 {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				results <- replicas[i%4].checkIngestRate(ctx, key, 50)
			}(i)
		}
		wg.Wait()
		close(results)
		accepted, limited := 0, 0
		for err := range results {
			switch rateStatus(err) {
			case 200:
				accepted++
			case 429:
				limited++
			default:
				t.Fatalf("unexpected quota outcome: %v", err)
			}
		}
		got := rateStatus((&App{db: replicas[0].db}).checkIngestRate(ctx, key, 50))
		if !currentRateWindow(t, admin).Equal(window) {
			continue
		}
		if accepted != 50 || limited != 50 {
			t.Fatalf("four replicas accepted=%d limited=%d; want 50 each", accepted, limited)
		}
		if got != 429 {
			t.Fatalf("new process bypassed spent quota: %d", got)
		}
		return
	}
	t.Fatal("ingest quota could not finish within one database minute")
}

func assertSharedRollbackQuota(t *testing.T, ctx context.Context, f *observabilityFixture, replicas []*App) {
	t.Helper()
	for attempt := range 3 {
		window := currentRateWindow(t, f.admin)
		key := fmt.Sprintf("rollback-key-%d", attempt)
		// Business rollback does not refund separately committed admission.
		tx, err := tenantTx(ctx, f.a.db, f.org)
		if err != nil {
			t.Fatal(err)
		}
		if err := (&App{db: replicas[0].db}).checkIngestRate(ctx, key, 1); err != nil {
			t.Fatal(err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		got := rateStatus((&App{db: replicas[1].db}).checkIngestRate(ctx, key, 1))
		if !currentRateWindow(t, f.admin).Equal(window) {
			continue
		}
		if got != 429 {
			t.Fatalf("rollback refunded quota: %d", got)
		}
		return
	}
	t.Fatal("rollback quota could not finish within one database minute")
}

func assertSharedPeerQuota(t *testing.T, admin *pgxpool.Pool, replicas []*App) {
	t.Helper()
	for attempt := range 3 {
		window := currentRateWindow(t, admin)
		operation := fmt.Sprintf("test-login-%d", attempt)
		var statuses [4]int
		// Forwarded addresses are not identities, and a new process cannot evade the peer budget.
		for i := range statuses {
			request := httptest.NewRequest("GET", "http://localhost/auth/login", nil)
			request.RemoteAddr = "192.0.2.1:1000"
			request.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", i+1))
			statuses[i] = rateStatus(replicas[i].checkPublicRequest(request, operation, 3, 30))
		}
		if !currentRateWindow(t, admin).Equal(window) {
			continue
		}
		for i, got := range statuses {
			want := 200
			if i == 3 {
				want = 429
			}
			if got != want {
				t.Fatalf("peer admission %d: %d want %d", i, got, want)
			}
		}
		return
	}
	t.Fatal("peer quota could not finish within one database minute")
}

func currentRateWindow(t *testing.T, pool *pgxpool.Pool) time.Time {
	t.Helper()
	var window time.Time
	if err := pool.QueryRow(context.Background(), "SELECT date_trunc('minute',clock_timestamp())").Scan(&window); err != nil {
		t.Fatal(err)
	}
	return window
}

func TestSharedRateBoundedStorageAndPurge(t *testing.T) {
	f := newObservabilityFixture(t)
	window := checkFullRateWindow(t, f)
	checkRatePurge(t, f, window)
}

func checkFullRateWindow(t *testing.T, f *observabilityFixture) time.Time {
	t.Helper()
	ctx := context.Background()
	for range 3 {
		window := currentRateWindow(t, f.admin)
		seedFullRateWindow(t, f.admin, window)
		if !currentRateWindow(t, f.admin).Equal(window) {
			continue
		}
		// A full family admits a new key without adding a counter, while an existing
		// key still spends its remaining budget.
		newKeyErr := f.a.sharedRate(ctx, 1, "one-more-key", 2)
		existingKeyErr := f.a.sharedRate(ctx, 1, "capacity-1", 2)
		existingKeyStatus := rateStatus(f.a.sharedRate(ctx, 1, "capacity-1", 2))
		if !currentRateWindow(t, f.admin).Equal(window) {
			continue
		}
		assertFullRateWindow(t, f.admin, window, newKeyErr, existingKeyErr, existingKeyStatus)
		return window
	}
	t.Fatal("full-window checks could not finish within one database minute")
	return time.Time{}
}

func seedFullRateWindow(t *testing.T, admin *pgxpool.Pool, window time.Time) {
	t.Helper()
	ctx := context.Background()
	// A retry starts from a fresh family window after the database minute changes.
	if _, err := admin.Exec(ctx, "DELETE FROM rate_windows WHERE family=1 AND window_start=$1", window); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "INSERT INTO rate_windows(family,window_start,keys) VALUES(1,$1,16384)", window); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "INSERT INTO rate_counters(family,window_start,key_hash,hits) SELECT 1,$1,sha256(convert_to('capacity-'||i,'UTF8')),1 FROM generate_series(1,16384)i", window); err != nil {
		t.Fatal(err)
	}
}

func assertFullRateWindow(t *testing.T, admin *pgxpool.Pool, window time.Time, newKeyErr, existingKeyErr error, existingKeyStatus int) {
	t.Helper()
	if newKeyErr != nil {
		t.Fatalf("a full window refused a new key: %v", newKeyErr)
	}
	var keys, rows int
	if err := admin.QueryRow(context.Background(), "SELECT keys,(SELECT count(*) FROM rate_counters WHERE family=1 AND window_start=w.window_start) FROM rate_windows w WHERE family=1 AND window_start=$1", window).Scan(&keys, &rows); err != nil || keys != 16384 || rows != 16384 {
		t.Fatalf("a full window grew: keys=%d rows=%d %v", keys, rows, err)
	}
	if existingKeyErr != nil {
		t.Fatalf("full window denied an existing key: %v", existingKeyErr)
	}
	if existingKeyStatus != 429 {
		t.Fatalf("existing key exceeded budget: %d", existingKeyStatus)
	}
}

func checkRatePurge(t *testing.T, f *observabilityFixture, window time.Time) {
	t.Helper()
	ctx := context.Background()
	if err := f.a.sharedRate(ctx, 2, "other-family", 2); err != nil {
		t.Fatal(err)
	}
	oldWindow := window.Add(-3 * time.Minute)
	if _, err := f.admin.Exec(ctx, "INSERT INTO rate_windows(family,window_start,keys) VALUES(1,$1,1)", oldWindow); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, "INSERT INTO rate_counters(family,window_start,key_hash,hits) VALUES(1,$1,sha256('old'),1)", oldWindow); err != nil {
		t.Fatal(err)
	}
	if err := f.a.cleanupSharedRates(ctx); err != nil {
		t.Fatal(err)
	}
	var old, current int
	if err := f.admin.QueryRow(ctx, "SELECT count(*) FILTER(WHERE window_start<date_trunc('minute',clock_timestamp())-interval '2 minutes'),count(*) FILTER(WHERE family=1 AND window_start=$1) FROM rate_counters", window).Scan(&old, &current); err != nil {
		t.Fatal(err)
	}
	if old != 0 || current != 16384 {
		t.Fatalf("purge old=%d current=%d", old, current)
	}
}
