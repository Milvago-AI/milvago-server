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
	// Stay within one database minute, including on a slow runner.
	var remaining float64
	if err := f.admin.QueryRow(ctx, "SELECT 60-extract(second FROM clock_timestamp())").Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining < 15 {
		time.Sleep(time.Duration(remaining*float64(time.Second)) + 100*time.Millisecond)
	}
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
	var wg sync.WaitGroup
	results := make(chan error, 100)
	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results <- replicas[i%4].checkIngestRate(ctx, "shared-device /v2/events", 50)
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
	if accepted != 50 || limited != 50 {
		t.Fatalf("four replicas accepted=%d limited=%d; want 50 each", accepted, limited)
	}
	restarted := &App{db: replicas[0].db}
	if got := rateStatus(restarted.checkIngestRate(ctx, "shared-device /v2/events", 50)); got != 429 {
		t.Fatalf("new process bypassed spent quota: %d", got)
	}
	// Business rollback does not refund separately committed admission.
	tx, err := tenantTx(ctx, f.a.db, f.org)
	if err != nil {
		t.Fatal(err)
	}
	if err = restarted.checkIngestRate(ctx, "rollback-key", 1); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if got := rateStatus((&App{db: replicas[1].db}).checkIngestRate(ctx, "rollback-key", 1)); got != 429 {
		t.Fatalf("rollback refunded quota: %d", got)
	}
	// Forwarded addresses are not identities, and a new process cannot evade the peer budget.
	for i := range 4 {
		request := httptest.NewRequest("GET", "http://localhost/auth/login", nil)
		request.RemoteAddr = "192.0.2.1:1000"
		request.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", i+1))
		got := rateStatus(replicas[i].checkPublicRequest(request, "test-login", 3, 30))
		want := 200
		if i == 3 {
			want = 429
		}
		if got != want {
			t.Fatalf("peer admission %d: %d want %d", i, got, want)
		}
	}
	var owner, selectable, writable bool
	if err = f.a.db.QueryRow(ctx, "SELECT pg_has_role(current_user,pg_get_userbyid(relowner),'USAGE'),has_table_privilege(current_user,'rate_counters','SELECT'),has_table_privilege(current_user,'rate_counters','UPDATE') FROM pg_class WHERE oid='rate_counters'::regclass").Scan(&owner, &selectable, &writable); err != nil {
		t.Fatal(err)
	}
	if owner || selectable || writable {
		t.Fatal("runtime role can read or change quota storage")
	}
	var hasPublic bool
	if err = f.admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_proc p,aclexplode(p.proacl) acl WHERE p.oid='consume_rate_budget(smallint,bytea,integer)'::regprocedure AND acl.grantee=0)").Scan(&hasPublic); err != nil || hasPublic {
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

func TestSharedRateBoundedStorageAndPurge(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	var remaining float64
	if err := f.admin.QueryRow(ctx, "SELECT 60-extract(second FROM clock_timestamp())").Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining < 15 {
		time.Sleep(time.Duration(remaining*float64(time.Second)) + 100*time.Millisecond)
	}
	// Build a genuinely full current family, not merely an asserted counter.
	if _, err := f.admin.Exec(ctx, "INSERT INTO rate_windows(family,window_start,keys) VALUES(1,date_trunc('minute',clock_timestamp()),16384); INSERT INTO rate_counters(family,window_start,key_hash,hits) SELECT 1,date_trunc('minute',clock_timestamp()),sha256(convert_to('capacity-'||i,'UTF8')),1 FROM generate_series(1,16384)i"); err != nil {
		t.Fatal(err)
	}
	// Full: a new key is admitted without being counted, and the window does not grow.
	if err := f.a.sharedRate(ctx, 1, "one-more-key", 2); err != nil {
		t.Fatalf("a full window refused a new key: %v", err)
	}
	var keys, rows int
	if err := f.admin.QueryRow(ctx, "SELECT keys,(SELECT count(*) FROM rate_counters WHERE family=1 AND window_start=w.window_start) FROM rate_windows w WHERE family=1 AND window_start=date_trunc('minute',clock_timestamp())").Scan(&keys, &rows); err != nil || keys != 16384 || rows != 16384 {
		t.Fatalf("a full window grew: keys=%d rows=%d %v", keys, rows, err)
	}
	if err := f.a.sharedRate(ctx, 1, "capacity-1", 2); err != nil {
		t.Fatalf("full window denied an existing key: %v", err)
	}
	if got := rateStatus(f.a.sharedRate(ctx, 1, "capacity-1", 2)); got != 429 {
		t.Fatalf("existing key exceeded budget: %d", got)
	}
	if err := f.a.sharedRate(ctx, 2, "other-family", 2); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, "INSERT INTO rate_windows(family,window_start,keys) VALUES(1,date_trunc('minute',clock_timestamp())-interval '3 minutes',1); INSERT INTO rate_counters(family,window_start,key_hash,hits) VALUES(1,date_trunc('minute',clock_timestamp())-interval '3 minutes',sha256('old'),1)"); err != nil {
		t.Fatal(err)
	}
	if err := f.a.cleanupSharedRates(ctx); err != nil {
		t.Fatal(err)
	}
	var old, current int
	if err := f.admin.QueryRow(ctx, "SELECT count(*) FILTER(WHERE window_start<date_trunc('minute',clock_timestamp())-interval '2 minutes'),count(*) FILTER(WHERE family=1 AND window_start=date_trunc('minute',clock_timestamp())) FROM rate_counters").Scan(&old, &current); err != nil {
		t.Fatal(err)
	}
	if old != 0 || current != 16384 {
		t.Fatalf("purge old=%d current=%d", old, current)
	}
}
