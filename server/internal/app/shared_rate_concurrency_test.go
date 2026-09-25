package app

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSharedPublicQuotaConcurrentRefill(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	var remaining float64
	if err := f.admin.QueryRow(ctx, "SELECT 60-extract(second FROM clock_timestamp())").Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining < 10 {
		time.Sleep(time.Duration(remaining*float64(time.Second)) + 100*time.Millisecond)
	}
	cfg := f.a.db.Config()
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	a := &App{db: pool}
	if err := a.reservePublicRate(ctx, "warm-independent", 6000); err != nil {
		t.Fatal(err)
	}
	held, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	parent, cancel := context.WithCancel(ctx)
	defer cancel()
	leader := make(chan int, 1)
	go func() { leader <- rateStatus(a.reservePublicRate(parent, "blocked-refill", 6000)) }()
	// The only connection is held. Observe a refill marker without blocking on
	// the map mutex: a refill must not hold that mutex during its database wait.
	waitForQuotaRefill(t, a)
	assertIndependentRateReservation(t, a, parent, leader, held)
	assertQuotaBurst(t, f, a, ctx)
}

func waitForQuotaRefill(t *testing.T, a *App) {
	deadline := time.Now().Add(time.Second)
	loading := false
	for !loading && time.Now().Before(deadline) {
		if a.quotaReservations.mu.TryLock() {
			loading = a.quotaReservations.entries[string(hash("blocked-refill"))].loading != nil
			a.quotaReservations.mu.Unlock()
		}
		if !loading {
			time.Sleep(time.Millisecond)
		}
	}
	if !loading {
		t.Fatal("refill did not start independently of the cache mutex")
	}
}

func assertIndependentRateReservation(t *testing.T, a *App, parent context.Context, leader <-chan int, held *pgxpool.Conn) {
	select {
	case <-leader:
		t.Fatal("refill did not remain blocked on the held connection")
	default:
	}
	fast := make(chan int, 1)
	go func() { fast <- rateStatus(a.reservePublicRate(parent, "warm-independent", 6000)) }()
	select {
	case status := <-fast:
		if status != 200 {
			t.Fatalf("prepaid independent key: %d", status)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("unrelated refill blocked prepaid permits")
	}
	waiter, stop := context.WithTimeout(parent, 30*time.Millisecond)
	defer stop()
	started := time.Now()
	if status := rateStatus(a.reservePublicRate(waiter, "blocked-refill", 6000)); status != 503 || time.Since(started) > 250*time.Millisecond {
		t.Fatalf("refill follower ignored cancellation: status=%d duration=%s", status, time.Since(started))
	}
	held.Release()
	if status := <-leader; status != 200 {
		t.Fatalf("refill after pool recovery: %d", status)
	}
}

func assertQuotaBurst(t *testing.T, f *observabilityFixture, a *App, ctx context.Context) {
	var wg sync.WaitGroup
	results := make(chan int, 128)
	for range 128 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- rateStatus(a.reservePublicRate(ctx, "same-key-burst", 65)) }()
	}
	wg.Wait()
	close(results)
	accepted := 0
	for status := range results {
		if status == 200 {
			accepted++
		} else if status != 429 {
			t.Fatalf("concurrent quota status: %d", status)
		}
	}
	if accepted != 65 {
		t.Fatalf("concurrent permits=%d, want 65", accepted)
	}
	var charged int
	if err := f.admin.QueryRow(ctx, "SELECT hits FROM rate_counters WHERE family=2 AND key_hash=$1 AND window_start=date_trunc('minute',clock_timestamp())", hash("same-key-burst")).Scan(&charged); err != nil || charged != 65 {
		t.Fatalf("durable permits=%d: %v", charged, err)
	}
}
