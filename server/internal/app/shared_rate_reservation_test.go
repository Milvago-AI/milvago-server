package app

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSharedPublicQuotaReservations(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	replicas := make([]*App, 4)
	for i := range replicas {
		cfg := f.a.db.Config()
		cfg.MaxConns = 4
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		replicas[i] = &App{db: pool}
	}
	t.Run("four_replicas_partial_last_reservation", func(t *testing.T) {
		checkConcurrentPublicReservations(t, f, replicas)
	})
	t.Run("restart_loses_unused_permits_without_refund", func(t *testing.T) {
		checkRestartedPublicReservation(t, f)
	})
	t.Run("expired_local_reservation_is_not_reused", func(t *testing.T) {
		checkExpiredPublicReservation(t, f)
	})
	t.Run("a_lower_budget_does_not_reuse_old_permits", func(t *testing.T) {
		checkChangedPublicBudget(t, f)
	})
	t.Run("database_clock_and_privileges", func(t *testing.T) {
		checkPublicReservationClock(t, f)
	})
	t.Run("new_reservation_requires_database", func(t *testing.T) {
		checkPublicReservationOutage(t, f)
	})
}

func publicReservationOutcomes(ctx context.Context, replicas []*App, key string) (accepted, rejected, unexpected int) {
	var wg sync.WaitGroup
	results := make(chan int, 600)
	for _, replica := range replicas {
		wg.Add(1)
		go func(a *App) {
			defer wg.Done()
			for range 150 {
				results <- rateStatus(a.reservePublicRate(ctx, key, 101))
			}
		}(replica)
	}
	wg.Wait()
	close(results)
	unexpected = -1
	for status := range results {
		switch status {
		case 200:
			accepted++
		case 429:
			rejected++
		default:
			unexpected = status
		}
	}
	return
}

func checkConcurrentPublicReservations(t *testing.T, f *observabilityFixture, replicas []*App) {
	t.Helper()
	ctx := context.Background()
	for attempt := range 3 {
		key := fmt.Sprintf("concurrent-public-%d", attempt)
		window := currentRateWindow(t, f.admin)
		accepted, rejected, unexpected := publicReservationOutcomes(ctx, replicas, key)
		if unexpected >= 0 {
			t.Fatalf("unexpected status %d", unexpected)
		}
		if !currentRateWindow(t, f.admin).Equal(window) {
			continue
		}
		if accepted != 101 || rejected != 499 {
			t.Fatalf("global budget: accepted=%d rejected=%d", accepted, rejected)
		}
		var spent int
		if err := f.admin.QueryRow(ctx, "SELECT hits FROM rate_counters WHERE family=2 AND key_hash=$1 AND window_start=$2", hash(key), window).Scan(&spent); err != nil || spent != 101 {
			t.Fatalf("durable reservation count %d: %v", spent, err)
		}
		return
	}
	t.Fatal("concurrent reservation could not finish within one database minute")
}

func checkRestartedPublicReservation(t *testing.T, f *observabilityFixture) {
	t.Helper()
	ctx := context.Background()
	for attempt := range 3 {
		key := fmt.Sprintf("restart-public-%d", attempt)
		window := currentRateWindow(t, f.admin)
		original := &App{db: f.a.db}
		if err := original.reservePublicRate(ctx, key, 65); err != nil {
			t.Fatal(err)
		}
		restarted := &App{db: f.a.db}
		accepted := 0
		for range 40 {
			status := rateStatus(restarted.reservePublicRate(ctx, key, 65))
			if status == 200 {
				accepted++
			} else if status != 429 {
				t.Fatalf("unexpected restart status %d", status)
			}
		}
		if !currentRateWindow(t, f.admin).Equal(window) {
			continue
		}
		// 32 charged before the original process used its first permit. The new
		// process can consume only the remaining 33, even though 31 were abandoned.
		if accepted != 33 {
			t.Fatalf("restart recreated or lost unreserved permits: %d", accepted)
		}
		return
	}
	t.Fatal("restart quota could not finish within one database minute")
}

func checkExpiredPublicReservation(t *testing.T, f *observabilityFixture) {
	t.Helper()
	ctx := context.Background()
	for attempt := range 3 {
		key := fmt.Sprintf("expired-public-%d", attempt)
		window := currentRateWindow(t, f.admin)
		a := &App{db: f.a.db}
		if err := a.reservePublicRate(ctx, key, 32); err != nil {
			t.Fatal(err)
		}
		a.quotaReservations.mu.Lock()
		cacheKey := string(hash(key))
		lease := a.quotaReservations.entries[cacheKey]
		ready := lease.remaining == 31 && time.Now().Before(lease.expires)
		if ready {
			lease.expires = time.Now().Add(-time.Millisecond)
			a.quotaReservations.entries[cacheKey] = lease
		}
		a.quotaReservations.mu.Unlock()
		if !ready {
			if !currentRateWindow(t, f.admin).Equal(window) {
				continue
			}
			t.Fatal("reservation precondition missing")
		}
		got := rateStatus(a.reservePublicRate(ctx, key, 32))
		if !currentRateWindow(t, f.admin).Equal(window) {
			continue
		}
		if got != 429 {
			t.Fatalf("expired permits admitted a request: %d", got)
		}
		return
	}
	t.Fatal("expired lease check could not finish within one database minute")
}

func checkChangedPublicBudget(t *testing.T, f *observabilityFixture) {
	t.Helper()
	ctx := context.Background()
	for attempt := range 3 {
		key := fmt.Sprintf("changed-budget-%d", attempt)
		window := currentRateWindow(t, f.admin)
		a := &App{db: f.a.db}
		if err := a.reservePublicRate(ctx, key, 64); err != nil {
			t.Fatal(err)
		}
		got := rateStatus(a.reservePublicRate(ctx, key, 1))
		if !currentRateWindow(t, f.admin).Equal(window) {
			continue
		}
		if got != 429 {
			t.Fatalf("old reservation bypassed a lower budget: %d", got)
		}
		return
	}
	t.Fatal("budget change check could not finish within one database minute")
}

func checkPublicReservationClock(t *testing.T, f *observabilityFixture) {
	t.Helper()
	ctx := context.Background()
	stable := false
	for attempt := range 3 {
		key := fmt.Sprintf("clock-public-%d", attempt)
		window := currentRateWindow(t, f.admin)
		var granted int
		var validFor int64
		if err := f.a.db.QueryRow(ctx, "SELECT granted,valid_for_ms FROM reserve_rate_budget(2::smallint,$1::bytea,10,32)", hash(key)).Scan(&granted, &validFor); err != nil {
			t.Fatal(err)
		}
		if !currentRateWindow(t, f.admin).Equal(window) {
			continue
		}
		if granted != 10 || validFor <= 0 || validFor > 60000 {
			t.Fatalf("invalid reservation amount/TTL %d/%d", granted, validFor)
		}
		stable = true
		break
	}
	if !stable {
		t.Fatal("reservation clock could not be checked within one database minute")
	}
	var hasPublic bool
	if err := f.admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_proc p,aclexplode(p.proacl) acl WHERE p.oid='reserve_rate_budget(smallint,bytea,integer,integer)'::regprocedure AND acl.grantee=0)").Scan(&hasPublic); err != nil || hasPublic {
		t.Fatalf("public execution permitted: %v %v", hasPublic, err)
	}
}

func checkPublicReservationOutage(t *testing.T, f *observabilityFixture) {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.NewWithConfig(ctx, f.a.db.Config())
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	if got := rateStatus((&App{db: pool}).reservePublicRate(ctx, "closed-public", 6000)); got != 503 {
		t.Fatalf("database-free reservation status %d", got)
	}
}
