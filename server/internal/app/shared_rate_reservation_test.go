package app

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSharedPublicQuotaReservations(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	var remaining float64
	if err := f.admin.QueryRow(ctx, "SELECT 60-extract(second FROM clock_timestamp())").Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining < 15 {
		time.Sleep(time.Duration(remaining*float64(time.Second)) + 100*time.Millisecond)
	}
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
		var wg sync.WaitGroup
		results := make(chan int, 600)
		for _, replica := range replicas {
			wg.Add(1)
			go func(a *App) {
				defer wg.Done()
				for range 150 {
					results <- rateStatus(a.reservePublicRate(ctx, "concurrent-public", 101))
				}
			}(replica)
		}
		wg.Wait()
		close(results)
		accepted, rejected := 0, 0
		for status := range results {
			switch status {
			case 200:
				accepted++
			case 429:
				rejected++
			default:
				t.Fatalf("unexpected status %d", status)
			}
		}
		if accepted != 101 || rejected != 499 {
			t.Fatalf("global budget: accepted=%d rejected=%d", accepted, rejected)
		}
		var spent int
		if err := f.admin.QueryRow(ctx, "SELECT hits FROM rate_counters WHERE family=2 AND key_hash=$1 AND window_start=date_trunc('minute',clock_timestamp())", hash("concurrent-public")).Scan(&spent); err != nil || spent != 101 {
			t.Fatalf("durable reservation count %d: %v", spent, err)
		}
	})
	t.Run("restart_loses_unused_permits_without_refund", func(t *testing.T) {
		original := &App{db: f.a.db}
		if err := original.reservePublicRate(ctx, "restart-public", 65); err != nil {
			t.Fatal(err)
		}
		restarted := &App{db: f.a.db}
		accepted := 0
		for range 40 {
			status := rateStatus(restarted.reservePublicRate(ctx, "restart-public", 65))
			if status == 200 {
				accepted++
			} else if status != 429 {
				t.Fatalf("unexpected restart status %d", status)
			}
		}
		// 32 charged before the original process used its first permit. The new
		// process can consume only the remaining 33, even though 31 were abandoned.
		if accepted != 33 {
			t.Fatalf("restart recreated or lost unreserved permits: %d", accepted)
		}
	})
	t.Run("expired_local_reservation_is_not_reused", func(t *testing.T) {
		a := &App{db: f.a.db}
		if err := a.reservePublicRate(ctx, "expired-public", 32); err != nil {
			t.Fatal(err)
		}
		a.quotaReservations.mu.Lock()
		key := string(hash("expired-public"))
		lease := a.quotaReservations.entries[key]
		if lease.remaining != 31 || !time.Now().Before(lease.expires) {
			t.Fatal("reservation precondition missing")
		}
		lease.expires = time.Now().Add(-time.Millisecond)
		a.quotaReservations.entries[key] = lease
		a.quotaReservations.mu.Unlock()
		if got := rateStatus(a.reservePublicRate(ctx, "expired-public", 32)); got != 429 {
			t.Fatalf("expired permits admitted a request: %d", got)
		}
	})
	t.Run("a_lower_budget_does_not_reuse_old_permits", func(t *testing.T) {
		a := &App{db: f.a.db}
		if err := a.reservePublicRate(ctx, "changed-budget", 64); err != nil {
			t.Fatal(err)
		}
		if got := rateStatus(a.reservePublicRate(ctx, "changed-budget", 1)); got != 429 {
			t.Fatalf("old reservation bypassed a lower budget: %d", got)
		}
	})
	t.Run("database_clock_and_privileges", func(t *testing.T) {
		var granted int
		var validFor int64
		var hasPublic bool
		if err := f.a.db.QueryRow(ctx, "SELECT granted,valid_for_ms FROM reserve_rate_budget(2::smallint,$1::bytea,10,32)", hash("clock-public")).Scan(&granted, &validFor); err != nil {
			t.Fatal(err)
		}
		if granted != 10 || validFor <= 0 || validFor > 60000 {
			t.Fatalf("invalid reservation amount/TTL %d/%d", granted, validFor)
		}
		if err := f.admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_proc p,aclexplode(p.proacl) acl WHERE p.oid='reserve_rate_budget(smallint,bytea,integer,integer)'::regprocedure AND acl.grantee=0)").Scan(&hasPublic); err != nil || hasPublic {
			t.Fatalf("public execution permitted: %v %v", hasPublic, err)
		}
	})
	t.Run("new_reservation_requires_database", func(t *testing.T) {
		pool, err := pgxpool.NewWithConfig(ctx, f.a.db.Config())
		if err != nil {
			t.Fatal(err)
		}
		pool.Close()
		if got := rateStatus((&App{db: pool}).reservePublicRate(ctx, "closed-public", 6000)); got != 503 {
			t.Fatalf("database-free reservation status %d", got)
		}
	})
}
