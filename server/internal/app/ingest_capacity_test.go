package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestEventTransactionsPreserveAdmissionCapacity(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	cfg := f.a.db.Config()
	cfg.MaxConns = 3
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	a := &App{db: pool}
	first, err := a.eventTransaction(ctx, f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Rollback(ctx)
	// All event capacity is held, but a quota check and readiness can still use
	// the existing connection budget; no extra pool or unbounded connection.
	limited, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := a.sharedRate(limited, 1, "reserved-admission-test", 60); err != nil {
		t.Fatal(err)
	}
	if err := pool.Ping(limited); err != nil {
		t.Fatal(err)
	}
	blocked, stop := context.WithTimeout(ctx, 30*time.Millisecond)
	defer stop()
	if _, err := a.eventTransaction(blocked, f.org); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("event slot cancellation: %v", err)
	}
	if pool.Stat().AcquiredConns() != 1 || len(a.eventSlots) != 1 {
		t.Fatal("waiting event acquired a connection or leaked a slot")
	}
	if err := first.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	next, err := a.eventTransaction(limited, f.org)
	if err != nil {
		t.Fatal(err)
	}
	if err := next.Commit(limited); err != nil {
		t.Fatal(err)
	}
	_ = next.Rollback(ctx)
	if len(a.eventSlots) != 0 {
		t.Fatal("completed transaction leaked an event slot")
	}
	if pool.Stat().TotalConns() > 3 {
		t.Fatal("total connection budget was expanded")
	}
}
