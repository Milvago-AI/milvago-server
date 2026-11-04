package app

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A zero TTL is a normal SQL result during the final fractional millisecond.
// Observe the actual database calls rather than waiting for a wall-clock minute.
type quotaBoundaryTrace struct {
	mu       sync.Mutex
	finished time.Time
	gap      time.Duration
	calls    int
}

func (q *quotaBoundaryTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if data.SQL == "SELECT granted,valid_for_ms FROM reserve_rate_budget($4::smallint,$1::bytea,$2::integer,$3::integer)" {
		q.mu.Lock()
		if q.calls == 1 {
			q.gap = time.Since(q.finished)
		}
		q.calls++
		q.mu.Unlock()
	}
	return ctx
}

func (q *quotaBoundaryTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {
	q.mu.Lock()
	q.finished = time.Now()
	q.mu.Unlock()
}

func TestSharedPublicQuotaExpiredWindowRefillIsBounded(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	// Replace only the disposable fixture's SQL provider. Every returned permit
	// is recorded, including the ones the application must discard as expired.
	_, err := f.admin.Exec(ctx, `CREATE TABLE quota_boundary_calls (id bigint GENERATED ALWAYS AS IDENTITY);
CREATE OR REPLACE FUNCTION reserve_rate_budget(p_family smallint,p_key bytea,p_budget integer,p_amount integer)
RETURNS TABLE(granted integer,valid_for_ms bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $boundary$
DECLARE invocation bigint;
BEGIN
 INSERT INTO public.quota_boundary_calls DEFAULT VALUES RETURNING id INTO invocation;
 RETURN QUERY SELECT 32, CASE WHEN invocation=1 THEN 0::bigint ELSE 60000::bigint END;
END $boundary$;`)
	if err != nil {
		t.Fatal(err)
	}
	trace := &quotaBoundaryTrace{}
	cfg := f.a.db.Config()
	cfg.MaxConns = 1
	cfg.ConnConfig.Tracer = trace
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	app := &App{db: pool}
	if err = app.reservePublicRate(ctx, "boundary", 1000); err != nil {
		t.Fatalf("fresh refill after an expired window failed: %v", err)
	}
	trace.mu.Lock()
	calls, gap := trace.calls, trace.gap
	trace.mu.Unlock()
	if calls != 2 || gap < time.Millisecond {
		t.Fatalf("expired refill spun within the same fractional window: calls=%d gap=%s", calls, gap)
	}
	app.quotaReservations.mu.Lock()
	lease := app.quotaReservations.entries[string(hash("boundary"))]
	app.quotaReservations.mu.Unlock()
	if lease.remaining != 31 || !time.Now().Before(lease.expires) {
		t.Fatal("expired permits were merged into the fresh reservation")
	}
	var charged int
	if err = f.admin.QueryRow(ctx, "SELECT count(*)*32 FROM quota_boundary_calls").Scan(&charged); err != nil || charged != 64 {
		t.Fatalf("discarded permits were refunded: charged=%d err=%v", charged, err)
	}
	if _, err = f.admin.Exec(ctx, `TRUNCATE quota_boundary_calls RESTART IDENTITY;
CREATE OR REPLACE FUNCTION reserve_rate_budget(p_family smallint,p_key bytea,p_budget integer,p_amount integer)
RETURNS TABLE(granted integer,valid_for_ms bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $boundary$
BEGIN
 INSERT INTO public.quota_boundary_calls DEFAULT VALUES;
 RETURN QUERY SELECT 32, 0::bigint;
END $boundary$;`); err != nil {
		t.Fatal(err)
	}
	if got := rateStatus(app.reservePublicRate(ctx, "always-expired", 1000)); got != 503 {
		t.Fatalf("expired-only database admitted a request: %d", got)
	}
	if err = f.admin.QueryRow(ctx, "SELECT count(*) FROM quota_boundary_calls").Scan(&charged); err != nil || charged != 2 {
		t.Fatalf("refill retry was not bounded: calls=%d err=%v", charged, err)
	}
}
