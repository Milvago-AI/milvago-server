package app

import (
	"context"
	_ "embed"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

//go:embed shared_rate_migration.sql
var sharedRateMigration string

func initializeSharedRates(ctx context.Context, tx pgx.Tx, role string) error {
	if _, err := tx.Exec(ctx, sharedRateMigration); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `REVOKE ALL ON rate_windows,rate_counters FROM `+role+`; GRANT EXECUTE ON FUNCTION reserve_rate_budget(smallint,bytea,integer,integer),consume_rate_budget(smallint,bytea,integer),cleanup_rate_budgets() TO `+role)
	return err
}

func rateLimited() error { return apiError{429, "rate_limited", "Too many requests. Retry shortly."} }

// sharedRate commits independently of the request's tenant transaction.
// A rollback never refunds quota; database failures never fall back to local counters.
func (a *App) sharedRate(ctx context.Context, family int16, key string, budget int) error {
	if a.db == nil {
		return apiError{503, "rate_limit_unavailable", "Request admission is temporarily unavailable."}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var allowed bool
	if err := a.db.QueryRow(ctx, `SELECT consume_rate_budget($1::smallint,$2::bytea,$3::integer)`, family, hash(key), budget).Scan(&allowed); err != nil {
		return apiError{503, "rate_limit_unavailable", "Request admission is temporarily unavailable."}
	}
	if !allowed {
		return rateLimited()
	}
	return nil
}

func (a *App) checkIngestRate(ctx context.Context, key string, budget int) error {
	if !a.ingestRate.allow(key, budget, time.Now()) {
		return rateLimited()
	}
	return a.sharedRate(ctx, 1, key, budget)
}

func (a *App) checkPublicRequest(r *http.Request, operation string, peerBudget, totalBudget int) error {
	if !a.allowPublicRequest(r, operation, peerBudget, totalBudget) {
		return rateLimited()
	}
	peer := publicPeer(r)
	// Totals in family 3, peers in family 2: filling the peer window can never leave
	// a total uncounted (audit of 2026-09-24).
	if operation == "device-auth" {
		if err := a.reserveRate(r.Context(), 2, operation+" peer:"+peer, peerBudget); err != nil {
			return err
		}
		return a.reserveRate(r.Context(), 3, operation+" total", totalBudget)
	}
	if err := a.sharedRate(r.Context(), 2, operation+" peer:"+peer, peerBudget); err != nil {
		return err
	}
	return a.sharedRate(r.Context(), 3, operation+" total", totalBudget)
}

func (a *App) cleanupSharedRates(ctx context.Context) error {
	_, err := a.db.Exec(ctx, `SELECT cleanup_rate_budgets()`)
	return err
}
