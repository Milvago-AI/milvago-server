package app

import (
	"context"
	"sync"

	"github.com/jackc/pgx/v5"
)

// An event batch may perform far more work than an admission check. Leave two
// connections available for short authorization/quota queries and health checks,
// within the existing pool budget. Waiting batches consume no pool connection.
func (a *App) eventTransaction(ctx context.Context, org string) (pgx.Tx, error) {
	a.eventSlotsOnce.Do(func() {
		limit := max(1, int(a.db.Config().MaxConns)-2)
		a.eventSlots = make(chan struct{}, limit)
	})
	select {
	case a.eventSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	tx, err := tenantTx(ctx, a.db, org)
	if err != nil {
		<-a.eventSlots
		return nil, err
	}
	return &eventTx{Tx: tx, release: func() { <-a.eventSlots }}, nil
}

type eventTx struct {
	pgx.Tx
	once    sync.Once
	release func()
}

func (t *eventTx) Commit(ctx context.Context) error {
	defer t.once.Do(t.release)
	return t.Tx.Commit(ctx)
}
func (t *eventTx) Rollback(ctx context.Context) error {
	defer t.once.Do(t.release)
	return t.Tx.Rollback(ctx)
}
