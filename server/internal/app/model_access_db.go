package app

import (
	"context"
	// Required by go:embed directives in this file.
	_ "embed"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed model_access_migration.sql
var modelAccessMigration string

func initializeModelAccess(ctx context.Context, tx pgx.Tx, role string) error {
	var applied bool
	if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=5)`).Scan(&applied); e != nil {
		return e
	}
	if !applied {
		if _, e := tx.Exec(ctx, modelAccessMigration); e != nil {
			return fmt.Errorf("model access migration: %w", e)
		}
		if _, e := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES(5)`); e != nil {
			return e
		}
	}
	// Reasons that are not a model decision (2026-10-16): a blocked or redirected service, a
	// refused file, a protected word. The column check named only the model reasons.
	if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=2026101601)`).Scan(&applied); e != nil {
		return e
	}
	if !applied {
		if _, e := tx.Exec(ctx, `ALTER TABLE shadow_events DROP CONSTRAINT IF EXISTS shadow_events_decision_reason_check;
ALTER TABLE shadow_events ADD CONSTRAINT shadow_events_decision_reason_check CHECK(decision_reason IN ('','model_denied','model_unknown','control_unavailable','service_blocked','service_redirected','upload_blocked','keyword')) NOT VALID;`); e != nil {
			return fmt.Errorf("event decision reasons migration: %w", e)
		}
		// NOT VALID skips the scan under ADD CONSTRAINT's exclusive lock: existing rows are checked
		// by validateDecisionReasons, once this transaction has committed.
		if _, e := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES(2026101601) ON CONFLICT DO NOTHING`); e != nil {
			return e
		}
	}
	_, e := tx.Exec(ctx, `GRANT SELECT,INSERT,UPDATE,DELETE ON model_enforcement TO `+role)
	return e
}

// validateDecisionReasons checks the existing events against the decision reason constraint in a
// transaction of its own, after the migration has committed: VALIDATE then only takes a SHARE UPDATE
// EXCLUSIVE lock, so events keep being written during the scan. It runs at every start until the
// constraint is validated, so a start interrupted between the two steps finishes the job.
func validateDecisionReasons(ctx context.Context, pool *pgxpool.Pool) error {
	tx, e := pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(726403210)`); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `DO $v$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname='shadow_events_decision_reason_check' AND conrelid='shadow_events'::regclass AND NOT convalidated) THEN
    ALTER TABLE shadow_events VALIDATE CONSTRAINT shadow_events_decision_reason_check;
  END IF;
END $v$`); e != nil {
		return fmt.Errorf("event decision reasons validation: %w", e)
	}
	return tx.Commit(ctx)
}
