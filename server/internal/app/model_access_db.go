package app

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/jackc/pgx/v5"
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
	_, e := tx.Exec(ctx, `GRANT SELECT,INSERT,UPDATE,DELETE ON model_enforcement TO `+role)
	return e
}
