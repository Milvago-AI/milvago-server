package app

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/jackc/pgx/v5"
)

//go:embed api_keys_migration.sql
var apiKeysMigration string

// initializeAPIKeys creates the api_keys table, its tenant policy and the
// cross-tenant resolution function once, then re-issues the runtime grants on
// every boot. Version-gated because the file is not idempotent: it transfers the
// ownership of a SECURITY DEFINER function, which must happen exactly once.
func initializeAPIKeys(ctx context.Context, tx pgx.Tx, role string) error {
	var applied bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=6)`).Scan(&applied); err != nil {
		return err
	}
	if !applied {
		if _, err := tx.Exec(ctx, apiKeysMigration); err != nil {
			return fmt.Errorf("api keys migration: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES(6)`); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `GRANT SELECT,INSERT,UPDATE,DELETE ON api_keys TO `+role+`; GRANT EXECUTE ON FUNCTION api_key_identity(bytea) TO `+role)
	return err
}
