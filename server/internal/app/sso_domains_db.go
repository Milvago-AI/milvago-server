package app

import (
	"context"
	// Required by go:embed directives in this file.
	_ "embed"
	"fmt"

	"github.com/jackc/pgx/v5"
)

//go:embed sso_domains_migration.sql
var ssoDomainsMigration string

// initializeSSODomains creates the proven-domain table once (it transfers the ownership
// of a SECURITY DEFINER function, which must happen exactly once) and re-issues the
// runtime grants on every boot.
func initializeSSODomains(ctx context.Context, tx pgx.Tx, role string) error {
	var applied bool
	if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=20260928)`).Scan(&applied); e != nil {
		return e
	}
	if !applied {
		if _, e := tx.Exec(ctx, ssoDomainsMigration); e != nil {
			return fmt.Errorf("sso domains migration: %w", e)
		}
		if _, e := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES(20260928)`); e != nil {
			return e
		}
	}
	_, e := tx.Exec(ctx, `GRANT SELECT,INSERT,UPDATE,DELETE ON sso_domains TO `+role+`; GRANT EXECUTE ON FUNCTION sso_domain_owner(text) TO `+role)
	return e
}
