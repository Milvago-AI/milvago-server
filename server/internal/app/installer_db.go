package app

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/jackc/pgx/v5"
)

//go:embed installer_migration.sql
var installerMigration string

func initializeInstallers(ctx context.Context, tx pgx.Tx, role string) error {
	var applied bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=4)`).Scan(&applied); err != nil {
		return err
	}
	if !applied {
		if _, err := tx.Exec(ctx, installerMigration); err != nil {
			return fmt.Errorf("installer migration: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES(4)`); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `GRANT SELECT,INSERT,UPDATE,DELETE ON installer_profiles,installer_installations TO `+role+`; GRANT EXECUTE ON FUNCTION installer_identity(bytea) TO `+role)
	return err
}
