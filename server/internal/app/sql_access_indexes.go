package app

import (
	"context"
	_ "embed"

	"github.com/jackc/pgx/v5"
)

//go:embed sql_access_indexes.sql
var sqlAccessIndexes string

// Run after all service tables exist, in the migration transaction only.
// Preserve stricter operator limits and abort the upgrade on a lock/build timeout.
func initializeSQLAccessIndexes(ctx context.Context, tx pgx.Tx) error {
	return initializeBoundedReadMigration(ctx, tx, sqlAccessIndexes)
}

func initializeBoundedReadMigration(ctx context.Context, tx pgx.Tx, ddl string) error {
	var lock, statement string
	if err := tx.QueryRow(ctx, `SELECT current_setting('lock_timeout'),current_setting('statement_timeout')`).Scan(&lock, &statement); err != nil {
		return err
	}
	for _, query := range []string{
		`SELECT set_config('lock_timeout',CASE WHEN setting::bigint BETWEEN 1 AND 2000 THEN current_setting('lock_timeout') ELSE '2000ms' END,true) FROM pg_settings WHERE name='lock_timeout'`,
		`SELECT set_config('statement_timeout',CASE WHEN setting::bigint BETWEEN 1 AND 60000 THEN current_setting('statement_timeout') ELSE '60000ms' END,true) FROM pg_settings WHERE name='statement_timeout'`,
		ddl,
	} {
		if _, err := tx.Exec(ctx, query); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `SELECT set_config('lock_timeout',$1,true),set_config('statement_timeout',$2,true)`, lock, statement)
	return err
}
