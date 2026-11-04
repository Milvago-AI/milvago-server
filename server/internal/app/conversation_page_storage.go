package app

import (
	"context"
	_ "embed"

	"github.com/jackc/pgx/v5"
)

//go:embed conversation_page_storage.sql
var conversationPageStorage string

func initializeConversationPaging(ctx context.Context, tx pgx.Tx) error {
	var lock, statement string
	var lockMillis, statementMillis int64
	if err := tx.QueryRow(ctx, `SELECT current_setting('lock_timeout'),current_setting('statement_timeout'),
	 (SELECT setting::bigint FROM pg_settings WHERE name='lock_timeout'),
	 (SELECT setting::bigint FROM pg_settings WHERE name='statement_timeout')`).Scan(&lock, &statement, &lockMillis, &statementMillis); err != nil {
		return err
	}
	boundedLock, boundedStatement := lock, statement
	if lockMillis == 0 || lockMillis > 3000 {
		boundedLock = "3s"
	}
	if statementMillis == 0 || statementMillis > 60000 {
		boundedStatement = "60s"
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout',$1,true),set_config('statement_timeout',$2,true)`, boundedLock, boundedStatement); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, conversationPageStorage); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `SELECT set_config('lock_timeout',$1,true),set_config('statement_timeout',$2,true)`, lock, statement)
	return err
}
