package app

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// Migrations install read indexes; API processes keep their existing non-DDL role.
// Keep operator limits when stricter, and restore both settings in this transaction.
func initializeDataReadIndexes(ctx context.Context, tx pgx.Tx) error {
	var originalLock, originalStatement string
	if err := tx.QueryRow(ctx, `SELECT current_setting('lock_timeout'), current_setting('statement_timeout')`).Scan(&originalLock, &originalStatement); err != nil {
		return err
	}
	for _, setting := range []string{
		`SELECT set_config('lock_timeout', CASE WHEN setting::bigint BETWEEN 1 AND 2000 THEN current_setting('lock_timeout') ELSE '2000ms' END, true) FROM pg_settings WHERE name='lock_timeout'`,
		`SELECT set_config('statement_timeout', CASE WHEN setting::bigint BETWEEN 1 AND 60000 THEN current_setting('statement_timeout') ELSE '60000ms' END, true) FROM pg_settings WHERE name='statement_timeout'`,
	} {
		if _, err := tx.Exec(ctx, setting); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `CREATE INDEX IF NOT EXISTS shadow_events_presence_inventory
	 ON public.shadow_events(organization_id,provider,device_id,user_key)
	 INCLUDE(action,occurred_at) WHERE detector='presence'`); err != nil {
		return err
	}
	var valid bool
	if err := tx.QueryRow(ctx, `SELECT i.indisvalid AND i.indisready
	 AND i.indrelid='public.shadow_events'::regclass AND am.amname='btree'
	 AND i.indnkeyatts=4 AND i.indnatts=6
	 AND ARRAY(SELECT a.attname::text FROM unnest(i.indkey) WITH ORDINALITY k(attnum,n)
	 JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum ORDER BY k.n)
	 =ARRAY['organization_id','provider','device_id','user_key','action','occurred_at']
	 AND pg_get_expr(i.indpred,i.indrelid)='(detector = ''presence''::text)'
	 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_am am ON am.oid=c.relam
	 WHERE i.indexrelid=to_regclass('public.shadow_events_presence_inventory')`).Scan(&valid); err != nil {
		return err
	}
	if !valid {
		return errors.New("presence inventory index has an incompatible definition")
	}
	_, err := tx.Exec(ctx, `SELECT set_config('lock_timeout',$1,true),set_config('statement_timeout',$2,true)`, originalLock, originalStatement)
	return err
}
