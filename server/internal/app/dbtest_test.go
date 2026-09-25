package app

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// setTenant points the admin connection at one organization for the rest of the
// current subtest, and restores what it found when that subtest ends.
//
// Two properties make the raw call dangerous enough to be worth a helper. The
// setting is **session** scoped, not transaction local, and the admin pool is capped
// at a single connection — so it is not this statement's context, it is every later
// query's context, for the whole test. And the tables it governs are under FORCE row
// level security, so a stale value does not raise: an UPDATE simply matches no rows
// and reports success. A subtest that changed it and then failed an assertion before
// changing it back used to leave the next subtest writing into nothing.
//
// The restore runs through t.Cleanup precisely so that it survives a t.Fatal in
// between, which a trailing "set it back" line does not.
func setTenant(t *testing.T, admin *pgxpool.Pool, org string) {
	t.Helper()
	ctx := context.Background()
	var previous string
	if e := admin.QueryRow(ctx, `SELECT coalesce(current_setting('milvago.organization_id',true),'')`).Scan(&previous); e != nil {
		t.Fatal(e)
	}
	if _, e := admin.Exec(ctx, `SELECT set_config('milvago.organization_id',$1,false)`, org); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if _, e := admin.Exec(ctx, `SELECT set_config('milvago.organization_id',$1,false)`, previous); e != nil {
			t.Errorf("could not restore the tenant context: %v", e)
		}
	})
}
