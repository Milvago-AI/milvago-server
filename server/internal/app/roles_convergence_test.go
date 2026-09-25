package app

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Purging retained prompt text is an irreversible mass DELETE. Until 2026-09-21 it was
// gated by `content.read`, so every role that could merely consult a prompt could also
// erase the lot. It now has its own owner-only permission, and this is what keeps that
// true: admin holds content.read and must still be refused.
func TestContentPurgeIsNotReachableWithReadAlone(t *testing.T) {
	p := newProjectionFixture(t)
	body := map[string]any{"before": time.Now().UTC()}

	if !slices.Contains(builtinRolePermissions["admin"], permContentRead) {
		t.Fatal("fixture broken: admin no longer holds content.read, so this proves nothing")
	}
	if slices.Contains(builtinRolePermissions["admin"], permContentPurge) {
		t.Fatal("fixture broken: admin was granted content.purge, so the refusal below would prove nothing (owner-only is a policy choice; the console panel follows the permission)")
	}

	if w := p.as("admin", "POST", "/api/shadow/content/purge", body); w.Code != 403 {
		t.Fatalf("an admin holding content.read purged content: %d %s", w.Code, w.Body.String())
	}
	if w := p.as("viewer", "POST", "/api/shadow/content/purge", body); w.Code != 403 {
		t.Fatalf("a viewer reached the purge: %d %s", w.Code, w.Body.String())
	}
	// The owner keeps it, and the fixture already gave that session a fresh second
	// factor -- without which the handler refuses on its own, for a different reason.
	if w := p.as("owner", "POST", "/api/shadow/content/purge", body); w.Code != 200 {
		t.Fatalf("the owner was refused the purge: %d %s", w.Code, w.Body.String())
	}
}

// The permissions of a built-in role are stated in more than one place, and they only
// agree because the boot sequence repairs itself in a particular order: the seed loop
// in db.go overwrites every built-in role from a SQL literal on EVERY boot, and later
// statements add back what that literal does not carry. Reorder those two and an owner
// silently loses rights on the next restart.
//
// This test is the guard. It compares what the database actually holds after boot with
// builtinRolePermissions, which is the set the Go code believes in. It catches a
// permission added to the catalogue with no database counterpart, a repair placed
// before the overwrite instead of after, a repair gated by schema_migrations so it runs
// once and is then undone, and any future edit to the SQL literal.
//
// It runs in both editions and picks up the Enterprise-only permissions for free.
func TestBuiltinRolePermissionsConverge(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	check := func(t *testing.T, when string) {
		t.Helper()
		tx, e := tenantTx(ctx, f.a.db, f.org)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		assertBuiltinRoles(t, ctx, tx, when)
	}
	check(t, "after the first boot")

	// The failure this guards against only appears on the SECOND boot: the seed loop
	// overwrites every built-in role from a literal that knows fewer permissions, and a
	// later block adds the rest back. Strip one of those additions to stand in for a
	// database created before the permission existed, boot again on the same migrated
	// schema, and require the repair to have run.
	//
	// `roles` is under FORCE RLS, so the strip must be proven and not assumed: with the
	// tenant context lost, this UPDATE matches zero rows without an error and the check
	// below would pass without the repair ever running.
	setTenant(t, f.admin, f.org)
	holders := 0
	for _, permissions := range builtinRolePermissions {
		if slices.Contains(permissions, permContentPurge) {
			holders++
		}
	}
	if holders == 0 {
		t.Fatal("fixture broken: no built-in role holds content.purge, so there is nothing to strip")
	}
	tag, e := f.admin.Exec(ctx, "UPDATE roles SET permissions=array_remove(permissions,$1) WHERE builtin AND $1=ANY(permissions)", permContentPurge)
	if e != nil {
		t.Fatal(e)
	}
	if int(tag.RowsAffected()) < holders {
		t.Fatalf("the strip reached %d role(s), expected at least %d: the negative control did not happen", tag.RowsAffected(), holders)
	}
	pool, e := OpenDatabase(ctx, f.a.config)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	check(t, "after a second boot on an already-migrated database")
}

func assertBuiltinRoles(t *testing.T, ctx context.Context, tx interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, when string) {
	t.Helper()
	for name, expected := range builtinRolePermissions {
		var stored []string
		if e := tx.QueryRow(ctx, "SELECT permissions FROM roles WHERE name=$1 AND builtin", name).Scan(&stored); e != nil {
			t.Fatalf("%s: built-in role %q is missing from the database: %v", when, name, e)
		}
		want, got := slices.Clone(expected), slices.Clone(stored)
		slices.Sort(want)
		slices.Sort(got)
		if !slices.Equal(want, got) {
			missing, extra := []string{}, []string{}
			for _, p := range want {
				if !slices.Contains(got, p) {
					missing = append(missing, p)
				}
			}
			for _, p := range got {
				if !slices.Contains(want, p) {
					extra = append(extra, p)
				}
			}
			t.Fatalf("%s: built-in role %q has drifted: the database is missing %v and carries %v that the Go catalogue does not", when, name, missing, extra)
		}
	}
}
