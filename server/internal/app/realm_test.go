package app

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRealmNames(t *testing.T) {
	if got := childRealm("0f8fad5b-d9cb-469f-a165-70867728950e"); got != "org-0f8fad5bd9cb469fa16570867728950e" {
		t.Fatal("child realm name", got)
	}
	if got, e := realmIssuer("https://id.example.test/realms/milvago", "org-1"); e != nil || got != "https://id.example.test/realms/org-1" {
		t.Fatal("realm issuer", got, e)
	}
	// A realm name never changes the issuer path beyond its own segment.
	for _, bad := range []string{"", "org/../master", "org?x", "org#x", "org%2Fmaster"} {
		if _, e := realmIssuer("https://id.example.test/realms/milvago", bad); e == nil {
			t.Fatal("unsafe realm accepted", bad)
		}
	}
	if _, e := realmIssuer("https://id.example.test", "org-1"); e == nil {
		t.Fatal("an issuer without a realm was rewritten")
	}
	a := &App{config: Config{Issuer: "https://id.example.test/realms/milvago"}}
	if a.rootRealm() != "milvago" || a.realmName("") != "milvago" || a.realmName("org-1") != "org-1" {
		t.Fatal("root realm", a.rootRealm())
	}
}

// A sub-organization's directory test must not probe the platform's own network.
func TestTenantDirectoryTarget(t *testing.T) {
	for _, ok := range []string{"ldaps://ldap.example.test", "ldap://dc1.corp.example.test:389", "ldaps://ldap.example.test:3269", "ldaps://203.0.113.10:636", "ldaps://10.20.30.40", "ldaps://[2001:db8::1]:636"} {
		if e := tenantDirectoryTarget(ok); e != nil {
			t.Fatal("a directory server was refused", ok, e)
		}
	}
	for _, refused := range []string{"ldaps://database:5432", "ldaps://ldap.example.test:5432", "ldaps://identity", "ldaps://localhost", "ldaps://dc.localhost",
		"ldaps://127.0.0.1", "ldaps://[::1]", "ldaps://[::ffff:127.0.0.1]", "ldaps://0.0.0.0", "ldaps://169.254.169.254", "ldaps://[fe80::1]", "ldaps://224.0.0.1"} {
		if e := tenantDirectoryTarget(refused); e == nil {
			t.Fatal("a sub-organization may point its directory at", refused)
		}
	}
}

// testOrganizationRealms: the invitation's direct link ends at the first sign-in or when
// its link expires, and a failure to end it refuses the sign-in; then the Enterprise
// realm scenarios.
func (f *identityScenarioFixture) testOrganizationRealms(t *testing.T) {
	a, p, db, ctx := f.a, f.identity, f.admin, context.Background()
	p.mu.Lock()
	p.roles[ssoPendingRole] = true
	p.userRoles["pending-subject"] = map[string]bool{ssoPendingRole: true}
	p.userRoles["pending-live"] = map[string]bool{ssoPendingRole: true}
	p.mu.Unlock()
	var expired, live string
	if e := db.QueryRow(ctx, `INSERT INTO users(subject,email,display_name,pending_invitation_until) VALUES('pending-subject','pending@example.test','Synthetic pending',now()-interval '1 minute') RETURNING id`).Scan(&expired); e != nil {
		t.Fatal(e)
	}
	if e := db.QueryRow(ctx, `INSERT INTO users(subject,email,display_name,pending_invitation_until) VALUES('pending-live','live@example.test','Synthetic live',now()+interval '1 hour') RETURNING id`).Scan(&live); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _, _ = db.Exec(ctx, `DELETE FROM users WHERE id IN ($1,$2)`, expired, live) })
	a.expirePendingInvitations(ctx)
	p.mu.Lock()
	expiredRole, liveRole := p.userRoles["pending-subject"][ssoPendingRole], p.userRoles["pending-live"][ssoPendingRole]
	p.mu.Unlock()
	var cleared bool
	if e := db.QueryRow(ctx, `SELECT pending_invitation_until IS NULL FROM users WHERE id=$1`, expired).Scan(&cleared); e != nil || !cleared || expiredRole || !liveRole {
		t.Fatalf("expiry: cleared=%v expiredRole=%v liveRole=%v (%v)", cleared, expiredRole, liveRole, e)
	}
	// At the first sign-in the role must go, or the sign-in is refused.
	p.mu.Lock()
	p.roleFail = true
	p.mu.Unlock()
	tx, e := a.db.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	e = a.endPendingInvitation(ctx, tx, "", live, "pending-live")
	tx.Rollback(ctx)
	p.mu.Lock()
	p.roleFail = false
	p.mu.Unlock()
	if e == nil || !strings.Contains(e.Error(), "complete the invitation") {
		t.Fatal("a sign-in went on although the invitation role could not be removed", e)
	}
	if tx, e = a.db.Begin(ctx); e != nil {
		t.Fatal(e)
	}
	if e = a.endPendingInvitation(ctx, tx, "", live, "pending-live"); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	p.mu.Lock()
	liveRole = p.userRoles["pending-live"][ssoPendingRole]
	p.mu.Unlock()
	if liveRole {
		t.Fatal("the first sign-in left the invitation role in place")
	}
	f.testEnterpriseRealms(t)
}

// tenantExec runs one statement in an organization's tenant context, which the tables
// under FORCE RLS require even of the schema owner.
func tenantExec(ctx context.Context, db *pgxpool.Pool, org, statement string, args ...any) error {
	tx, e := tenantTx(ctx, db, org)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, statement, args...); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
