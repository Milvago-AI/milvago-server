package app

import (
	"context"
	"strings"
	"testing"
	"time"
)

func (f *identityScenarioFixture) testFailedDirectInvitationKeepsRecoverableLease(t *testing.T) {
	t.Helper()
	ctx, p := context.Background(), f.identity
	const email = "failed-direct-lease@example.test"
	p.mu.Lock()
	p.mailsSucceed = false
	p.mu.Unlock()
	w := f.owner("POST", "/api/members/invitations", map[string]string{"email": email, "role": "viewer"})
	requireHTTP(t, w, 502)
	p.mu.Lock()
	var subject string
	for id, u := range p.users {
		if strings.EqualFold(u.Email, email) {
			subject = id
		}
	}
	pending := p.userRoles[subject][ssoPendingRole]
	p.mailsSucceed = true
	p.mu.Unlock()
	if subject == "" || !pending {
		t.Fatal("fixture did not reach role grant before mail failure")
	}
	var user string
	var original time.Time
	if e := f.admin.QueryRow(ctx, `SELECT id,pending_invitation_until FROM users WHERE subject=$1`, subject).Scan(&user, &original); e != nil {
		t.Fatal("mail failure lost the durable lease", e)
	}
	var memberships int
	if e := f.admin.QueryRow(ctx, `SELECT count(*) FROM memberships WHERE user_id=$1`, user).Scan(&memberships); e != nil || memberships != 0 {
		t.Fatal("failed invitation granted membership", memberships, e)
	}
	requireHTTP(t, f.owner("POST", "/api/members/invitations", map[string]string{"email": email, "role": "viewer"}), 201)
	var retried time.Time
	if e := f.admin.QueryRow(ctx, `SELECT pending_invitation_until FROM users WHERE id=$1`, user).Scan(&retried); e != nil || !retried.Equal(original) {
		t.Fatal("retry changed the original lease", retried, original, e)
	}
	if _, e := f.admin.Exec(ctx, `UPDATE users SET pending_invitation_until=clock_timestamp()-interval '1 second' WHERE id=$1`, user); e != nil {
		t.Fatal(e)
	}
	f.a.expirePendingInvitations(ctx)
	p.mu.Lock()
	pending = p.userRoles[subject][ssoPendingRole]
	p.mu.Unlock()
	var cleared bool
	if e := f.admin.QueryRow(ctx, `SELECT pending_invitation_until IS NULL FROM users WHERE id=$1`, user).Scan(&cleared); e != nil || !cleared || pending {
		t.Fatal("expiry did not recover the failed invitation", cleared, pending, e)
	}
}
