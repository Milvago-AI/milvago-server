package app

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Commit a recoverable lease before changing the external identity role. This
// row has no membership; failure of email or the caller's transaction cannot
// roll it back and leave an untracked direct sign-in exemption.
func (a *App) preparePendingInvitation(ctx context.Context, admin *identityAdmin, body inviteRequest, realm, subject string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var user string
	var until time.Time
	e := a.db.QueryRow(ctx, `INSERT INTO users(subject,email,display_name,identity_type,language,realm,username,pending_invitation_until) VALUES($1,$2,'','local',$3,$4,$2,clock_timestamp()+interval '24 hours') ON CONFLICT(subject) DO NOTHING RETURNING id,pending_invitation_until`, subject, body.Email, body.Language, realm).Scan(&user, &until)
	if errors.Is(e, pgx.ErrNoRows) {
		// An account already used or prepared must not receive a new exemption.
		return false, nil
	}
	if e != nil {
		return false, e
	}
	tx, e := a.db.Begin(ctx)
	if e != nil {
		return false, e
	}
	defer tx.Rollback(ctx)
	var eligible bool
	if e = tx.QueryRow(ctx, `SELECT COALESCE(pending_invitation_until=$4 AND pending_invitation_until>clock_timestamp(),false) FROM users WHERE id=$1 AND realm=$2 AND subject=$3 FOR UPDATE`, user, realm, subject, until).Scan(&eligible); e != nil {
		return false, e
	}
	if !eligible {
		return false, nil
	}
	// Expiration and first-login cleanup take the same row lock. A completed
	// cleanup prevents this grant; a later cleanup always sees the durable lease.
	if e = markPendingInvitation(ctx, admin, subject); e != nil {
		return false, e
	}
	if e = tx.Commit(ctx); e != nil {
		return false, e
	}
	return true, nil
}

func (a *App) expirePendingInvitation(ctx context.Context, user, realm, subject string) error {
	tx, e := a.db.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var due bool
	e = tx.QueryRow(ctx, `SELECT COALESCE(pending_invitation_until<clock_timestamp(),false) FROM users WHERE id=$1 AND realm=$2 AND subject=$3 FOR UPDATE`, user, realm, subject).Scan(&due)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	if !due {
		return nil
	}
	if e = a.clearInvitationRole(ctx, realm, subject); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE users SET pending_invitation_until=NULL WHERE id=$1`, user); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
