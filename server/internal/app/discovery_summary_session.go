package app

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// Credential resolution happened before queuing. Recheck the same live session
// locally, without another quota charge or remote identity refresh.
func revalidateDiscoverySummarySession(ctx context.Context, tx pgx.Tx, session *Session) error {
	err := tx.QueryRow(ctx, `SELECT s.mfa,coalesce(s.login_trusted_until>clock_timestamp(),false)
 FROM sessions s WHERE s.token_hash=$1 AND s.user_id=$2 AND s.organization_id=$3
 AND s.expires_at>clock_timestamp() AND s.identity_expires_at>clock_timestamp()`, session.TokenHash, session.UserID, session.OrganizationID).Scan(&session.MFA, &session.LoginTrusted)
	if errors.Is(err, pgx.ErrNoRows) {
		return apiError{401, "unauthenticated", "Sign in to continue."}
	}
	return err
}
