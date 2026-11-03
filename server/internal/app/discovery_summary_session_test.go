package app

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

type discoverySummarySessionRow struct{ err error }

func (row discoverySummarySessionRow) Scan(dest ...any) error {
	if row.err != nil {
		return row.err
	}
	*dest[0].(*bool), *dest[1].(*bool) = false, false
	return nil
}

type discoverySummarySessionTx struct {
	pgx.Tx
	err  error
	sql  string
	args []any
}

func (tx *discoverySummarySessionTx) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	tx.sql, tx.args = sql, args
	return discoverySummarySessionRow{err: tx.err}
}

func TestDiscoverySummarySessionRevalidationUsesLiveCredentialAndFlags(t *testing.T) {
	databaseError := errors.New("synthetic session database failure")
	for _, failure := range []error{nil, pgx.ErrNoRows, databaseError} {
		tx := &discoverySummarySessionTx{err: failure}
		session := &Session{TokenHash: bytes.Repeat([]byte{7}, 32), UserID: summaryTestOrg(1), OrganizationID: summaryTestOrg(2), MFA: true, LoginTrusted: true}
		err := revalidateDiscoverySummarySession(context.Background(), tx, session)
		if failure == nil && (err != nil || session.MFA || session.LoginTrusted) {
			t.Fatal("stale sign-in flags were retained", err)
		}
		if errors.Is(failure, pgx.ErrNoRows) {
			var missing apiError
			if !errors.As(err, &missing) || missing.status != 401 || missing.code != "unauthenticated" {
				t.Fatal("dead session was accepted", err)
			}
		} else if failure != nil && !errors.Is(err, failure) {
			t.Fatal("database failure was converted to credential revocation", err)
		}
		if len(tx.args) != 3 || !bytes.Equal(tx.args[0].([]byte), session.TokenHash) || tx.args[1] != session.UserID || tx.args[2] != session.OrganizationID {
			t.Fatal("session identity was not pinned")
		}
		for _, clause := range []string{"s.token_hash=$1", "s.user_id=$2", "s.organization_id=$3", "s.expires_at>clock_timestamp()", "s.identity_expires_at>clock_timestamp()"} {
			if !strings.Contains(tx.sql, clause) {
				t.Fatal("session freshness predicate missing", clause)
			}
		}
		if strings.Contains(tx.sql, "FOR SHARE") || strings.Contains(tx.sql, "FOR UPDATE") {
			t.Fatal("summary introduced a long session-row lock")
		}
	}
}
