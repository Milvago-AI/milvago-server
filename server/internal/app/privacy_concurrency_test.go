package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// lockHolder is a separate connection that takes a lock the product will meet, so a
// real request can be stopped at an exact point while holding what it holds there.
func lockHolder(t *testing.T) *pgx.Conn {
	t.Helper()
	c, e := pgx.Connect(context.Background(), os.Getenv("TEST_MIGRATION_DATABASE_URL"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close(context.Background()) })
	if _, e := c.Exec(context.Background(), "BEGIN"); e != nil {
		t.Fatal(e)
	}
	return c
}

// awaitLockWait proves a real PostgreSQL wait on the given lock type; elapsed time
// alone is no evidence.
func awaitLockWait(t *testing.T, f *observabilityFixture, locktype string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		if e := f.admin.QueryRow(context.Background(), "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype=$1 AND NOT granted)", locktype).Scan(&waiting); e != nil {
			t.Fatal(e)
		}
		if waiting {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("no request waited on a %s lock", locktype)
}

func awaitPrivacyRequest(t *testing.T, done <-chan *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	select {
	case w := <-done:
		return w
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent request did not finish")
		return nil
	}
}

// A session withdrawn while its request is in flight -- authenticated, not yet at the
// fresh-MFA check -- commits nothing.
func TestPrivacyConcurrentSessionWithdrawal(t *testing.T) {
	for _, operation := range []string{"reveal", "rotate"} {
		t.Run(operation, func(t *testing.T) { testPrivacyConcurrentSessionWithdrawal(t, operation) })
	}
}

// A role change waits for a request that holds the barrier -- a real one, stopped
// between its authorization and its commit -- and applies to the next request.
func TestPrivacyConcurrentRoleWithdrawal(t *testing.T) {
	f, subject, _ := privacyFixture(t)
	ctx := context.Background()
	role := "synthetic-concurrent-reader"
	requireHTTP(t, f.call("POST", "/api/roles", map[string]any{"name": role, "permissions": []string{"events.read", "identity.reveal"}}, f.csrf), 201)
	var user string
	if e := f.admin.QueryRow(ctx, "INSERT INTO users(subject,email,display_name) VALUES('synthetic-concurrent-user','concurrent@example.test','Synthetic concurrent user') RETURNING id").Scan(&user); e != nil {
		t.Fatal(e)
	}
	if _, e := f.admin.Exec(ctx, "INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,$3)", f.org, user, role); e != nil {
		t.Fatal(e)
	}
	token, csrf := randomToken(), randomToken()
	cookie := &http.Cookie{Name: cookieName("session"), Value: token}
	if _, e := f.admin.Exec(ctx, `INSERT INTO sessions(token_hash,user_id,organization_id,csrf_token,encrypted_tokens,mfa,mfa_verified_at,expires_at,identity_expires_at) VALUES($1,$2,$3,$4,$5,true,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '1 hour')`, hash(token), user, f.org, csrf, []byte("synthetic-session")); e != nil {
		t.Fatal(e)
	}
	path := "/api/subjects/" + subject + "/reveal"
	// The reveal is stopped at its audit row, after authorization, holding the barrier.
	holder := lockHolder(t)
	if _, e := holder.Exec(ctx, "LOCK TABLE audit IN SHARE ROW EXCLUSIVE MODE"); e != nil {
		t.Fatal(e)
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- sessionCall(f, cookie, csrf, "POST", path, map[string]string{"reason": "Synthetic concurrency verification"})
	}()
	awaitLockWait(t, f, "relation")
	revoked := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		revoked <- f.call("PUT", "/api/roles/"+role, map[string]any{"permissions": []string{"events.read"}}, f.csrf)
	}()
	awaitLockWait(t, f, "advisory")
	if _, e := holder.Exec(ctx, "ROLLBACK"); e != nil {
		t.Fatal(e)
	}
	requireHTTP(t, awaitPrivacyRequest(t, done), 200)
	var n int
	if e := f.admin.QueryRow(ctx, "SELECT count(*) FROM audit WHERE action='identity.reveal' AND actor=$1", user).Scan(&n); e != nil || n != 1 {
		t.Fatal("the reveal authorized before the change did not commit", n, e)
	}
	requireHTTP(t, awaitPrivacyRequest(t, revoked), 200)
	requireHTTP(t, sessionCall(f, cookie, csrf, "POST", path, map[string]string{"reason": "Synthetic concurrency verification"}), 403)
}

func TestPrivacyAPIKeyLockOrder(t *testing.T) {
	for _, withdrawal := range []string{"revoke", "expire"} {
		t.Run(withdrawal, func(t *testing.T) { testPrivacyAPIKeyLockOrder(t, withdrawal) })
	}
}

func testPrivacyConcurrentSessionWithdrawal(t *testing.T, operation string) {
	f, subject, _ := privacyFixture(t)
	ctx := context.Background()
	path := "/api/subjects/" + subject + "/reveal"
	if operation == "rotate" {
		path = "/api/privacy/alias-key/rotate"
	}
	// The organization's barrier held exclusively: the request authenticates, then
	// waits on the barrier before its authority and its fresh-MFA check.
	holder := lockHolder(t)
	if _, e := holder.Exec(ctx, "SELECT pg_advisory_xact_lock("+barrierKeySQL+")", f.org); e != nil {
		t.Fatal(e)
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- f.call("POST", path, map[string]string{"reason": "Synthetic concurrency verification"}, f.csrf)
	}()
	awaitLockWait(t, f, "advisory")
	// DELETE is the same durable session withdrawal performed by logout.
	tag, e := f.admin.Exec(ctx, "DELETE FROM sessions WHERE token_hash=$1", hash(f.owner.Value))
	if e != nil || tag.RowsAffected() != 1 {
		t.Fatal("session withdrawal failed", e)
	}
	if _, e := holder.Exec(ctx, "ROLLBACK"); e != nil {
		t.Fatal(e)
	}
	w := awaitPrivacyRequest(t, done)
	requireHTTP(t, w, 403)
	var n int
	if e = f.admin.QueryRow(ctx, "SELECT count(*) FROM audit WHERE action IN ('identity.reveal','privacy.alias_key.rotated')").Scan(&n); e != nil || n != 0 {
		t.Fatal("withdrawn request committed", n, e)
	}
}

func testPrivacyAPIKeyLockOrder(t *testing.T, withdrawal string) {
	p := newProjectionFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, e := tenantTx(ctx, p.a.db, p.org)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(context.Background())
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock_shared("+barrierKeySQL+")", p.org); e != nil {
		t.Fatal(e)
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- p.as("key", "PUT", "/api/roles/synthetic-lock-order", map[string]any{"permissions": []string{"events.read"}})
	}()
	waiting := false
	for ctx.Err() == nil {
		if e := p.admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted)").Scan(&waiting); e != nil {
			t.Fatal(e)
		}
		if waiting {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !waiting {
		t.Fatal("key mutation did not reach permission lock")
	}
	// A completed revocation must not deadlock behind a credential row acquired
	// before that lock. This reproduces the former opposite lock order.
	sql := "UPDATE api_keys SET revoked_at=clock_timestamp() WHERE secret_hash=$1"
	if withdrawal == "expire" {
		sql = "UPDATE api_keys SET expires_at=clock_timestamp() WHERE secret_hash=$1"
	}
	tag, e := tx.Exec(ctx, sql, hash(p.key))
	if e != nil || tag.RowsAffected() != 1 {
		t.Fatal("key revocation blocked or absent", e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	requireHTTP(t, awaitPrivacyRequest(t, done), 401)

}
