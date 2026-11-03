package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Revoke the synthetic cookie immediately before its local post-queue check.
// This uses the existing test tracer rather than a production injection hook.
type summarySessionRevocationTrace struct {
	once    sync.Once
	revoke  func(context.Context) error
	failure chan error
}

func (trace *summarySessionRevocationTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(data.SQL, "SELECT s.mfa,coalesce(s.login_trusted_until>clock_timestamp(),false)") && trace.revoke != nil {
		trace.once.Do(func() {
			if err := trace.revoke(ctx); err != nil {
				trace.failure <- err
			}
		})
	}
	return ctx
}
func (*summarySessionRevocationTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {
}

func TestDiscoverySummaryAdmissionEndsBeforeNormalErrorOverflowAndFlushIO(t *testing.T) {
	for _, mode := range []string{"normal", "authorization_error", "credential_error", "overflow", "flush"} {
		t.Run(mode, func(t *testing.T) {
			trace := &summarySessionRevocationTrace{failure: make(chan error, 1)}
			f := newObservabilityFixtureWithTracer(t, trace)
			if mode == "authorization_error" {
				if _, err := f.admin.Exec(context.Background(), `DELETE FROM memberships WHERE organization_id=$1 AND user_id=$2`, f.org, f.user); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "credential_error" {
				trace.revoke = func(ctx context.Context) error {
					_, err := f.admin.Exec(ctx, `DELETE FROM sessions WHERE token_hash=$1`, hash(f.owner.Value))
					return err
				}
			}
			writer := &discoveryDeniedBlockingWriter{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), proceed: make(chan struct{})}
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(writer.proceed) }) }
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			done := make(chan struct{})
			failures := make(chan error, 1)
			t.Cleanup(func() {
				release()
				cancel()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("summary I/O worker did not stop")
				}
			})
			callback := func(w http.ResponseWriter, r *http.Request, _ pgx.Tx, _ *Session) error {
				if mode == "overflow" {
					_, err := w.Write(make([]byte, heldLimit+1))
					return err
				}
				reply(w, 200, map[string]bool{"ok": true})
				if mode == "flush" {
					if err := http.NewResponseController(w).Flush(); err != nil {
						return err
					}
					if tx, err := tenantTx(r.Context(), f.a.db, f.org); !errors.Is(err, context.Canceled) {
						if tx != nil {
							tx.Rollback(r.Context())
						}
						failures <- errors.New("response reopened a closed request transaction")
					}
				}
				return nil
			}
			handler := discoverySummaryAdmissionHandler(&f.a.discoverySummaries, f.a.handler(permDiscoveryRead, callback, accessBoth))
			request := httptest.NewRequest("GET", "/api/discovery/applications", nil).WithContext(ctx)
			request.AddCookie(f.owner)
			go func() { defer close(done); handler(writer, request) }()
			select {
			case <-writer.entered:
			case <-done:
				t.Fatal("summary ended before actual client I/O")
			case <-time.After(5 * time.Second):
				t.Fatal("summary did not reach client I/O")
			}
			if _, entries, _ := summaryTestRefs(&f.a.discoverySummaries, f.org); entries != 0 || f.a.db.Stat().AcquiredConns() != 0 {
				t.Fatal("response retained transaction or admission during I/O")
			}
			probe, err := f.admin.Begin(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = probe.Exec(context.Background(), `SET LOCAL lock_timeout='500ms'`); err == nil {
				_, err = probe.Exec(context.Background(), `SELECT pg_advisory_xact_lock(`+barrierKeySQL+`)`, f.org)
			}
			rollbackErr := probe.Rollback(context.Background())
			if err != nil || rollbackErr != nil {
				t.Fatal("response retained privacy locks", err, rollbackErr)
			}
			release()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("released response did not finish")
			}
			want := 200
			if mode == "authorization_error" {
				want = 403
			} else if mode == "credential_error" {
				want = 401
			}
			requireHTTP(t, writer.ResponseRecorder, want)
			select {
			case err := <-trace.failure:
				t.Fatal("test cookie revocation did not commit", err)
			default:
			}
			select {
			case err := <-failures:
				t.Fatal(err)
			default:
			}
		})
	}
}

func TestDiscoverySummaryAdmissionPanicEndsTransactionBeforeCleanup(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	response := httptest.NewRecorder()
	panicked := false
	func() {
		defer func() { panicked = recover() != nil }()
		callback := func(w http.ResponseWriter, _ *http.Request, _ pgx.Tx, _ *Session) error {
			_, _ = w.Write([]byte("synthetic buffered partial"))
			panic("synthetic summary panic")
		}
		handler := discoverySummaryAdmissionHandler(&f.a.discoverySummaries, f.a.handler(permDiscoveryRead, callback, accessBoth))
		request := httptest.NewRequest("GET", "/api/discovery/applications", nil).WithContext(ctx)
		request.AddCookie(f.owner)
		handler(response, request)
	}()
	if _, entries, _ := summaryTestRefs(&f.a.discoverySummaries, f.org); !panicked || entries != 0 || f.a.db.Stat().AcquiredConns() != 0 || response.Body.Len() != 0 {
		t.Fatal("panic retained a permit/transaction or emitted partial data")
	}
}
