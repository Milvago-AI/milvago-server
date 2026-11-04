package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestDataReadRegisteredConsoleBudgets(t *testing.T) {
	f := newObservabilityFixture(t)
	manifest := []string{}
	for _, route := range f.a.routes {
		// registeredRoute records the exact server route, including generated scopes.
		pattern := route.Pattern
		method, path, ok := strings.Cut(pattern, " ")
		if !ok || method != "GET" || !strings.HasPrefix(path, "/api/") {
			continue
		}
		r, cancel := dataReadRequest(httptest.NewRequest(method, path, nil))
		deadline, bounded := r.Context().Deadline()
		cancel()
		if !bounded || time.Until(deadline) > dataDownloadBudget {
			t.Fatalf("unbounded registered data read: %s", pattern)
		}
		manifest = append(manifest, pattern)
	}
	if len(manifest) < 50 {
		t.Fatal("runtime data-read inventory is incomplete")
	}
	sort.Strings(manifest)
	raw, _ := json.Marshal(map[string]any{"edition": Edition, "routes": manifest})
	t.Logf("registered_data_reads=%s", raw)
}

func TestDataReadHandlerCancelsSQLAndReleasesTransaction(t *testing.T) {
	f := newObservabilityFixture(t)
	entered := false
	f.a.console("GET /api/read-budget-test", permOverviewRead, func(w http.ResponseWriter, r *http.Request, tx pgx.Tx, _ *Session) error {
		entered = true
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > dataReadBudget {
			t.Error("handler has no read deadline")
		}
		var ignored any
		return tx.QueryRow(r.Context(), `SELECT pg_sleep(2)`).Scan(&ignored)
	})
	// Warm the session/license path before measuring cancellation inside SQL.
	requireHTTP(t, f.callAs("GET", "/api/settings", nil, f.owner, f.csrf, ""), 200)
	parent, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stop()
	r := httptest.NewRequest("GET", "/api/read-budget-test", nil).WithContext(parent)
	r.AddCookie(f.owner)
	w := httptest.NewRecorder()
	start := time.Now()
	f.a.Handler().ServeHTTP(w, r)
	requireHTTP(t, w, 504)
	if !entered || time.Since(start) > time.Second {
		t.Fatal("read SQL did not respect the shorter caller deadline")
	}
	// pgxpool destroys a connection closed by cancellation asynchronously.
	// Allow that cleanup to complete, but fail a connection actually retained.
	cleanupDeadline := time.Now().Add(time.Second)
	for f.a.db.Stat().AcquiredConns() != 0 && time.Now().Before(cleanupDeadline) {
		time.Sleep(time.Millisecond)
	}
	if f.a.db.Stat().AcquiredConns() != 0 {
		t.Fatal("canceled read retained a pool connection after cleanup")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := f.a.db.Ping(ctx); err != nil {
		t.Fatal("canceled read retained a broken transaction or connection", err)
	}
}
