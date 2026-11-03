package app

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type discoveryPaginationQueries struct {
	sync.Mutex
	queries []pgx.TraceQueryStartData
}

func (q *discoveryPaginationQueries) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if (strings.HasPrefix(data.SQL, "SELECT ") || strings.HasPrefix(data.SQL, "WITH ")) && strings.Contains(data.SQL, "discovery_") && strings.Contains(data.SQL, "ORDER BY") {
		q.Lock()
		q.queries = append(q.queries, data)
		q.Unlock()
	}
	return ctx
}
func (*discoveryPaginationQueries) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestDiscoveryPaginationPlansDoNotSortDisplayUUIDText(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	queries := &discoveryPaginationQueries{}
	uuidDisplayCast := regexp.MustCompile(`\b(?:device_id|id)\)*::text\b`)
	config := f.a.db.Config()
	config.MaxConns = 1
	config.ConnConfig.Tracer = queries
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	original := f.a.db
	f.a.db = pool
	t.Cleanup(func() { f.a.db = original; pool.Close() })
	for _, route := range []string{
		"/api/discovery/applications/openclaw/instances?limit=50",
		"/api/discovery/applications/openclaw/locations?limit=50",
		"/api/discovery/events?limit=50", "/api/discovery/environments?limit=50",
		"/api/discovery/coverage?limit=50", "/api/discovery/runs?limit=50",
	} {
		queries.Lock()
		queries.queries = nil
		queries.Unlock()
		requireHTTP(t, f.call("GET", route, nil, ""), 200)
		queries.Lock()
		captured := append([]pgx.TraceQueryStartData(nil), queries.queries...)
		queries.Unlock()
		if len(captured) == 0 {
			t.Fatalf("no paginated query observed for %s", route)
		}
		tx, err := tenantTx(ctx, pool, f.org)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		for _, query := range captured {
			var raw json.RawMessage
			if err := tx.QueryRow(ctx, "EXPLAIN (FORMAT JSON, COSTS OFF) "+query.SQL, query.Args...).Scan(&raw); err != nil {
				tx.Rollback(ctx)
				t.Fatal(err)
			}
			var plan any
			if json.Unmarshal(raw, &plan) != nil {
				t.Fatal("invalid PostgreSQL plan")
			}
			var inspect func(any)
			inspect = func(value any) {
				switch node := value.(type) {
				case []any:
					for _, child := range node {
						inspect(child)
					}
				case map[string]any:
					for key, child := range node {
						if key == "Sort Key" || key == "Presorted Key" {
							encoded, _ := json.Marshal(child)
							if uuidDisplayCast.Match(encoded) {
								t.Errorf("%s sorts display text instead of the indexed UUID: %s", route, encoded)
							}
						}
						inspect(child)
					}
				}
			}
			inspect(plan)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	}
}
