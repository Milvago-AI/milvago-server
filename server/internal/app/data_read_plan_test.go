package app

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type dataReadTraceKey struct{}
type dataReadTraceEntry struct {
	sql     string
	args    []any
	start   time.Time
	elapsed time.Duration
}
type dataReadTrace struct {
	sync.Mutex
	queries []*dataReadTraceEntry
}

func (trace *dataReadTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if !strings.Contains(data.SQL, "shadow_events") || strings.HasPrefix(data.SQL, "EXPLAIN") {
		return ctx
	}
	entry := &dataReadTraceEntry{sql: data.SQL, args: append([]any{}, data.Args...), start: time.Now()}
	return context.WithValue(ctx, dataReadTraceKey{}, entry)
}
func (trace *dataReadTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryEndData) {
	entry, _ := ctx.Value(dataReadTraceKey{}).(*dataReadTraceEntry)
	if entry == nil {
		return
	}
	entry.elapsed = time.Since(entry.start)
	trace.Lock()
	trace.queries = append(trace.queries, entry)
	trace.Unlock()
}
func traceDataReadFixture(t *testing.T, f *observabilityFixture) (*dataReadTrace, func()) {
	t.Helper()
	original := f.a.db
	config := original.Config()
	trace := &dataReadTrace{}
	config.ConnConfig.Tracer = trace
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	f.a.db = pool
	return trace, func() { f.a.db = original; pool.Close() }
}
func (trace *dataReadTrace) explainSlow(t *testing.T, f *observabilityFixture) {
	t.Helper()
	trace.Lock()
	queries := append([]*dataReadTraceEntry{}, trace.queries...)
	trace.Unlock()
	for _, entry := range queries {
		t.Logf("event SQL timing: %.1fms", float64(entry.elapsed.Microseconds())/1000)
		if entry.elapsed < time.Second {
			continue
		}
		tx, err := tenantTx(context.Background(), f.a.db, f.org)
		if err != nil {
			t.Fatal(err)
		}
		var raw []byte
		err = tx.QueryRow(context.Background(), `EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) `+entry.sql, entry.args...).Scan(&raw)
		tx.Rollback(context.Background())
		if err != nil {
			t.Logf("slow read plan unavailable: %v", err)
			continue
		}
		var plan []map[string]any
		if json.Unmarshal(raw, &plan) != nil || len(plan) != 1 {
			t.Fatal("missing read plan")
		}
		t.Logf("event SQL execution: %vms JIT=%v", plan[0]["Execution Time"], plan[0]["JIT"])
		var visit func(map[string]any)
		visit = func(node map[string]any) {
			t.Logf("event plan: type=%v relation=%v index=%v rows=%v loops=%v width=%v hit=%v read=%v temp=%v filter_removed=%v", node["Node Type"], node["Relation Name"], node["Index Name"], node["Actual Rows"], node["Actual Loops"], node["Plan Width"], node["Shared Hit Blocks"], node["Shared Read Blocks"], node["Temp Written Blocks"], node["Rows Removed by Filter"])
			for _, v := range node["Plans"].([]any) {
				visit(v.(map[string]any))
			}
		}
		// Leaves omit Plans; normalize them before the recursive walk.
		var normalize func(map[string]any)
		normalize = func(node map[string]any) {
			if node["Plans"] == nil {
				node["Plans"] = []any{}
			}
			for _, v := range node["Plans"].([]any) {
				normalize(v.(map[string]any))
			}
		}
		node := plan[0]["Plan"].(map[string]any)
		normalize(node)
		visit(node)
	}
}
