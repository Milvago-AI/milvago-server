package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type pageMetadataQueries struct {
	sync.Mutex
	queries []pgx.TraceQueryStartData
}

func (*pageMetadataQueries) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (q *pageMetadataQueries) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(data.SQL, "SELECT ") || strings.HasPrefix(data.SQL, "WITH ") {
		q.Lock()
		q.queries = append(q.queries, data)
		q.Unlock()
	}
	return ctx
}

func TestPaginatedMetadataFollowsPageSelection(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	device := "00000000-0000-4000-8000-000000000001"
	for i := 1; i <= 40; i++ {
		id := fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
		cipher, err := f.a.sealIdentity(f.org, "device-name:"+id, "Synthetic pagination host")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.admin.Exec(ctx, `INSERT INTO devices(organization_id,id,credential_hash,hostname,hostname_ciphertext,platform,version,status,collector_health)
		 VALUES($1,$2,$3,$4,$5,'pagination-fixture','test','approved',jsonb_build_object('padding',repeat('x',4096)))`, f.org, id, hash("page-device-"+id), deviceAlias(id), cipher); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_entities(organization_id,device_id,scope,id,kind,sequence) VALUES($1,$2,'host','process/page','process',1)`, f.org, device); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_identifications(organization_id,device_id,scope,entity_id,application_id,signature_id,signature_revision,state,evidence,sequence)
	 SELECT $1,$2,'host','process/page','fixture-page-'||lpad(i::text,4,'0'),'signature-'||i,1,'installed','[]',1 FROM generate_series(1,120) i`, f.org, device); err != nil {
		t.Fatal(err)
	}
	queries := &pageMetadataQueries{}
	config := f.a.db.Config()
	config.ConnConfig.Tracer = queries
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	original := f.a.db
	f.a.db = pool
	t.Cleanup(func() { f.a.db = original; pool.Close() })
	for _, test := range []struct {
		name, path, marker        string
		page, total, maxAggregate int
	}{
		{"applications", "/api/discovery/applications?limit=5&q=fixture-page", "WITH RECURSIVE identification_keys AS", 5, -1, 6},
		{"inventory", "/api/discovery/inventory?limit=5&app=fixture-page&regex=app", "matching_keys AS MATERIALIZED", 5, 120, 5},
		{"encrypted device search", "/api/devices?platform=pagination-fixture&query=Synthetic+pagination&limit=1&offset=1", "SELECT jsonb_build_object('id',d.id", 1, 40, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			queries.Lock()
			queries.queries = nil
			queries.Unlock()
			w := f.call("GET", test.path, nil, "")
			requireHTTP(t, w, 200)
			var page struct {
				Items []json.RawMessage `json:"items"`
				Total int               `json:"total"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || len(page.Items) != test.page || (test.total >= 0 && page.Total != test.total) {
				t.Fatalf("page cardinality: %d/%d (%v)", len(page.Items), page.Total, err)
			}
			queries.Lock()
			captured := append([]pgx.TraceQueryStartData{}, queries.queries...)
			queries.Unlock()
			var selected *pgx.TraceQueryStartData
			for i := range captured {
				if strings.Contains(captured[i].SQL, test.marker) {
					selected = &captured[i]
				}
			}
			if selected == nil {
				t.Fatal("missing paginated metadata query")
			}
			tx, err := tenantTx(ctx, pool, f.org)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err = tx.Exec(ctx, `SET LOCAL jit=off`); err != nil {
				t.Fatal(err)
			}
			var raw json.RawMessage
			if err = tx.QueryRow(ctx, `EXPLAIN (ANALYZE,BUFFERS,VERBOSE,FORMAT JSON) `+selected.SQL, selected.Args...).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var plans []struct{ Plan map[string]any }
			if err = json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 {
				t.Fatal("invalid metadata plan")
			}
			if test.maxAggregate == 0 {
				if plans[0].Plan["Actual Rows"] != float64(test.page) {
					t.Fatalf("device search loaded full metadata outside the page: %v", plans[0].Plan["Actual Rows"])
				}
				return
			}
			found := false
			var inspect func(map[string]any)
			inspect = func(n map[string]any) {
				output, _ := json.Marshal(n["Output"])
				group, _ := json.Marshal(n["Group Key"])
				if n["Node Type"] == "Aggregate" && strings.Contains(string(group), "application_id") && strings.Contains(string(output), "count(*)") || n["Node Type"] == "Aggregate" && strings.Contains(string(group), "family") && strings.Contains(string(output), "max(") {
					found = true
					if rows, _ := n["Actual Rows"].(float64); rows > float64(test.maxAggregate) {
						t.Errorf("detailed aggregate expanded %.0f groups for a page of %d", rows, test.page)
					}
				}
				children, _ := n["Plans"].([]any)
				for _, child := range children {
					inspect(child.(map[string]any))
				}
			}
			inspect(plans[0].Plan)
			if !found {
				t.Fatal("missing measured detailed aggregate")
			}
		})
	}
}
