package app

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type discoveryStorageWrites struct {
	pgx.Tx
	queries []string
}

func (tx *discoveryStorageWrites) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	tx.queries = append(tx.queries, sql)
	return tx.Tx.Exec(ctx, sql, args...)
}

func (tx *discoveryStorageWrites) SendBatch(ctx context.Context, batch *pgx.Batch) pgx.BatchResults {
	for _, query := range batch.QueuedQueries {
		tx.queries = append(tx.queries, query.SQL)
	}
	return tx.Tx.SendBatch(ctx, batch)
}

func TestDiscoveryEmptyStorageFamiliesDoNotWriteOrEraseExistingRows(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	var device string
	if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,kind)
 VALUES($1,$2,'Storage fixture','test','0.7.0','approved','browser') RETURNING id`, f.org, hash(randomToken())).Scan(&device); err != nil {
		t.Fatal(err)
	}
	tx, err := tenantTx(ctx, f.a.db, f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	captured := &discoveryStorageWrites{Tx: tx}
	now := time.Now().Unix()
	raw, err := json.Marshal(map[string]any{
		"version": 1, "scope": "endpoint", "sequence": 7, "observed_at": now,
		"entities": []any{map[string]any{"id": "process/one", "kind": "process"}, map[string]any{"id": "process/two", "kind": "process"}},
		"relations": []any{map[string]any{"from": "process/one", "to": "process/two", "kind": "parent", "source": "host-process"}},
		"coverage": []any{map[string]any{"scope": "endpoint", "adapter": "fixture-empty", "status": "partial", "checked_at": now, "complete": false}},
		"result": map[string]any{"identifications": []any{}, "communications": []any{map[string]any{"entity_id": "process/one", "provider": "openai", "evidence": map[string]any{"fact_id": "fact/one", "source": "host_flow", "observed_at": now, "fields": []string{"remote_host"}}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var report discoveryReport
	if err = json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/discovery/reports", nil)
	if err = f.a.storeDiscoveryReport(r, captured, f.org, device, &report); err != nil {
		t.Fatal(err)
	}
	families := []string{"discovery_relations", "discovery_coverage", "discovery_communications"}
	count := func(table string) int {
		n := 0
		for _, sql := range captured.queries {
			if strings.Contains(sql, "INSERT INTO "+table+"(") {
				n++
			}
		}
		return n
	}
	// Prove that the instrumentation observes actual nonempty writes.
	before := map[string]string{}
	for _, table := range families {
		if count(table) != 1 {
			t.Fatalf("missing positive write control for %s", table)
		}
		var row string
		if err = tx.QueryRow(ctx, "SELECT row_to_json(x)::text FROM "+table+" x WHERE organization_id=$1 AND device_id=$2", f.org, device).Scan(&row); err != nil {
			t.Fatal(err)
		}
		before[table] = row
	}
	captured.queries = nil
	report.Sequence = 100
	report.Relations = report.Relations[:0]
	report.Coverage = report.Coverage[:0]
	report.Result.Communications = report.Result.Communications[:0]
	if err = f.a.storeDiscoveryReport(r, captured, f.org, device, &report); err != nil {
		t.Fatal(err)
	}
	if count("discovery_entities") != 1 {
		t.Fatal("the nonempty entity write was not exercised")
	}
	for _, table := range families {
		if count(table) != 0 {
			t.Errorf("empty family sent a write: %s", table)
		}
		var rows int
		var row string
		if err = tx.QueryRow(ctx, "SELECT count(*),min(row_to_json(x)::text) FROM "+table+" x WHERE organization_id=$1 AND device_id=$2", f.org, device).Scan(&rows, &row); err != nil || rows != 1 || row != before[table] {
			t.Fatalf("empty family changed existing rows in %s: count=%d err=%v", table, rows, err)
		}
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	// A later FK failure must be reported before the caller can commit any write.
	failing, err := tenantTx(ctx, f.a.db, f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer failing.Rollback(ctx)
	report.Relations = report.Relations[:1]
	report.Relations[0].To = "process/missing"
	if err = f.a.storeDiscoveryReport(r, failing, f.org, device, &report); err == nil {
		t.Fatal("later write failure was hidden")
	}
	if err = failing.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var retained int
	if err = f.admin.QueryRow(ctx, `SELECT count(*) FROM discovery_entities WHERE organization_id=$1 AND device_id=$2`, f.org, device).Scan(&retained); err != nil || retained != 0 {
		t.Fatalf("partial batch escaped rollback: rows=%d err=%v", retained, err)
	}
}
