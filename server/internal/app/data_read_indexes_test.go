package app

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strconv"
	"testing"
)

func TestDataReadIndexMigrationContract(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	tx, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SET LOCAL lock_timeout='150ms'; SET LOCAL statement_timeout='5s'`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = initializeDataReadIndexes(ctx, tx); err != nil {
			t.Fatal(err)
		}
	}
	var lock, statement string
	if err = tx.QueryRow(ctx, `SELECT current_setting('lock_timeout'),current_setting('statement_timeout')`).Scan(&lock, &statement); err != nil {
		t.Fatal(err)
	}
	if lock != "150ms" || statement != "5s" {
		t.Fatalf("operator limits changed: %s / %s", lock, statement)
	}
	if _, err = tx.Exec(ctx, `DROP INDEX shadow_events_presence_inventory; CREATE INDEX shadow_events_presence_inventory ON shadow_events(organization_id)`); err != nil {
		t.Fatal(err)
	}
	if err = initializeDataReadIndexes(ctx, tx); err == nil {
		t.Fatal("incompatible index silently accepted")
	}
}

type readPlan struct {
	Type     string     `json:"Node Type"`
	Relation string     `json:"Relation Name"`
	Index    string     `json:"Index Name"`
	Rows     float64    `json:"Actual Rows"`
	Loops    float64    `json:"Actual Loops"`
	Hit      int        `json:"Shared Hit Blocks"`
	Read     int        `json:"Shared Read Blocks"`
	Heap     int        `json:"Heap Fetches"`
	Children []readPlan `json:"Plans"`
}

func TestDataReadPresenceIndexBudget(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	rows := 100000
	if raw := os.Getenv("MILVAGO_PERFORMANCE_ROWS"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 100000 || value > 2000000 {
			t.Fatal("performance fixture rows must be 100000..2000000")
		}
		rows = value
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO devices(organization_id,id,credential_hash,hostname,platform,version,status)
	 SELECT $1,md5('presence-device-'||n)::uuid,decode(md5('presence-credential-'||n)||md5('presence-credential-'||n),'hex'),'Synthetic host '||n,'test','test','approved' FROM generate_series(1,10000)n`, f.org); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO shadow_events(organization_id,device_id,id,occurred_at,kind,provider,tool,source,action,policy_revision,characters,labels,sensitivity,detector,user_key)
	 SELECT $1,md5('presence-device-'||((n-1)%10000+1))::uuid,md5('presence-event-'||n)::uuid,now()-n*interval '1 second','navigation',
	 'service-'||((n/16)%40)||'.example.invalid','synthetic','browser',CASE WHEN n%5=0 THEN 'blocked' ELSE 'observed' END,1,0,'[]','normal',
	 CASE WHEN n%16=0 THEN 'presence' ELSE '' END,md5('synthetic-account-'||((n/16)%500)) FROM generate_series(1,$2::integer)n`, f.org, rows); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `VACUUM (ANALYZE) shadow_events`); err != nil {
		t.Fatal(err)
	}
	// Negative control on the isolated fixture: without the migration, this
	// runtime query must lose its covering path over the presence inventory.
	if _, err := f.admin.Exec(ctx, `DROP INDEX shadow_events_presence_inventory`); err != nil {
		t.Fatal(err)
	}
	negative, err := tenantTx(ctx, f.a.db, f.org)
	if err != nil {
		t.Fatal(err)
	}
	var absent []byte
	err = negative.QueryRow(ctx, `EXPLAIN (FORMAT JSON) `+candidateDomainsQuery, 0, []string{}, []string{}, true).Scan(&absent)
	negative.Rollback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(absent, []byte("shadow_events_presence_inventory")) || !bytes.Contains(absent, []byte("shadow_events")) {
		t.Fatal("negative plan control did not exercise presence history")
	}
	migration, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = initializeDataReadIndexes(ctx, migration); err != nil {
		migration.Rollback(ctx)
		t.Fatal(err)
	}
	if err = migration.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	tx, err := tenantTx(ctx, f.a.db, f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SET LOCAL statement_timeout='8s'`); err != nil {
		t.Fatal(err)
	}
	args := []any{0, []string{}, []string{}, true}
	var raw []byte
	if err = tx.QueryRow(ctx, `EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) `+candidateDomainsQuery, args...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var plans []struct {
		Plan readPlan
		Time float64 `json:"Execution Time"`
	}
	if err = json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 {
		t.Fatalf("invalid plan: %v", err)
	}
	found := false
	var visit func(readPlan)
	visit = func(node readPlan) {
		if node.Relation == "shadow_events" {
			t.Logf("presence scan: type=%s rows=%.0f loops=%.0f heap=%d hits=%d reads=%d", node.Type, node.Rows, node.Loops, node.Heap, node.Hit, node.Read)
			if node.Type != "Index Only Scan" || node.Index != "shadow_events_presence_inventory" {
				t.Errorf("unbounded presence scan: %s %s", node.Type, node.Index)
			}
			if node.Heap != 0 {
				t.Errorf("vacuumed presence fixture fetched %d unrelated heap pages/tuples", node.Heap)
			}
			if node.Rows*node.Loops > float64(rows/16+128) {
				t.Error("presence scan includes unrelated history")
			}
			found = true
		}
		for _, child := range node.Children {
			visit(child)
		}
	}
	visit(plans[0].Plan)
	if !found {
		t.Fatal("presence plan not inspected")
	}
	// Hits include repeated visibility-map buffer accesses, not unique heap pages.
	// Bound buffer reads and total accesses independently so a genuine full scan fails.
	if plans[0].Plan.Read > rows/16/12+512 || plans[0].Plan.Hit+plans[0].Plan.Read > rows/16*2+512 {
		t.Fatalf("presence buffer budget exceeded: hits=%d reads=%d", plans[0].Plan.Hit, plans[0].Plan.Read)
	}
	if err = tx.QueryRow(ctx, candidateDomainsQuery, args...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var response struct {
		Platforms []struct {
			Provider string
			Visits   int
			Blocked  int
			Devices  int
			Accounts int
		}
	}
	if err = json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	type expected struct {
		visits, blocked   int
		devices, accounts map[int]bool
	}
	want := map[string]*expected{}
	for n := 16; n <= rows; n += 16 {
		provider := "service-" + strconv.Itoa((n/16)%40) + ".example.invalid"
		if want[provider] == nil {
			want[provider] = &expected{devices: map[int]bool{}, accounts: map[int]bool{}}
		}
		e := want[provider]
		e.visits++
		if n%5 == 0 {
			e.blocked++
		}
		e.devices[(n-1)%10000+1] = true
		e.accounts[(n/16)%500] = true
	}
	if len(response.Platforms) != len(want) {
		t.Fatalf("platform count changed: %d", len(response.Platforms))
	}
	for _, row := range response.Platforms {
		e := want[row.Provider]
		if e == nil || row.Visits != e.visits || row.Blocked != e.blocked || row.Devices != len(e.devices) || row.Accounts != len(e.accounts) {
			t.Fatalf("aggregate semantics changed for %s", row.Provider)
		}
	}
	t.Logf("presence inventory: total=%d matched=%d groups=%d SQL=%.3fms pages=%d", rows, rows/16, len(want), plans[0].Time, plans[0].Plan.Hit+plans[0].Plan.Read)
	tx.Rollback(ctx)
	verifyLargeDataReadEndpoints(t, f)
}
