package app

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
)

type discoveryAggregateQueryCapture struct {
	pgx.Tx
	sql  string
	args []any
}

func TestDiscoveryApplicationAggregateKeyPages(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	var device string
	if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,kind)
  VALUES($1,$2,'Aggregate page fixture','test','0.7.0','approved','browser') RETURNING id`, f.org, hash(randomToken())).Scan(&device); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_entities(organization_id,device_id,scope,id,kind,sequence)
  VALUES($1,$2,'endpoint','process/1','process',1)`, f.org, device); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_identifications(organization_id,device_id,scope,entity_id,application_id,signature_id,signature_revision,state,evidence,sequence)
  SELECT $1,$2,'endpoint','process/1','app-'||lpad(n::text,3,'0'),'signature/'||n,1,'installed','[]',1 FROM generate_series(0,79) n`, f.org, device); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_identifications(organization_id,device_id,scope,entity_id,application_id,signature_id,signature_revision,state,evidence,sequence,expires_at)
  VALUES($1,$2,'endpoint','process/1','app-020a','expired',1,'installed','[]',1,now()-interval '1 minute')`, f.org, device); err != nil {
		t.Fatal(err)
	}
	tx, err := tenantTx(ctx, f.a.db, f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for _, scenario := range []struct {
		query               string
		limit, start, count int
	}{{"", 7, 0, 80}, {"app-07", 3, 70, 10}} {
		after := ""
		count := 0
		for pageNumber := 0; pageNumber < 13; pageNumber++ {
			raw, err := readDiscoveryApplications(ctx, tx, discoveryReadKey{organization: f.org, after: after, query: scenario.query, limit: scenario.limit}, discoveryAdditionalInventoryDevices(&Session{}))
			if err != nil {
				t.Fatal(err)
			}
			var page struct {
				Items []struct {
					ID                 string
					Devices, Instances int
				}
				Next string `json:"next_cursor"`
			}
			if json.Unmarshal(raw, &page) != nil || len(page.Items) == 0 || len(page.Items) > scenario.limit {
				t.Fatalf("invalid application page: %s", raw)
			}
			for _, item := range page.Items {
				if item.ID != fmt.Sprintf("app-%03d", scenario.start+count) || item.Devices != 1 || item.Instances != 1 {
					t.Fatalf("skipped, repeated, or expired application: %+v", item)
				}
				count++
				after = item.ID
			}
			if page.Next == "" {
				break
			}
			if page.Next != discoveryCursor(after) {
				t.Fatal("cursor does not match last returned key")
			}
		}
		if count != scenario.count {
			t.Fatalf("incomplete bounded pages: %d, want %d", count, scenario.count)
		}
	}
	var foreign string
	if err := f.admin.QueryRow(ctx, `INSERT INTO organizations(name,parent_id) VALUES('Synthetic aggregate tenant',$1) RETURNING id`, f.org).Scan(&foreign); err != nil {
		t.Fatal(err)
	}
	foreignTx, err := tenantTx(ctx, f.admin, foreign)
	if err != nil {
		t.Fatal(err)
	}
	defer foreignTx.Rollback(ctx)
	var foreignDevice string
	if err := foreignTx.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,kind)
  VALUES($1,$2,'Foreign aggregate fixture','test','0.7.0','approved','browser') RETURNING id`, foreign, hash(randomToken())).Scan(&foreignDevice); err != nil {
		t.Fatal(err)
	}
	if _, err := foreignTx.Exec(ctx, `INSERT INTO discovery_entities(organization_id,device_id,scope,id,kind,sequence)
  VALUES($1,$2,'endpoint','process/1','process',1)`, foreign, foreignDevice); err != nil {
		t.Fatal(err)
	}
	if _, err := foreignTx.Exec(ctx, `INSERT INTO discovery_identifications(organization_id,device_id,scope,entity_id,application_id,signature_id,signature_revision,state,evidence,sequence)
  VALUES($1,$2,'endpoint','process/1','foreign-app','foreign',1,'executed','[]',1)`, foreign, foreignDevice); err != nil {
		t.Fatal(err)
	}
	if err := foreignTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// The SQL organization argument is never sufficient to escape the transaction's tenant.
	raw, err := readDiscoveryApplications(ctx, tx, discoveryReadKey{organization: foreign, limit: 50}, discoveryAdditionalInventoryDevices(&Session{}))
	if err != nil {
		t.Fatal(err)
	}
	var page struct{ Items []any }
	if json.Unmarshal(raw, &page) != nil || len(page.Items) != 0 {
		t.Fatal("aggregate crossed tenant scope")
	}
}

func (q *discoveryAggregateQueryCapture) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	q.sql, q.args = sql, append([]any(nil), args...)
	return q.Tx.Query(ctx, sql, args...)
}

func TestDiscoveryApplicationAggregateDenseDevices(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	devices := []string{}
	for i := 0; i < 2; i++ {
		var device string
		if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,kind)
   VALUES($1,$2,'Aggregate fixture','test','0.7.0','approved','browser') RETURNING id`, f.org, hash(randomToken())).Scan(&device); err != nil {
			t.Fatal(err)
		}
		devices = append(devices, device)
		if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_entities(organization_id,device_id,scope,id,kind,sequence)
   SELECT $1,$2,'endpoint','process/'||n,'process',1 FROM generate_series(1,500) n`, f.org, device); err != nil {
			t.Fatal(err)
		}
		if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_identifications(organization_id,device_id,scope,entity_id,application_id,signature_id,signature_revision,state,evidence,sequence)
   SELECT $1,$2,'endpoint','process/'||n,'openclaw',s,1,CASE WHEN s='process' THEN 'executed' ELSE 'installed' END,'[]',1
   FROM generate_series(1,500) n CROSS JOIN (VALUES('process'),('installation')) signatures(s)`, f.org, device); err != nil {
			t.Fatal(err)
		}
	}
	// Equal entity IDs in separate scopes are different instances; signatures are not.
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_entities(organization_id,device_id,scope,id,kind,sequence)
  VALUES($1,$2,'guest','process/1','process',1)`, f.org, devices[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_identifications(organization_id,device_id,scope,entity_id,application_id,signature_id,signature_revision,state,evidence,sequence,expires_at)
  VALUES($1,$2,'guest','process/1','openclaw','http',1,'interface_recognized','[]',1,now()+interval '48 hours'),
  ($1,$2,'endpoint','process/1','openclaw','expired',1,'indication','[]',1,now()-interval '1 minute'),
  ($1,$2,'endpoint','process/1','other-tool','other',1,'installed','[]',1,now()+interval '48 hours'),
  ($1,$2,'endpoint','process/1','retired-tool','retired',1,'executed','[]',1,now()-interval '1 minute')`, f.org, devices[0]); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"discovery_identifications", "discovery_entities", "devices"} {
		if _, err := f.admin.Exec(ctx, "ANALYZE "+table); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := tenantTx(ctx, f.a.db, f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	capture := &discoveryAggregateQueryCapture{Tx: tx}
	key := discoveryReadKey{organization: f.org, limit: 50}
	raw, err := readDiscoveryApplications(ctx, capture, key, discoveryAdditionalInventoryDevices(&Session{}))
	if err != nil {
		t.Fatal(err)
	}
	var page struct {
		Items []struct {
			ID                 string `json:"id"`
			Devices, Instances int
			States             []string
		}
		Next string `json:"next_cursor"`
	}
	if json.Unmarshal(raw, &page) != nil || len(page.Items) != 2 || page.Next != "" {
		t.Fatalf("incorrect aggregate page: %s", raw)
	}
	item := page.Items[0]
	if item.ID != "openclaw" || item.Devices != 2 || item.Instances != 1001 {
		t.Fatalf("instance keys lost or duplicated: %+v", item)
	}
	states := map[string]bool{}
	for _, state := range item.States {
		states[state] = true
	}
	if len(states) != 3 || !states["executed"] || !states["installed"] || !states["interface_recognized"] {
		t.Fatalf("expired or missing states: %v", states)
	}
	if page.Items[1].ID != "other-tool" || page.Items[1].Devices != 1 || page.Items[1].Instances != 1 {
		t.Fatalf("separate application was merged: %+v", page.Items[1])
	}
	var plan json.RawMessage
	if err := tx.QueryRow(ctx, "EXPLAIN (ANALYZE, FORMAT JSON) "+capture.sql, capture.args...).Scan(&plan); err != nil {
		t.Fatal(err)
	}
	var nodes any
	if len(plan) > 128*1024 || json.Unmarshal(plan, &nodes) != nil {
		t.Fatal("invalid bounded aggregate plan")
	}
	scanned, maxGroups := float64(0), float64(0)
	var walk func(any)
	walk = func(value any) {
		switch node := value.(type) {
		case []any:
			for _, child := range node {
				walk(child)
			}
		case map[string]any:
			rows, _ := node["Actual Rows"].(float64)
			loops, _ := node["Actual Loops"].(float64)
			if node["Relation Name"] == "discovery_identifications" {
				scanned += rows * loops
			}
			if node["Node Type"] == "Aggregate" && rows > maxGroups {
				maxGroups = rows
			}
			for _, child := range node {
				walk(child)
			}
		}
	}
	walk(nodes)
	// The page needs device aggregates, not an intermediate row per entity or
	// another full fleet traversal merely to discover its application names.
	if maxGroups > 4 {
		t.Errorf("aggregate expanded dense entities into %.0f intermediate groups", maxGroups)
	}
	if scanned > 3000 {
		t.Errorf("aggregate scanned %.0f identification rows for 2004 facts", scanned)
	}
	for _, scenario := range []struct {
		after, query string
		limit, items int
		id           string
		next         bool
	}{
		{"", "", 1, 1, "openclaw", true},
		{"openclaw", "", 1, 1, "other-tool", false},
		{"", "OTHER", 50, 1, "other-tool", false},
		{"z", "", 50, 0, "", false},
		{"", "retired", 50, 0, "", false},
		{"", "' OR true --", 50, 0, "", false},
	} {
		raw, err := readDiscoveryApplications(ctx, tx, discoveryReadKey{organization: f.org, after: scenario.after, query: scenario.query, limit: scenario.limit}, discoveryAdditionalInventoryDevices(&Session{}))
		if err != nil {
			t.Fatal(err)
		}
		page.Items = nil
		page.Next = ""
		if json.Unmarshal(raw, &page) != nil || len(page.Items) != scenario.items || (page.Next != "") != scenario.next {
			t.Fatalf("page/filter mismatch: %+v: %s", scenario, raw)
		}
		if scenario.items > 0 && page.Items[0].ID != scenario.id {
			t.Fatalf("wrong page: %+v: %s", scenario, raw)
		}
	}
}
