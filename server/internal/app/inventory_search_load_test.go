package app

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestInventorySearchLoad(t *testing.T) {
	if os.Getenv("MILVAGO_INVENTORY_LOAD") != "1" {
		t.Skip("isolated inventory load fixture")
	}
	f := newObservabilityFixture(t)
	ctx := context.Background()
	if _, err := f.admin.Exec(ctx, `INSERT INTO devices(organization_id,id,credential_hash,hostname,platform,version,status)
 SELECT $1,md5('inventory-load-'||n)::uuid,decode(md5('inventory-load-key-'||n)||md5('inventory-load-key-2-'||n),'hex'),'Synthetic load host','test','test','approved' FROM generate_series(0,99) n`, f.org); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_entities(organization_id,device_id,scope,id,kind,sequence)
 SELECT $1,md5('inventory-load-'||(n%100))::uuid,'host','process/'||n,'process',1 FROM generate_series(1,100000) n`, f.org); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_identifications(organization_id,device_id,scope,entity_id,application_id,signature_id,signature_revision,state,evidence,sequence)
 SELECT $1,md5('inventory-load-'||(n%100))::uuid,'host','process/'||n,'fixture-'||lpad((n%1000)::text,4,'0'),'fixture.process',1,'installed','[{"source":"host_process"}]',1 FROM generate_series(1,100000) n`, f.org); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, "ANALYZE discovery_identifications"); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		q     string
		total int
	}{
		{"", 1000}, {"app=%5Efixture-000&regex=app", 10},
		{"query=fixture-000&regex=query", 10},
		{"source=host_process&regex=source", 1000},
		{"environment=host&regex=environment&state=install&regex=state", 1000},
		{"service=unmatched&regex=service", 0},
	} {
		start := time.Now()
		w := f.call("GET", "/api/discovery/inventory?limit=50&"+test.q, nil, "")
		elapsed := time.Since(start)
		requireHTTP(t, w, 200)
		var result struct {
			Total int `json:"total"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Total != test.total {
			t.Fatalf("incorrect total: %s", w.Body.String())
		}
		t.Logf("100000 observations / 100 devices / 1000 applications: %s => %s", test.q, elapsed)
	}
}
