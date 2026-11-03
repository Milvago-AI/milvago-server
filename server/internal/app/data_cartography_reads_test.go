package app

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestDataReadCartographyRejectsOverflowWithoutTruncation(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	var device string
	if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status) VALUES($1,decode(md5('map-key')||md5('map-key'),'hex'),'Synthetic','test','0.7.28','approved') RETURNING id`, f.org).Scan(&device); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO shadow_events(organization_id,device_id,id,occurred_at,kind,provider,tool,source,action,policy_revision,characters,model,labels,sensitivity)
 SELECT $1,$2,gen_random_uuid(),now()-interval '1 minute','prompt','synthetic.example.invalid','synthetic','browser','observed',1,1,'synthetic-'||n,'[]','normal' FROM generate_series(1,10001)n`, f.org, device); err != nil {
		t.Fatal(err)
	}
	w := f.callAs("GET", "/api/shadow/cartography", nil, f.owner, f.csrf, "")
	requireHTTP(t, w, 413)
	var refusal struct {
		Code string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &refusal); err != nil {
		t.Fatal(err)
	}
	if refusal.Code != "response_too_large" {
		t.Fatal("overflow did not explain how to narrow the read")
	}
	// The exact boundary returns every flow and the matching total.
	if _, err := f.admin.Exec(ctx, `DELETE FROM shadow_events WHERE device_id=$1 AND model='synthetic-10001'`, device); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	w = f.callAs("GET", "/api/shadow/cartography", nil, f.owner, f.csrf, "")
	requireHTTP(t, w, 200)
	var result struct {
		Flows  []json.RawMessage
		Totals struct{ Requests int }
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 10000 || result.Totals.Requests != 10000 {
		t.Fatal("map was silently truncated or totals changed")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("bounded map exceeded its fixture read budget")
	}
	w = f.callAs("GET", "/api/shadow/cartography?model=synthetic-1", nil, f.owner, f.csrf, "")
	requireHTTP(t, w, 200)
	result.Flows = nil
	result.Totals.Requests = 0
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 1 || result.Totals.Requests != 1 {
		t.Fatal("narrowed map did not recover a complete result")
	}
}
