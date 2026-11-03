package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"
)

// Short, isolated read qualification at fleet scale; no agents or VMs installed.
func TestAIGovernanceLocationLoadSmoke(t *testing.T) {
	if os.Getenv("MILVAGO_DISCOVERY_LOAD_SMOKE") != "1" {
		t.Skip("requires the separate isolated load fixture")
	}
	f := newObservabilityFixture(t)
	ctx := context.Background()
	for _, query := range []string{
		`INSERT INTO devices(organization_id,id,credential_hash,hostname,platform,version,status) SELECT $1,('00000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,decode(md5(n::text),'hex'),'Synthetic governance host','test','0.7.0','approved' FROM generate_series(1,10000)n`,
		`INSERT INTO discovery_entities(organization_id,device_id,scope,id,kind,sequence) SELECT $1,d.id,'endpoint','process/'||n,'process',1 FROM devices d CROSS JOIN generate_series(1,10)n WHERE d.organization_id=$1`,
		`INSERT INTO discovery_identifications(organization_id,device_id,scope,entity_id,application_id,signature_id,signature_revision,state,evidence,sequence) SELECT organization_id,device_id,scope,id,'fixture','fixture.process',1,'executed','[]',1 FROM discovery_entities WHERE organization_id=$1`,
	} {
		if _, err := f.admin.Exec(ctx, query, f.org); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	base := AIGovernanceRule{ID: "mandatory", Application: "fixture", Activity: "execution", Scope: "organization", Decision: "deny", Mandatory: true, AllowExceptions: true, Owner: "Load fixture", Purpose: "Synthetic bounded read qualification", ReviewDue: now.Add(time.Hour)}
	rules := []AIGovernanceRule{base}
	for n := 1; n < 20; n++ {
		r := base
		r.ID = fmt.Sprintf("aux-%d", n)
		r.Application = r.ID
		rules = append(rules, r)
	}
	for n := 1; n < 237; n++ {
		r := base
		r.ID = fmt.Sprintf("device-%d", n)
		r.Scope = "device"
		r.Target = fmt.Sprintf("00000000-0000-4000-8000-%012d", n)
		r.Decision = "allow"
		r.Mandatory = false
		r.AllowExceptions = false
		rules = append(rules, r)
	}
	raw, _ := json.Marshal(AIGovernanceDocument{Version: 1, Rules: rules})
	if _, err := f.admin.Exec(ctx, `INSERT INTO ai_governance_policies(organization_id,revision,document) VALUES($1,1,$2)`, f.org, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO ai_governance_exceptions(organization_id,device_id,rule_id,policy_revision,reason,approved_by,expires_at) SELECT $1,d.id,r.id,1,'Synthetic approved exception',$2,now()+interval '1 hour' FROM (SELECT id FROM devices WHERE organization_id=$1 ORDER BY id LIMIT 50)d CROSS JOIN (SELECT CASE WHEN n=0 THEN 'mandatory' ELSE 'aux-'||n END id FROM generate_series(0,19)n)r`, f.org, f.user); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"devices", "discovery_entities", "discovery_identifications", "ai_governance_exceptions"} {
		if _, err := f.admin.Exec(ctx, "ANALYZE "+table); err != nil {
			t.Fatal(err)
		}
	}
	path := "/api/discovery/applications/fixture/locations?limit=50"
	response := f.call("GET", path, nil, "")
	requireHTTP(t, response, 200)
	var page struct {
		Items []struct {
			Observations int `json:"observations"`
			Governance   struct {
				Execution aiGovernanceAssessment `json:"execution"`
			} `json:"governance"`
		} `json:"items"`
		Next string `json:"next_cursor"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 50 || page.Next == "" {
		t.Fatal("fleet locations were not paginated")
	}
	for _, item := range page.Items {
		if item.Observations != 10 || item.Governance.Execution.Status != "allowed" || item.Governance.Execution.Exception == "" {
			t.Fatal("bounded exception resolution failed", item)
		}
	}
	next := f.call("GET", path+"&cursor="+page.Next, nil, "")
	requireHTTP(t, next, 200)
	if err := json.Unmarshal(next.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	for _, item := range page.Items {
		if item.Governance.Execution.Status != "deviation" {
			t.Fatal("mandatory restriction lost after first page", item)
		}
	}
	response = nil
	next = nil
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	tasks := runtime.NumGoroutine()
	fds, _ := os.ReadDir("/proc/self/fd")
	type sample struct {
		latency time.Duration
		status  int
	}
	samples := make(chan sample, 100)
	var workers sync.WaitGroup
	for n := 0; n < 4; n++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for n := 0; n < 25; n++ {
				start := time.Now()
				r := f.call("GET", path, nil, "")
				samples <- sample{time.Since(start), r.Code}
			}
		}()
	}
	workers.Wait()
	close(samples)
	times := []time.Duration{}
	slow500, slow1000 := 0, 0
	for sample := range samples {
		if sample.status != 200 {
			t.Errorf("read status %d", sample.status)
		}
		times = append(times, sample.latency)
		if sample.latency >= 500*time.Millisecond {
			slow500++
		}
		if sample.latency >= time.Second {
			slow1000++
		}
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	afterFDs, _ := os.ReadDir("/proc/self/fd")
	t.Logf("10,000 synthetic devices/100,000 observations/256 rules/1,000 active exceptions; 100 location reads at 4 clients; p95=%s p99=%s; heap %d -> %d; goroutines %d -> %d; FD %d -> %d", times[94], times[98], before.HeapAlloc, after.HeapAlloc, tasks, runtime.NumGoroutine(), len(fds), len(afterFDs))
	if slow500 > 5 || slow1000 > 1 {
		t.Error("governance location latency target exceeded")
	}
	if after.HeapAlloc > before.HeapAlloc+128*1024*1024 || runtime.NumGoroutine() > tasks+32 || len(afterFDs) > len(fds)+32 {
		t.Error("governance read retained resources exceeded bounded short sample")
	}
}
