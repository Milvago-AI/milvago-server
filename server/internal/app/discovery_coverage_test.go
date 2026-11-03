package app

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"
)

func TestDiscoveryMissingAgentsAndReportsRemainVisibleAndPageWithoutInventingCoverage(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	ids := []string{"00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", "00000000-0000-4000-8000-000000000003", "00000000-0000-4000-8000-000000000004"}
	for n, id := range ids {
		capabilities, status := "[]", "approved"
		if n == 1 || n == 2 {
			capabilities = `["discovery-v1"]`
		}
		if n == 3 {
			status = "pending"
		}
		if _, err := f.admin.Exec(ctx, `INSERT INTO devices(organization_id,id,credential_hash,hostname,platform,version,status,capabilities) VALUES($1,$2,$3,'Synthetic visibility host','test','0.7.0',$4,$5)`, f.org, id, hash(randomToken()), status, capabilities); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_coverage(organization_id,device_id,scope,adapter,status,complete,checked_at,sequence) VALUES($1,$2,'endpoint','host-processes','available',true,now(),1)`, f.org, ids[2]); err != nil {
		t.Fatal(err)
	}
	type row struct {
		Device   string `json:"device_id"`
		Status   string `json:"status"`
		Reason   string `json:"reason"`
		Complete bool   `json:"complete"`
		Server   bool   `json:"server_assessed"`
	}
	read := func(cursor string) ([]row, string) {
		t.Helper()
		response := f.call("GET", "/api/discovery/coverage?limit=2&cursor="+url.QueryEscape(cursor), nil, "")
		requireHTTP(t, response, 200)
		var page struct {
			Items []row  `json:"items"`
			Next  string `json:"next_cursor"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		return page.Items, page.Next
	}
	first, cursor := read("")
	if len(first) != 2 || cursor == "" || first[0].Device != ids[0] || first[0].Reason != "agent_capability_missing" || first[1].Reason != "source_coverage_missing" {
		t.Fatalf("missing devices disappeared: %+v", first)
	}
	for _, r := range first {
		if r.Status != "unavailable" || r.Complete || !r.Server {
			t.Fatalf("server assessment invented collection success: %+v", r)
		}
	}
	second, end := read(cursor)
	if len(second) != 1 || end != "" || second[0].Device != ids[2] || second[0].Server || second[0].Status != "available" || !second[0].Complete {
		t.Fatalf("current coverage or cursor was lost: %+v", second)
	}
	if _, err := f.admin.Exec(ctx, `UPDATE discovery_coverage SET expires_at=now()-interval '1 second' WHERE organization_id=$1 AND device_id=$2`, f.org, ids[2]); err != nil {
		t.Fatal(err)
	}
	second, _ = read(cursor)
	if len(second) != 1 || second[0].Status != "unavailable" || !second[0].Server || second[0].Complete {
		t.Fatalf("expired collection still claimed visibility: %+v", second)
	}
}
