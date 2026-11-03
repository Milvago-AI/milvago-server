package app

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestDiscoveryDeviceCoverageFiltersBeforePaginationAndRetainsUnknownVisibility(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	ids := []string{"00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
	for _, id := range ids {
		if _, err := f.admin.Exec(ctx, `INSERT INTO devices(organization_id,id,credential_hash,hostname,platform,version,status,capabilities) VALUES($1,$2,$3,'Synthetic coverage host','test','0.7.0','approved','["discovery-v1"]')`, f.org, id, hash(randomToken())); err != nil {
			t.Fatal(err)
		}
	}
	for _, adapter := range []string{"guest-tools", "network"} {
		if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_coverage(organization_id,device_id,scope,adapter,status,complete,checked_at,sequence) VALUES($1,$2,'endpoint',$3,'unavailable',false,now(),1)`, f.org, ids[2], adapter); err != nil {
			t.Fatal(err)
		}
	}
	type row struct {
		Device   string `json:"device_id"`
		Adapter  string `json:"adapter"`
		Status   string `json:"status"`
		Reason   string `json:"reason"`
		Complete bool   `json:"complete"`
	}
	read := func(device, cursor string) ([]row, string) {
		t.Helper()
		response := f.call("GET", "/api/discovery/coverage?limit=1&device_id="+url.QueryEscape(device)+"&cursor="+url.QueryEscape(cursor), nil, "")
		requireHTTP(t, response, 200)
		var page struct {
			Items []row  `json:"items"`
			Next  string `json:"next_cursor"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		for _, item := range page.Items {
			if item.Device != strings.ToLower(device) || item.Status != "unavailable" || item.Complete {
				t.Fatalf("coverage escaped its device or invented visibility: %+v", item)
			}
		}
		return page.Items, page.Next
	}
	first, cursor := read(strings.ToUpper(ids[2]), "")
	if len(first) != 1 || first[0].Adapter != "guest-tools" || cursor == "" {
		t.Fatal("filter was applied after pagination", first, cursor)
	}
	second, end := read(ids[2], cursor)
	if len(second) != 1 || second[0].Adapter != "network" || end != "" {
		t.Fatal("filtered page lost its source", second, end)
	}
	missing, end := read(ids[0], "")
	if len(missing) != 1 || missing[0].Reason != "source_coverage_missing" || end != "" {
		t.Fatal("missing reports must remain explicit", missing, end)
	}
	unknown, end := read("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "")
	if len(unknown) != 0 || end != "" {
		t.Fatal("unknown device returned another device's coverage")
	}
	var foreignOrg string
	foreignDevice := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	if err := f.admin.QueryRow(ctx, `INSERT INTO organizations(name,parent_id) VALUES('Synthetic foreign coverage',$1) RETURNING id`, f.org).Scan(&foreignOrg); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `SELECT set_config('milvago.organization_id',$1,false)`, foreignOrg); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO devices(organization_id,id,credential_hash,hostname,platform,version,status) VALUES($1,$2,$3,'Synthetic foreign device','test','0.7.0','approved')`, foreignOrg, foreignDevice, hash(randomToken())); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_coverage(organization_id,device_id,scope,adapter,status,complete,checked_at,sequence) VALUES($1,$2,'endpoint','private-foreign-source','available',true,now(),1)`, foreignOrg, foreignDevice); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `SELECT set_config('milvago.organization_id',$1,false)`, f.org); err != nil {
		t.Fatal(err)
	}
	foreign, end := read(foreignDevice, "")
	if len(foreign) != 0 || end != "" {
		t.Fatal("device filter crossed the tenant boundary")
	}
	for _, device := range []string{"image/png", "data:image/png;base64,AA", strings.Repeat("a", 37)} {
		requireHTTP(t, f.call("GET", "/api/discovery/coverage?device_id="+url.QueryEscape(device), nil, ""), 400)
	}
	requireHTTP(t, f.call("GET", "/api/discovery/coverage?device_id="+ids[0]+"&cursor="+url.QueryEscape(cursor), nil, ""), 400)
	if _, err := f.admin.Exec(ctx, `INSERT INTO privacy_settings(organization_id,configuration) VALUES($1,'{"aggregate_only":true}') ON CONFLICT(organization_id) DO UPDATE SET configuration=privacy_settings.configuration||excluded.configuration`, f.org); err != nil {
		t.Fatal(err)
	}
	requireHTTP(t, f.call("GET", "/api/discovery/coverage?device_id="+ids[2], nil, ""), 403)
}
