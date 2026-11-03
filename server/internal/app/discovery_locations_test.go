package app

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"
)

func TestDiscoveryLocationsGroupWholeDevicesAndFilterProofs(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	const first = "00000000-0000-4000-8000-000000000001"
	const second = "00000000-0000-4000-8000-000000000002"
	for _, id := range []string{first, second} {
		if _, err := f.admin.Exec(ctx, `INSERT INTO devices(organization_id,id,credential_hash,hostname,platform,version,status) VALUES($1,$2,$3,'Fixture','test','0.7.0','approved')`, f.org, id, hash(randomToken())); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_entities(organization_id,device_id,scope,id,kind,sequence) SELECT $1,d::uuid,'endpoint','process/'||n,'process',1 FROM unnest(ARRAY[$2,$3]) d CROSS JOIN generate_series(1,60)n`, f.org, first, second); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_identifications(organization_id,device_id,scope,entity_id,application_id,signature_id,signature_revision,state,evidence,sequence,expires_at) SELECT organization_id,device_id,scope,id,'openclaw','fixture',1,'executed','[]',1,CASE WHEN id='process/60' THEN now()-interval '1 hour' ELSE now()+interval '1 hour' END FROM discovery_entities WHERE organization_id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	type page struct {
		Items []struct {
			Device string `json:"device_id"`
			Count  int    `json:"observations"`
		} `json:"items"`
		Next string `json:"next_cursor"`
	}
	read := func(path string) page {
		t.Helper()
		response := f.call("GET", path, nil, "")
		requireHTTP(t, response, 200)
		var p page
		if err := json.Unmarshal(response.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := read("/api/discovery/applications/openclaw/locations?limit=1")
	if len(p.Items) != 1 || p.Items[0].Device != first || p.Items[0].Count != 59 || p.Next == "" {
		t.Fatalf("incomplete device grouping: %+v", p)
	}
	p = read("/api/discovery/applications/openclaw/locations?limit=1&cursor=" + url.QueryEscape(p.Next))
	if len(p.Items) != 1 || p.Items[0].Device != second || p.Items[0].Count != 59 || p.Next != "" {
		t.Fatalf("invalid second location: %+v", p)
	}
	p = read("/api/discovery/applications/openclaw/instances?limit=100&device_id=" + second)
	if len(p.Items) != 59 {
		t.Fatalf("proof count %d", len(p.Items))
	}
	for _, row := range p.Items {
		if row.Device != second {
			t.Fatal("proof leaked another location")
		}
	}
	for _, suffix := range []string{"locations?limit=101", "locations?cursor=" + url.QueryEscape(discoveryCursor("not-a-uuid")), "instances?device_id=data:image/png", "instances?device_id=" + url.QueryEscape("' OR true --")} {
		requireHTTP(t, f.call("GET", "/api/discovery/applications/openclaw/"+suffix, nil, ""), 400)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO privacy_settings(organization_id,configuration) VALUES($1,'{"aggregate_only":true}') ON CONFLICT(organization_id) DO UPDATE SET configuration=excluded.configuration`, f.org); err != nil {
		t.Fatal(err)
	}
	requireHTTP(t, f.call("GET", "/api/discovery/applications/openclaw/locations", nil, ""), 403)
}
