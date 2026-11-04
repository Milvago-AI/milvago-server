package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestDiscoveryApplicationAggregationCountsEntitiesAcrossScopesAndSignatures(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	const first = "00000000-0000-4000-8000-000000000001"
	const second = "00000000-0000-4000-8000-000000000002"
	for _, id := range []string{first, second} {
		if _, err := f.admin.Exec(ctx, `INSERT INTO devices(organization_id,id,credential_hash,hostname,platform,version,status) VALUES($1,$2,$3,'Synthetic aggregation host','test','0.7.0','approved')`, f.org, id, hash(randomToken())); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_entities(organization_id,device_id,scope,id,kind,sequence) SELECT $1,d::uuid,scope,id,'process',1 FROM unnest(ARRAY[$2,$3]) d CROSS JOIN (VALUES('host','process/1'),('vm','process/1'),('expired','process/2')) x(scope,id)`, f.org, first, second); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_identifications(organization_id,device_id,scope,entity_id,application_id,signature_id,signature_revision,state,evidence,sequence,expires_at)
VALUES($1,$2,'host','process/1','openclaw','one',1,'executed','[]',1,now()+interval '1 hour'),
($1,$2,'host','process/1','openclaw','two',1,'indication','[]',1,now()+interval '1 hour'),
($1,$2,'vm','process/1','openclaw','one',1,'installed','[]',1,now()+interval '1 hour'),
($1,$3,'host','process/1','openclaw','one',1,'interface_recognized','[]',1,now()+interval '1 hour'),
($1,$3,'expired','process/2','openclaw','one',1,'executed','[]',1,now()-interval '1 hour')`, f.org, first, second); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_reviews(organization_id,application_id,status) VALUES($1,'openclaw','authorized')`, f.org); err != nil {
		t.Fatal(err)
	}
	response := f.call("GET", "/api/discovery/applications?q=OPENCLAW&limit=1", nil, "")
	requireHTTP(t, response, 200)
	var page struct {
		Items []struct {
			ID        string   `json:"id"`
			Devices   int      `json:"devices"`
			Instances int      `json:"instances"`
			States    []string `json:"states"`
			Review    string   `json:"review"`
		} `json:"items"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != "openclaw" || page.Items[0].Devices != 2 || page.Items[0].Instances != 3 || len(page.Items[0].States) != 4 || page.Items[0].Review != "authorized" {
		t.Fatalf("invalid aggregate: %+v", page)
	}
	requireHTTP(t, f.call("GET", "/api/discovery/applications?q=no-match", nil, ""), 200)
	requireHTTP(t, f.call("PUT", "/api/discovery/applications/openclaw/review", map[string]string{"status": "unauthorized"}, f.csrf), 200)
	refreshed := f.call("GET", "/api/discovery/applications?q=OPENCLAW&limit=1", nil, "")
	requireHTTP(t, refreshed, 200)
	if !strings.Contains(refreshed.Body.String(), `"review":"unauthorized"`) {
		t.Fatal("governance mutation did not invalidate the aggregate")
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO privacy_settings(organization_id,configuration) VALUES($1,'{"aggregate_only":true}') ON CONFLICT(organization_id) DO UPDATE SET configuration=privacy_settings.configuration||excluded.configuration`, f.org); err != nil {
		t.Fatal(err)
	}
	requireHTTP(t, f.call("GET", "/api/discovery/applications?q=OPENCLAW&limit=1", nil, ""), 403)
	if _, err := f.admin.Exec(ctx, `UPDATE memberships SET role='reporter' WHERE user_id=$1 AND organization_id=$2`, f.user, f.org); err != nil {
		t.Fatal(err)
	}
	requireHTTP(t, f.call("GET", "/api/discovery/applications?q=OPENCLAW&limit=1", nil, ""), 403)
}
