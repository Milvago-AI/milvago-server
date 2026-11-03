package app

import (
	"context"
	"strings"
	"testing"
)

func TestDiscoveryDeviceNamesReuseInventoryProjectionAndRespectAliases(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	var device string
	if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status) VALUES($1,$2,'Synthetic alias','test','0.7.0','approved') RETURNING id`, f.org, hash(randomToken())).Scan(&device); err != nil {
		t.Fatal(err)
	}
	cipher, err := f.a.sealIdentity(f.org, "device-name:"+device, "Synthetic workstation")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(ctx, `UPDATE devices SET hostname_ciphertext=$1 WHERE organization_id=$2 AND id=$3`, cipher, f.org, device); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`INSERT INTO discovery_entities(organization_id,device_id,scope,id,kind,sequence) VALUES($1,$2,'endpoint','vm/fixture','vm',1),($1,$2,'endpoint','process/fixture','process',1)`,
		`INSERT INTO discovery_identifications(organization_id,device_id,scope,entity_id,application_id,signature_id,signature_revision,state,evidence,sequence) VALUES($1,$2,'endpoint','process/fixture','openclaw','openclaw.process',1,'executed','[]',1)`,
		`INSERT INTO discovery_events(organization_id,device_id,scope,entity_id,kind,application_id) VALUES($1,$2,'endpoint','process/fixture','identified','openclaw')`,
		`INSERT INTO discovery_coverage(organization_id,device_id,scope,adapter,status,complete,checked_at,sequence) VALUES($1,$2,'endpoint','fixture','partial',false,now(),1)`,
		`INSERT INTO discovery_runs(organization_id,device_id,status) VALUES($1,$2,'pending')`,
	} {
		if _, err = f.admin.Exec(ctx, statement, f.org, device); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"/api/discovery/environments", "/api/discovery/coverage", "/api/discovery/events", "/api/discovery/runs", "/api/discovery/applications/openclaw/instances"} {
		response := f.call("GET", path+"?limit=50", nil, "")
		requireHTTP(t, response, 200)
		if !strings.Contains(response.Body.String(), `"device_name":"Synthetic workstation"`) || strings.Contains(response.Body.String(), cipher) {
			t.Fatal("machine projection was missing or disclosed ciphertext", path)
		}
		aliased := f.call("GET", path+"?limit=50&identity=aliases", nil, "")
		requireHTTP(t, aliased, 200)
		if strings.Contains(aliased.Body.String(), "Synthetic workstation") || !strings.Contains(aliased.Body.String(), deviceAlias(device)) {
			t.Fatal("explicit alias projection was ignored", path)
		}
	}
	if _, err = f.admin.Exec(ctx, `INSERT INTO privacy_settings(organization_id,configuration) VALUES($1,'{"aggregate_only":true}') ON CONFLICT(organization_id) DO UPDATE SET configuration=privacy_settings.configuration||excluded.configuration`, f.org); err != nil {
		t.Fatal(err)
	}
	requireHTTP(t, f.call("GET", "/api/discovery/environments", nil, ""), 403)
}
