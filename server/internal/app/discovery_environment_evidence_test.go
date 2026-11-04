package app

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestDiscoveryEnvironmentEvidenceAndHistory(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := f.admin.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	device := func(org string) string {
		t.Helper()
		var id string
		if err := f.admin.QueryRow(ctx, "INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,kind) VALUES($1,$2,'Synthetic environment host','test','0.7.0','approved','browser') RETURNING id", org, hash(randomToken())).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	selected, other := device(f.org), device(f.org)
	seed := func(org, device, scope, entity, application string) {
		t.Helper()
		exec("INSERT INTO discovery_entities(organization_id,device_id,scope,id,kind,sequence) VALUES($1,$2,$3,$4,'container',1)", org, device, scope, entity)
		exec("INSERT INTO discovery_identifications(organization_id,device_id,scope,entity_id,application_id,signature_id,signature_revision,state,evidence,sequence) VALUES($1,$2,$3,$4,$5,'fixture.image',1,'indication',$6,1)", org, device, scope, entity, application, "[{\"source\":\"container_metadata\",\"fact_id\":\"proof/fixture\",\"observed_at\":100,\"fields\":[\"image_repository\"]}]")
		exec("INSERT INTO discovery_events(organization_id,device_id,scope,entity_id,kind,application_id) VALUES($1,$2,$3,$4,'identified',$5)", org, device, scope, entity, application)
	}
	seed(f.org, selected, "first", "container/shared", "selected")
	seed(f.org, selected, "second", "container/shared", "wrong-scope")
	seed(f.org, selected, "first", "container/other", "wrong-entity")
	seed(f.org, other, "first", "container/shared", "wrong-device")
	exec("INSERT INTO discovery_communications(organization_id,device_id,scope,entity_id,provider,sequence,evidence,last_seen) VALUES($1,$2,'first','container/shared','fixture-provider',1,$3,now())", f.org, selected, "{\"source\":\"container_flow\",\"fact_id\":\"proof/network\",\"observed_at\":100,\"fields\":[\"remote_host\"]}")
	exec("INSERT INTO discovery_events(organization_id,device_id,scope,entity_id,kind) VALUES($1,$2,'first','container/shared','provider_contacted')", f.org, selected)
	exec("INSERT INTO discovery_identifications(organization_id,device_id,scope,entity_id,application_id,signature_id,signature_revision,state,evidence,sequence,expires_at) VALUES($1,$2,'first','container/shared','expired','expired.image',1,'indication','[]',1,now()-interval '1 minute')", f.org, selected)
	var foreignOrg string
	if err := f.admin.QueryRow(ctx, "INSERT INTO organizations(name,parent_id) VALUES('Other synthetic tenant',$1) RETURNING id", f.org).Scan(&foreignOrg); err != nil {
		t.Fatal(err)
	}
	exec("SELECT set_config('milvago.organization_id',$1,false)", foreignOrg)
	foreignDevice := device(foreignOrg)
	seed(foreignOrg, foreignDevice, "first", "container/shared", "wrong-tenant")
	exec("SELECT set_config('milvago.organization_id',$1,false)", f.org)
	type page struct {
		Items []map[string]any `json:"items"`
		Next  string           `json:"next_cursor"`
	}
	read := func(path string) page {
		t.Helper()
		w := f.call("GET", path, nil, "")
		requireHTTP(t, w, 200)
		var value page
		if err := json.Unmarshal(w.Body.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	proofPath := "/api/discovery/environments/container%2Fshared/evidence?device_id=" + selected + "&scope=first"
	seen, cursor := map[string]bool{}, ""
	for i := 0; i < 2; i++ {
		value := read(proofPath + "&limit=1&cursor=" + url.QueryEscape(cursor))
		if len(value.Items) != 1 {
			t.Fatal("wrong evidence page", value)
		}
		row := value.Items[0]
		kind := row["kind"].(string)
		raw, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		if seen[kind] || strings.Contains(string(raw), "wrong-") || row["application_id"] == "expired" {
			t.Fatal("evidence escaped its selected environment or repeated", row)
		}
		if row["evidence"] == nil {
			t.Fatal("proof metadata missing")
		}
		seen[kind] = true
		cursor = value.Next
	}
	if len(seen) != 2 || cursor != "" {
		t.Fatal("evidence continuation lost a source", seen, cursor)
	}
	historyPath := "/api/discovery/events?device_id=" + selected + "&scope=first&entity_id=container%2Fshared"
	events := map[string]bool{}
	cursor = ""
	for i := 0; i < 2; i++ {
		value := read(historyPath + "&limit=1&cursor=" + url.QueryEscape(cursor))
		if len(value.Items) != 1 {
			t.Fatal("wrong history page", value)
		}
		row := value.Items[0]
		id := row["id"].(string)
		if events[id] || row["device_id"] != selected || row["entity_id"] != "container/shared" || strings.HasPrefix(row["application_id"].(string), "wrong-") {
			t.Fatal("history escaped environment or repeated", row)
		}
		events[id] = true
		cursor = value.Next
	}
	if cursor != "" || len(events) != 2 {
		t.Fatal("history continuation lost events")
	}
	if len(read("/api/discovery/events?device_id="+foreignDevice+"&scope=first&entity_id=container%2Fshared").Items) != 0 {
		t.Fatal("foreign tenant history exposed")
	}
	requireHTTP(t, f.call("GET", "/api/discovery/environments/container%2Fshared/evidence?device_id="+foreignDevice+"&scope=first", nil, ""), 404)
	requireHTTP(t, f.call("GET", proofPath+"&cursor="+discoveryCursor("image/png"), nil, ""), 400)
	requireHTTP(t, f.call("GET", strings.Replace(proofPath, "scope=first", "scope=%3Cimg%3E", 1), nil, ""), 400)
	requireHTTP(t, f.call("GET", "/api/discovery/events?entity_id=%3Cimg%3E", nil, ""), 400)
	requireHTTP(t, f.call("GET", "/api/discovery/events?device_id=image%2Fpng", nil, ""), 400)
}

func TestDiscoveryEnvironmentEvidenceRequiresDevicePermission(t *testing.T) {
	a := &App{}
	r := httptest.NewRequest("GET", "/api/discovery/environments/container%2Ffixture/evidence", nil)
	if err := a.discoveryEnvironmentEvidence(httptest.NewRecorder(), r, nil, &Session{Permissions: []string{permDiscoveryRead}}); err == nil {
		t.Fatal("discovery.read alone exposed device evidence")
	}
}
