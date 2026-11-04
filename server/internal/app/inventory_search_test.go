package app

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestInventorySearchValidation(t *testing.T) {
	for _, field := range inventorySearchFields {
		f, err := parseInventorySearch(url.Values{field: {"(alpha|beta)[0-9]{2,3}"}, "regex": {field}})
		if err != nil {
			t.Fatalf("%s: %v", field, err)
		}
		args := []any{"tenant", "catalog", []string{}, 30}
		where := f.where(&args, []string{}, []string{})
		if strings.Contains(where, "alpha") {
			t.Fatal("pattern interpolated as SQL")
		}
	}
	for _, q := range []url.Values{
		{"app": {"["}, "regex": {"app"}}, {"app": {"(?=a)"}, "regex": {"app"}},
		{"app": {"a{9999}"}, "regex": {"app"}}, {"unknown": {"a"}}, {"regex": {"app"}},
		{"app": {"a"}, "regex": {"app", "app"}}, {"query": {"a", "b"}}, {"app": {"\x00"}},
		{"app": {strings.Repeat("a", 201)}},
	} {
		if _, err := parseInventorySearch(q); err == nil {
			t.Fatalf("invalid search accepted: %v", q)
		}
	}
}

func TestInventorySearchHTTP(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	const first = "00000000-0000-4000-8000-000000000001"
	const second = "00000000-0000-4000-8000-000000000002"
	for n, id := range []string{first, second} {
		name := []string{"LT-COM-SYNTHETIC", "LT-IT-SYNTHETIC"}[n]
		cipher, err := f.a.sealIdentity(f.org, "device-name:"+id, name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.admin.Exec(ctx, `INSERT INTO devices(organization_id,id,credential_hash,hostname,hostname_ciphertext,platform,version,status) VALUES($1,$2,$3,$4,$5,'test','test','approved')`, f.org, id, hash("inventory-fixture-"+id), deviceAlias(id), cipher); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_entities(organization_id,device_id,scope,id,kind,display,sequence)
 SELECT $1,d::uuid,scope,'process/1','process',jsonb_build_object('name',scope||' runtime'),1 FROM unnest(ARRAY[$2,$3]) d CROSS JOIN (VALUES('host'),('wsl')) x(scope)`, f.org, first, second); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_identifications(organization_id,device_id,scope,entity_id,application_id,signature_id,signature_revision,state,evidence,sequence,expires_at)
 VALUES($1,$2,'host','process/1','openclaw','one',1,'executed','[{"source":"host_process"}]',1,now()+interval '1 hour'),
 ($1,$2,'host','process/1','openclaw','two',1,'indication','[]',1,now()+interval '1 hour'),
 ($1,$3,'wsl','process/1','openclaw','one',1,'installed','[]',1,now()+interval '1 hour'),
 ($1,$3,'host','process/1','expired-only','one',1,'executed','[]',1,now()-interval '1 hour')`, f.org, first, second); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_communications(organization_id,device_id,scope,entity_id,provider,sequence,last_seen,evidence) VALUES($1,$2,'host','process/1','gemini.fixture.invalid',1,now(),'{}')`, f.org, first); err != nil {
		t.Fatal(err)
	}
	// More than one page: filtering must happen before pagination and counts.
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_identifications(organization_id,device_id,scope,entity_id,application_id,signature_id,signature_revision,state,evidence,sequence)
 SELECT $1,$2,'host','process/1','fixture-app-'||lpad(n::text,3,'0'),'fixture-'||n,1,'indication','[]',1 FROM generate_series(1,65) n`, f.org, first); err != nil {
		t.Fatal(err)
	}
	type page struct {
		Items []struct {
			ID        string `json:"id"`
			Devices   int    `json:"devices"`
			Instances int    `json:"instances"`
		} `json:"items"`
		Total int    `json:"total"`
		Next  string `json:"next_cursor"`
	}
	for _, test := range []struct {
		query          string
		total, devices int
	}{
		{"app=openclaw&regex=app", 1, 2},
		{"app=OPENCLAW&regex=app", 1, 2},
		{"device=LT-COM&regex=device&app=openclaw&regex=app", 1, 1},
		{"query=LT-COM&regex=query&app=openclaw&regex=app", 1, 1},
		{"app=openclaw&regex=app&environment=wsl&regex=environment", 1, 1},
		{"app=openclaw&regex=app&source=host_process&regex=source", 1, 1},
		{"service=gemini&regex=service&app=openclaw&regex=app", 1, 1},
		{"type=SOFT&regex=type&app=openclaw&regex=app", 1, 2},
		{"query=host_process&regex=query", 1, 1},
		{"app=openclaw&regex=app&state=executed&regex=state", 1, 1},
		{"app=openclaw&regex=app&device=LT-COM&regex=device&state=installed&regex=state", 0, 0},
		{"app=fixture-app-065&regex=app&limit=1", 1, 1},
		{"query=expired-only&regex=query", 0, 0},
		{"app=%27%3BSELECT&regex=app", 0, 0},
	} {
		w := f.call("GET", "/api/discovery/inventory?"+test.query, nil, "")
		requireHTTP(t, w, 200)
		var got page
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Total != test.total || len(got.Items) != test.total || (test.total > 0 && got.Items[0].Devices != test.devices) {
			t.Fatalf("%s: %s", test.query, w.Body.String())
		}
	}
	w := f.call("GET", "/api/discovery/inventory?app=fixture-app&regex=app&limit=20", nil, "")
	requireHTTP(t, w, 200)
	var got page
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 20 || got.Total != 65 || got.Next == "" {
		t.Fatalf("bad first page: %s", w.Body.String())
	}
	seen := map[string]bool{}
	for {
		for _, item := range got.Items {
			if seen[item.ID] {
				t.Fatal("duplicate across pages")
			}
			seen[item.ID] = true
		}
		if got.Next == "" {
			break
		}
		w = f.call("GET", "/api/discovery/inventory?app=fixture-app&regex=app&limit=20&cursor="+url.QueryEscape(got.Next), nil, "")
		requireHTTP(t, w, 200)
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Total != 65 {
			t.Fatal("total changed with cursor")
		}
	}
	if len(seen) != 65 {
		t.Fatal("pagination lost results")
	}
	for _, suffix := range []string{"app=%5B&regex=app", "cursor=W10", "app=a&regex=unknown", "device=a&device=b&regex=device&regex=device"} {
		requireHTTP(t, f.call("GET", "/api/discovery/inventory?"+suffix, nil, ""), 400)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO privacy_settings(organization_id,configuration) VALUES($1,'{"aggregate_only":true}') ON CONFLICT(organization_id) DO UPDATE SET configuration=privacy_settings.configuration||excluded.configuration`, f.org); err != nil {
		t.Fatal(err)
	}
	requireHTTP(t, f.call("GET", "/api/discovery/inventory", nil, ""), 403)
}

func TestInventorySearchSourceAuthorization(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	anonymous := httptest.NewRecorder()
	f.a.Handler().ServeHTTP(anonymous, httptest.NewRequest("GET", "/api/discovery/inventory", nil))
	requireHTTP(t, anonymous, 401)
	const device = "11111111-1111-4111-8111-111111111111"
	cipher, err := f.a.sealIdentity(f.org, "device-name:"+device, "LT-PRIVATE-NAME")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(ctx, `INSERT INTO devices(organization_id,id,credential_hash,hostname,hostname_ciphertext,platform,version,status) VALUES($1,$2,$3,$4,$5,'test','test','approved')`, f.org, device, hash("inventory-source-device"), deviceAlias(device), cipher); err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(ctx, `INSERT INTO discovery_entities(organization_id,device_id,scope,id,kind,display,sequence) VALUES($1,$2,'host','process/1','process','{"name":"LT-PRIVATE-NAME","image":"private-environment-image"}',1)`, f.org, device); err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(ctx, `INSERT INTO discovery_communications(organization_id,device_id,scope,entity_id,provider,sequence,last_seen,evidence) VALUES($1,$2,'host','process/1','private.provider.invalid',1,now(),'{}')`, f.org, device); err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(ctx, `INSERT INTO discovery_identifications(organization_id,device_id,scope,entity_id,application_id,signature_id,signature_revision,state,evidence,sequence) VALUES($1,$2,'host','process/1','private-software','private.one',1,'executed','[]',1)`, f.org, device); err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(ctx, `INSERT INTO candidate_domains(organization_id,domain,count,first_seen,last_seen,status) VALUES($1,'candidate.fixture.invalid',17,now(),now(),'new')`, f.org); err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(ctx, `INSERT INTO shadow_events(organization_id,id,device_id,kind,occurred_at,provider,tool,model,action,characters,source,policy_revision,sensitivity,detector) VALUES($1,gen_random_uuid(),$2,'navigation',now()-interval '1 minute','web.fixture.invalid','chrome','','observed',0,'browser',1,'normal','presence')`, f.org, device); err != nil {
		t.Fatal(err)
	}
	other := regexTestOrganization(t, f)
	if _, err = f.admin.Exec(ctx, `SELECT set_config('milvago.organization_id',$1,false)`, other); err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(ctx, `INSERT INTO candidate_domains(organization_id,domain,count,first_seen,last_seen,status) VALUES($1,'foreign.fixture.invalid',91,now(),now(),'new')`, other); err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(ctx, `SELECT set_config('milvago.organization_id',$1,false)`, f.org); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"LT-PRIVATE-NAME", "private-environment-image", "private.provider.invalid"} {
		aliases := f.call("GET", "/api/discovery/inventory?query="+url.QueryEscape(value)+"&regex=query&identity=aliases", nil, "")
		requireHTTP(t, aliases, 200)
		if !strings.Contains(aliases.Body.String(), `"total":0`) {
			t.Fatal("alias projection exposed protected local environment metadata")
		}
	}
	for _, test := range []struct {
		role         string
		permissions  []string
		names        []string
		deviceStatus int
	}{
		{"inventory-local", []string{permDiscoveryRead}, []string{"private-software"}, 403},
		{"inventory-web", []string{permPolicyManage, permDevicesRead}, []string{"candidate.fixture.invalid", "web.fixture.invalid"}, 200},
		{"inventory-none", []string{permDevicesRead}, nil, 403},
	} {
		if _, err = f.admin.Exec(ctx, `INSERT INTO roles(organization_id,name,permissions) VALUES($1,$2,$3)`, f.org, test.role, test.permissions); err != nil {
			t.Fatal(err)
		}
		if _, err = f.admin.Exec(ctx, `UPDATE memberships SET role=$1 WHERE organization_id=$2 AND user_id=$3`, test.role, f.org, f.user); err != nil {
			t.Fatal(err)
		}
		w := f.call("GET", "/api/discovery/inventory", nil, "")
		if test.names == nil {
			requireHTTP(t, w, 403)
			continue
		}
		requireHTTP(t, w, 200)
		var page struct {
			Items []struct {
				ID string `json:"id"`
			} `json:"items"`
			Total int `json:"total"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		if page.Total != len(test.names) || len(page.Items) != len(test.names) {
			t.Fatalf("%s: %s", test.role, w.Body.String())
		}
		for _, item := range page.Items {
			found := false
			for _, name := range test.names {
				found = found || name == item.ID
			}
			if !found {
				t.Fatalf("unauthorized inventory source: %s", item.ID)
			}
		}
		requireHTTP(t, f.call("GET", "/api/discovery/inventory?device=LT-PRIVATE&regex=device", nil, ""), test.deviceStatus)
		if test.role == "inventory-local" {
			hiddenName := f.call("GET", "/api/discovery/inventory?query=LT-PRIVATE&regex=query", nil, "")
			requireHTTP(t, hiddenName, 200)
			if !strings.Contains(hiddenName.Body.String(), `"total":0`) {
				t.Fatal("unqualified query bypassed device permission")
			}
			for _, value := range []string{"private-environment-image", "private.provider.invalid"} {
				hidden := f.call("GET", "/api/discovery/inventory?query="+url.QueryEscape(value)+"&regex=query", nil, "")
				requireHTTP(t, hidden, 200)
				if !strings.Contains(hidden.Body.String(), `"total":0`) {
					t.Fatal("unqualified query exposed protected environment or communication metadata")
				}
			}
			requireHTTP(t, f.call("GET", "/api/discovery/inventory?environment=LT-PRIVATE&regex=environment", nil, ""), 403)
			requireHTTP(t, f.call("GET", "/api/discovery/inventory?service=private&regex=service", nil, ""), 403)
		}
	}
}

func TestInventorySearchNameFleetLimit(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	if _, err := f.admin.Exec(ctx, `INSERT INTO devices(organization_id,id,credential_hash,hostname,platform,version,status)
 SELECT $1,md5('inventory-name-limit-'||n)::uuid,decode(md5('inventory-name-key-'||n)||md5('inventory-name-key-2-'||n),'hex'),'Synthetic alias','test','test','approved' FROM generate_series(1,10001) n`, f.org); err != nil {
		t.Fatal(err)
	}
	w := f.call("GET", "/api/discovery/inventory?query=impossible-name&regex=query", nil, "")
	requireHTTP(t, w, 413)
	if strings.Contains(w.Body.String(), `"items"`) {
		t.Fatal("oversized fleet returned a partial inventory")
	}
}
