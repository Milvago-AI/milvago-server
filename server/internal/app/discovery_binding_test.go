package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestDiscoverySystemBindingIsPublicScopedAndDoesNotEnableSources(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	var device string
	if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status) VALUES($1,$2,'Synthetic Linux host','linux','0.7.0','approved') RETURNING id`, f.org, hash(randomToken())).Scan(&device); err != nil {
		t.Fatal(err)
	}
	path := "/api/discovery/devices/" + device + "/system-binding"
	response := f.call("GET", path, nil, "")
	requireHTTP(t, response, 200)
	var binding map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &binding); err != nil {
		t.Fatal(err)
	}
	if len(binding) != 4 || binding["version"] != float64(1) || binding["device_id"] != device || binding["public_key"] == "" || binding["server_url"] == "" {
		t.Fatal("invalid public binding")
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("binding was cacheable")
	}
	var count int
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM discovery_settings WHERE organization_id=$1`, f.org).Scan(&count); err != nil || count != 0 {
		t.Fatal("export changed collection settings", err)
	}
	requireHTTP(t, f.call("GET", "/api/discovery/devices/not-an-id/system-binding", nil, ""), 400)
	requireHTTP(t, f.call("GET", "/api/discovery/devices/11111111-1111-4111-8111-111111111111/system-binding", nil, ""), 404)
	for _, platform := range []string{"linux", "windows"} {
		if _, err := f.admin.Exec(ctx, `UPDATE devices SET platform=$3 WHERE organization_id=$1 AND id=$2`, f.org, device, platform); err != nil {
			t.Fatal(err)
		}
		response := f.call("GET", path, nil, "")
		requireHTTP(t, response, 200)
		if err := json.Unmarshal(response.Body.Bytes(), &binding); err != nil || len(binding) != 4 || binding["device_id"] != device || !strings.Contains(response.Header().Get("Content-Disposition"), "milvago-"+platform+"-binding.json") {
			t.Fatal("binding is not scoped to the supported endpoint platform", err)
		}
	}
	if _, err := f.admin.Exec(ctx, `UPDATE devices SET platform='darwin' WHERE organization_id=$1 AND id=$2`, f.org, device); err != nil {
		t.Fatal(err)
	}
	requireHTTP(t, f.call("GET", path, nil, ""), 409)
	if _, err := f.admin.Exec(ctx, `UPDATE devices SET platform='linux' WHERE organization_id=$1 AND id=$2`, f.org, device); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO privacy_settings(organization_id,configuration) VALUES($1,'{"aggregate_only":true}') ON CONFLICT(organization_id) DO UPDATE SET configuration=privacy_settings.configuration||excluded.configuration`, f.org); err != nil {
		t.Fatal(err)
	}
	requireHTTP(t, f.call("GET", path, nil, ""), 403)
	if _, err := f.admin.Exec(ctx, `DELETE FROM privacy_settings WHERE organization_id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `UPDATE memberships SET role='reporter' WHERE user_id=$1 AND organization_id=$2`, f.user, f.org); err != nil {
		t.Fatal(err)
	}
	requireHTTP(t, f.call("GET", path, nil, ""), 403)
}
