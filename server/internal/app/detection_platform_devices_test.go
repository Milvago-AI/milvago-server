package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// The known-platform half of Discovery names the machines that reached a platform, in
// both editions. Same gates as the candidate drill-down,
// different records: presence events carry the machine on the row.
func TestKnownPlatformDevices(t *testing.T) {
	p := newProjectionFixture(t)
	ctx := context.Background()
	const host = "aggregator.example.invalid"
	for i := 0; i < 3; i++ {
		if _, e := p.admin.Exec(ctx, `INSERT INTO shadow_events(organization_id,device_id,id,occurred_at,kind,provider,tool,source,action,policy_revision,characters,sensitivity,detector)
 VALUES($1,$2,gen_random_uuid(),now(),'navigation',$3,'chrome','browser','observed',1,0,'normal','presence')`, p.org, p.device, host); e != nil {
			t.Fatal(e)
		}
	}
	read := func(t *testing.T, path string) map[string]any {
		t.Helper()
		w := p.as("owner", "GET", path, nil)
		requireHTTP(t, w, 200)
		var body map[string]any
		if e := json.Unmarshal(w.Body.Bytes(), &body); e != nil {
			t.Fatal(e)
		}
		return body
	}
	t.Run("names the machine and counts its visits", func(t *testing.T) {
		body := read(t, "/api/detection/platforms/"+host+"/devices")
		items, _ := body["items"].([]any)
		if len(items) != 1 {
			t.Fatalf("expected one machine, got %v", body["items"])
		}
		row := items[0].(map[string]any)
		if row["hostname"] != p.s.host {
			t.Fatalf("hostname %v, want the fixture machine name", row["hostname"])
		}
		if row["observations"].(float64) != 3 {
			t.Fatalf("visits %v, want the three presence records", row["observations"])
		}
		// The window is the organization's own retention, said out loud rather than implied.
		if body["window_days"].(float64) <= 0 {
			t.Fatalf("window_days %v, want the retention of this organization", body["window_days"])
		}
	})
	t.Run("answers aliases when the reader asked for aliases", func(t *testing.T) {
		body := read(t, "/api/detection/platforms/"+host+"/devices?identity=aliases")
		row := body["items"].([]any)[0].(map[string]any)
		if row["hostname"] != deviceAlias(p.device) {
			t.Fatalf("hostname %v, want the device alias", row["hostname"])
		}
	})
	// Capture wins over presence, so a covered provider never reaches Discovery; and a
	// silenced platform left the screen on purpose. Neither may be asked for by hand.
	t.Run("refuses a provider this edition captures", func(t *testing.T) {
		requireHTTP(t, p.as("owner", "GET", "/api/detection/platforms/chatgpt.com/devices", nil), 404)
	})
	// A platform an organization silenced is covered by the same `discoveryExclusions`
	// call as the covered provider above, and TestMutingAPlatformHidesItFromDiscovery…
	// already proves the muting half; it is not repeated here.
	t.Run("aggregate-only reporting never names a machine", func(t *testing.T) {
		if _, e := p.admin.Exec(ctx, `INSERT INTO privacy_settings(organization_id) VALUES($1) ON CONFLICT DO NOTHING`, p.org); e != nil {
			t.Fatal(e)
		}
		if tag, e := p.admin.Exec(ctx, `UPDATE privacy_settings SET configuration=configuration||'{"aggregate_only":true}'::jsonb WHERE organization_id=$1`, p.org); e != nil || tag.RowsAffected() != 1 {
			t.Fatal("privacy fixture missing", e)
		}
		w := p.as("owner", "GET", "/api/detection/platforms/"+host+"/devices", nil)
		requireHTTP(t, w, 403)
		if !strings.Contains(w.Body.String(), "aggregate_only") {
			t.Fatalf("unexpected refusal: %s", w.Body.String())
		}
	})
}
