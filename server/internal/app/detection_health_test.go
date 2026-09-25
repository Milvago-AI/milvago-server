package app

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestDetectorState(t *testing.T) {
	for _, test := range []struct {
		name   string
		sample detectorSample
		want   string
	}{
		{"unvisited provider is unmeasured", detectorSample{Devices: 2, Navigations: 40, Network: 40, DOM: 0}, "insufficient_data"},
		{"visited but silent without history", detectorSample{Devices: 3, Navigations: 9}, "insufficient_data"},
		{"visited, silent, used to capture", detectorSample{Devices: 3, Navigations: 9, Previous: 12}, "suspect"},
		{"dom keeps up", detectorSample{Devices: 3, Navigations: 9, Network: 10, DOM: 9}, "ok"},
		{"dom at the threshold", detectorSample{Devices: 3, Navigations: 9, Network: 10, DOM: 2}, "ok"},
		{"dom under the threshold", detectorSample{Devices: 3, Navigations: 9, Network: 10, DOM: 1}, "degraded_dom"},
		{"network rule missing", detectorSample{Devices: 3, Navigations: 9, Network: 0, DOM: 7}, "dom_only"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := detectorState(test.sample, 3, 20); got != test.want {
				t.Fatalf("%+v: %s, want %s", test.sample, got, test.want)
			}
		})
	}
	if detectorState(detectorSample{Devices: 1, Navigations: 1, Network: 1, DOM: 1}, 1, 20) != "ok" {
		t.Fatal("a threshold of one device must give a verdict on one device")
	}
}

type detectorHealthFixture struct {
	f       *observabilityFixture
	ctx     context.Context
	devices []string
}

type detectorHealthBatch struct {
	device                    string
	revision                  int
	receivedAgo               time.Duration
	provider                  string
	navigations, network, dom int
}

func newDetectorHealthFixture(t *testing.T) detectorHealthFixture {
	t.Helper()
	f := newObservabilityFixture(t)
	ctx := context.Background()
	if tag, err := f.admin.Exec(ctx, "UPDATE sessions SET mfa_verified_at=clock_timestamp() WHERE token_hash=$1", hash(f.owner.Value)); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("fresh authentication fixture missing", err)
	}
	devices := []string{}
	for i := 0; i < 3; i++ {
		var id string
		if err := f.admin.QueryRow(ctx, "INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status) VALUES($1,$2,$3,'test','0.5.0','approved') RETURNING id", f.org, hash(randomToken()), fmt.Sprintf("device-%d", i)).Scan(&id); err != nil {
			t.Fatal(err)
		}
		devices = append(devices, id)
	}
	return detectorHealthFixture{f: f, ctx: ctx, devices: devices}
}

func (fixture detectorHealthFixture) report(t *testing.T) map[string]any {
	t.Helper()
	w := fixture.f.call("GET", "/api/detection/health", nil, "")
	requireHTTP(t, w, 200)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func detectorHealthState(t *testing.T, out map[string]any, provider string, revision float64) string {
	t.Helper()
	for _, raw := range out["items"].([]any) {
		item := raw.(map[string]any)
		if item["provider"] == provider && item["catalog_revision"] == revision {
			return item["state"].(string)
		}
	}
	t.Fatalf("no row for %s revision %v: %v", provider, revision, out["items"])
	return ""
}

func (fixture detectorHealthFixture) batch(t *testing.T, sample detectorHealthBatch) {
	t.Helper()
	end := time.Now().Add(-sample.receivedAgo)
	payload, _ := json.Marshal(map[string]any{"id": randomToken(), "tool": "chrome", "extension_version": "0.5.0", "catalog_revision": sample.revision, "catalog_state": "ok",
		"window_start": end.Add(-time.Hour), "window_end": end,
		"providers": []map[string]any{{"provider": sample.provider, "navigations": sample.navigations, "prompts_network": sample.network, "prompts_dom": sample.dom, "responses_dom": sample.dom, "candidates": 0}}, "candidates": []any{}})
	if _, err := fixture.f.admin.Exec(fixture.ctx, "INSERT INTO detector_health(organization_id,device_id,id,payload,received_at) VALUES($1,$2,gen_random_uuid(),$3,$4)", fixture.f.org, sample.device, payload, end); err != nil {
		t.Fatal(err)
	}
}

func (fixture detectorHealthFixture) assertSilent(t *testing.T) {
	out := fixture.report(t)
	transport := out["transport"].(map[string]any)
	if transport["state"] != "no_transport" || transport["devices_approved"].(float64) != 3 || transport["devices_reporting"].(float64) != 0 {
		t.Fatal("silent fleet misreported", transport)
	}
	if len(out["items"].([]any)) != 0 {
		t.Fatal("no batch, no verdict", out["items"])
	}
}

func (fixture detectorHealthFixture) assertVerdicts(t *testing.T) {
	// Two devices on revision 7: below the default threshold of three.
	fixture.batch(t, detectorHealthBatch{fixture.devices[0], 7, time.Hour, "claude", 5, 10, 1})
	fixture.batch(t, detectorHealthBatch{fixture.devices[1], 7, time.Hour, "claude", 5, 10, 1})
	out := fixture.report(t)
	if detectorHealthState(t, out, "claude", 7) != "insufficient_data" {
		t.Fatal("two devices must not yield a verdict at threshold three", out)
	}
	if out["transport"].(map[string]any)["state"] != "partial" {
		t.Fatal("two of three devices reporting is partial", out["transport"])
	}
	// A third device: the DOM captured one prompt for twenty network prompts.
	fixture.batch(t, detectorHealthBatch{fixture.devices[2], 7, time.Hour, "claude", 5, 10, 1})
	out = fixture.report(t)
	if detectorHealthState(t, out, "claude", 7) != "degraded_dom" {
		t.Fatal("dom at ten percent of network must be degraded", out)
	}
	// Revision 8 on the same devices behaves: both revisions are reported apart.
	for _, device := range fixture.devices {
		fixture.batch(t, detectorHealthBatch{device, 8, 30 * time.Minute, "claude", 5, 10, 9})
	}
	out = fixture.report(t)
	if detectorHealthState(t, out, "claude", 8) != "ok" || detectorHealthState(t, out, "claude", 7) != "degraded_dom" {
		t.Fatal("revisions must be judged separately", out)
	}
	// A provider only captured by the DOM has no network rule in force.
	for _, device := range fixture.devices {
		fixture.batch(t, detectorHealthBatch{device, 8, 30 * time.Minute, "gemini", 4, 0, 6})
	}
	if detectorHealthState(t, fixture.report(t), "gemini", 8) != "dom_only" {
		t.Fatal("dom-only capture must be named")
	}
	// Visited, nothing captured now, captured last week: suspect.
	for _, device := range fixture.devices {
		fixture.batch(t, detectorHealthBatch{device, 8, 3 * 24 * time.Hour, "chatgpt", 4, 6, 6})
		fixture.batch(t, detectorHealthBatch{device, 8, 30 * time.Minute, "chatgpt", 4, 0, 0})
	}
	if detectorHealthState(t, fixture.report(t), "chatgpt", 8) != "suspect" {
		t.Fatal("a provider that stopped capturing must be suspect")
	}
	if fixture.report(t)["transport"].(map[string]any)["state"] != "ok" {
		t.Fatal("every approved device reported")
	}
}

func (fixture detectorHealthFixture) assertLateDelivery(t *testing.T) {
	for _, device := range fixture.devices {
		fixture.batch(t, detectorHealthBatch{device, 99, 72 * time.Hour, "late-provider", 4, 9, 9})
		fixture.batch(t, detectorHealthBatch{device, 99, time.Hour, "late-provider", 4, 0, 0})
	}
	tag, err := fixture.f.admin.Exec(fixture.ctx, "UPDATE detector_health SET received_at=clock_timestamp() WHERE (payload->>'catalog_revision')::int=99")
	if err != nil || tag.RowsAffected() != 6 {
		t.Fatal("late receipt fixture missing", err)
	}
	if detectorHealthState(t, fixture.report(t), "late-provider", 99) != "suspect" {
		t.Fatal("receipt time counted old prompts as current")
	}
}

func (fixture detectorHealthFixture) assertThresholds(t *testing.T) {
	cfg := defaultPrivacy()
	cfg.HealthMinDevices = 1
	cfg.HealthDOMRatio = 5
	requireHTTP(t, putPrivacyTest(t, fixture.f, cfg), 200)
	out := fixture.report(t)
	if out["thresholds"].(map[string]any)["min_devices"].(float64) != 1 || detectorHealthState(t, out, "claude", 7) != "ok" {
		t.Fatal("a five percent threshold must accept ten percent", out)
	}
	cfg.HealthWindowHours = 0
	requireHTTP(t, putPrivacyTest(t, fixture.f, cfg), 400)
}

// TestDetectorHealthReport drives the health route with synthetic heartbeat
// batches: the verdict must follow the number of devices that navigated, the
// catalogue revision must stay separate, and a fleet that sent nothing must be
// reported as silent rather than as zero prompts.
func TestDetectorHealthReport(t *testing.T) {
	fixture := newDetectorHealthFixture(t)
	t.Run("silent fleet is no transport", fixture.assertSilent)
	t.Run("verdicts follow devices and revision", fixture.assertVerdicts)
	t.Run("late delivery keeps its observation window", fixture.assertLateDelivery)
	t.Run("thresholds are the organization's", fixture.assertThresholds)
}
