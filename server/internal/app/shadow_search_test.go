package app

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestShadowRegexEveryStructuredFilter(t *testing.T) {
	for _, key := range shadowRegexFields {
		if key == "sensitivity" && Edition != "commercial" {
			continue
		}
		f, err := parseShadowFilter(url.Values{key: {"(alpha|beta)"}, "regex": {key}})
		if err != nil {
			t.Fatalf("%s rejected regex: %v", key, err)
		}
		if strings.Contains(f.Where, "(alpha|beta)") {
			t.Fatalf("%s interpolated user text", key)
		}
	}
	if Edition != "commercial" {
		if _, err := parseShadowFilter(url.Values{"sensitivity": {"sensitive"}, "regex": {"sensitivity"}}); err == nil {
			t.Fatal("regex bypassed the edition capability")
		}
	}
}

func TestShadowRegexMachineNameAndGlobalMetadataHTTP(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	device := "33333333-3333-4333-8333-333333333333"
	cipher, err := f.a.sealIdentity(f.org, "device-name:"+device, "LT-COM-SYNTHETIC")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(ctx, "INSERT INTO devices(organization_id,id,credential_hash,hostname,hostname_ciphertext,platform,version,status) VALUES($1,$2,$3,$4,$5,'test','test','approved')", f.org, device, hash("synthetic-search-device"), deviceAlias(device), cipher); err != nil {
		t.Fatal(err)
	}
	event := "44444444-4444-4444-8444-444444444444"
	if _, err = f.admin.Exec(ctx, `INSERT INTO shadow_events(organization_id,id,device_id,kind,occurred_at,provider,tool,model,action,characters,source,policy_revision,sensitivity,labels) VALUES($1,$2,$3,'prompt',now()-interval '1 minute','chatgpt.com','chrome','gpt-5','blocked',12,'browser',1,'normal','["synthetic-label"]')`, f.org, event, device); err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(ctx, `INSERT INTO dlp_policy_snapshots(organization_id,fingerprint,policy) VALUES($1,repeat('a',64),'{}')`, f.org); err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(ctx, `INSERT INTO dlp_decisions(organization_id,device_id,event_id,channel,policy_fingerprint,action,delivery,decisions,expires_at) VALUES($1,$2,$3,'browser',repeat('a',64),'block','not_sent','[{"rule_id":"synthetic-rule-one","mode":"active","consequence":"block","outcome":"blocked"},{"rule_id":"synthetic-rule-two","mode":"simulation","consequence":"warn","outcome":"simulated"}]',now()+interval '1 hour')`, f.org, device, event); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		key, value string
		count      int
	}{
		{"device_name", "LT-COM", 1}, {"device_name", "^lt-com-", 1},
		{"device_name", "^LT-NONE", 0}, {"query", "LT-COM", 1},
		{"query", "^blocked$", 1}, {"query", "synthetic-label", 1},
		{"action", "block|redirect", 1}, {"kind", "^pro", 1},
		{"attachment", "^n", 1}, {"query", "^no$", 1},
		{"dlp_rule", "rule-one$", 1}, {"dlp_mode", "^act", 1},
		{"dlp_consequence", "block|warn", 1}, {"dlp_outcome", "block|sim", 1},
		{"query", "rule-two$", 1}, {"actor_id", "^unknown$", 1},
	} {
		q := url.Values{test.key: {test.value}, "regex": {test.key}}
		w := f.call("GET", "/api/shadow/events?"+q.Encode(), nil, "")
		requireHTTP(t, w, 200)
		var result struct {
			Items []struct {
				ID string `json:"id"`
			} `json:"items"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if len(result.Items) != test.count {
			t.Fatalf("%s: got %d, want %d", q.Encode(), len(result.Items), test.count)
		}
		if test.count == 1 && result.Items[0].ID != event {
			t.Fatal("unexpected matching event")
		}
	}
	// Separate decision objects must not satisfy different categories together.
	wMixed := f.call("GET", "/api/shadow/events?dlp_rule=rule-one$&regex=dlp_rule&dlp_mode=simulation&regex=dlp_mode", nil, "")
	requireHTTP(t, wMixed, 200)
	var mixed struct {
		Items []any `json:"items"`
	}
	if err := json.Unmarshal(wMixed.Body.Bytes(), &mixed); err != nil || len(mixed.Items) != 0 {
		t.Fatal("DLP categories crossed decision boundaries")
	}
	for _, key := range []string{"device_name", "action", "kind", "attachment", "actor_id", "dlp_rule", "dlp_mode", "dlp_consequence", "dlp_outcome"} {
		q := url.Values{key: {"["}, "regex": {key}}
		w := f.call("GET", "/api/shadow/events?"+q.Encode(), nil, "")
		requireHTTP(t, w, 400)
	}
	// A name hidden by the aliases-only projection must not become a search oracle.
	w := f.call("GET", "/api/shadow/events?device_name=LT-COM&regex=device_name&identity=aliases", nil, "")
	requireHTTP(t, w, 200)
	var result struct {
		Items []any `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || len(result.Items) != 0 {
		t.Fatal("alias projection searched a sealed machine name")
	}
	for _, route := range []string{"conversations", "cartography"} {
		w := f.call("GET", "/api/shadow/"+route+"?device_name=LT-COM&regex=device_name", nil, "")
		requireHTTP(t, w, 200)
	}
	for _, route := range []string{"conversations", "cartography"} {
		w := f.call("GET", "/api/shadow/"+route+"?query=synthetic-label&regex=query", nil, "")
		requireHTTP(t, w, 200)
		if route == "cartography" {
			var mapResult struct {
				Totals struct {
					Requests int `json:"requests"`
				} `json:"totals"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &mapResult); err != nil || mapResult.Totals.Requests != 1 {
				t.Fatalf("global map result differs: %v", err)
			}
		}
	}
	var audited int
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM audit WHERE organization_id=$1 AND action='subject.view' AND details->'regex_search'->'actor_id' @> '["^unknown$"]'`, f.org).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("person regex audit missing: %d / %v", audited, err)
	}
	w = f.call("GET", "/api/shadow/events?actor_id=%5Eunknown%24&regex=actor_id", nil, "")
	requireHTTP(t, w, 200)
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM audit WHERE organization_id=$1 AND action='subject.view' AND details->'regex_search'->'actor_id' @> '["^unknown$"]'`, f.org).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("person regex audit did not deduplicate: %d / %v", audited, err)
	}
}
