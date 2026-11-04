package app

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestShadowRegexHTTPAndTenantIsolation(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	other := regexTestOrganization(t, f)
	device := "11111111-1111-4111-8111-111111111111"
	foreign := "22222222-2222-4222-8222-222222222222"
	for _, item := range []struct{ org, id string }{{f.org, device}, {other, foreign}} {
		if _, err := f.admin.Exec(ctx, `SELECT set_config('milvago.organization_id',$1,false)`, item.org); err != nil {
			t.Fatal(err)
		}
		if _, err := f.admin.Exec(ctx, `INSERT INTO devices(organization_id,id,credential_hash,hostname,platform,version,status) VALUES($1,$2,$3,'Synthetic alias','test','test','approved')`, item.org, item.id, hash("regex-fixture-"+item.id)); err != nil {
			t.Fatal(err)
		}
	}
	for i, item := range []struct{ org, device, provider, model string }{
		{f.org, device, "chatgpt.com", "gpt-4.1"},
		{f.org, device, "CHATGPT.COM", "gpt-5.6"},
		{f.org, device, "claude.ai", "claude-4.5"},
		{f.org, device, "synthetic.example.invalid", "synthetic-model"},
		{other, foreign, "chatgpt.com", "gpt-4.1"},
	} {
		if _, err := f.admin.Exec(ctx, `SELECT set_config('milvago.organization_id',$1,false)`, item.org); err != nil {
			t.Fatal(err)
		}
		if _, err := f.admin.Exec(ctx, `INSERT INTO shadow_events(organization_id,id,device_id,kind,occurred_at,provider,tool,model,action,characters,source,policy_revision,sensitivity) VALUES($1,gen_random_uuid(),$2,'prompt',$3,$4,'chrome',$5,'observed',12,'browser',1,'normal')`, item.org, item.device, time.Now().Add(-time.Duration(i+1)*time.Minute), item.provider, item.model); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.admin.Exec(ctx, `SELECT set_config('milvago.organization_id',$1,false)`, f.org); err != nil {
		t.Fatal(err)
	}
	unauthenticated := httptest.NewRecorder()
	f.a.Handler().ServeHTTP(unauthenticated, httptest.NewRequest("GET", "/api/shadow/events?provider=chatgpt&regex=provider", nil))
	requireHTTP(t, unauthenticated, 401)
	for _, test := range []struct {
		q     url.Values
		count int
	}{
		{url.Values{"provider": {"chatgpt"}, "regex": {"provider"}}, 2},
		{url.Values{"provider": {"CHATGPT"}, "regex": {"provider"}}, 2},
		{url.Values{"provider": {"(chatgpt|claude)"}, "regex": {"provider"}}, 3},
		{url.Values{"provider": {"chatgpt"}}, 0},
		{url.Values{"provider": {"chatgpt.com"}}, 1},
		{url.Values{"model": {`^gpt-5\.[0-9]+$`}, "regex": {"model"}}, 1},
		{url.Values{"device_id": {"^1111"}, "regex": {"device_id"}}, 4},
		{url.Values{"query": {"chatgpt|claude"}, "regex": {"query"}}, 3},
	} {
		w := f.call("GET", "/api/shadow/events?"+test.q.Encode(), nil, "")
		requireHTTP(t, w, 200)
		var result struct {
			Items []struct {
				Device string `json:"device_id"`
			} `json:"items"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if len(result.Items) != test.count {
			t.Fatalf("%s: %d events, want %d", test.q.Encode(), len(result.Items), test.count)
		}
		for _, item := range result.Items {
			if item.Device != device {
				t.Fatal("regex escaped tenant isolation")
			}
		}
	}
	saved := f.call("POST", "/api/shadow/filters", map[string]any{"name": "Synthetic regex view", "criteria": map[string]any{"provider": []string{"chatgpt"}, "regex": []string{"provider"}}}, f.csrf)
	requireHTTP(t, saved, 201)
	views := f.call("GET", "/api/shadow/filters", nil, "")
	requireHTTP(t, views, 200)
	var stored struct {
		Items []struct {
			Criteria struct {
				Regex    []string `json:"regex"`
				Provider []string `json:"provider"`
			} `json:"criteria"`
		} `json:"items"`
	}
	if err := json.Unmarshal(views.Body.Bytes(), &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored.Items) != 1 || len(stored.Items[0].Criteria.Regex) != 1 || stored.Items[0].Criteria.Regex[0] != "provider" || len(stored.Items[0].Criteria.Provider) != 1 || stored.Items[0].Criteria.Provider[0] != "chatgpt" {
		t.Fatal("saved view lost the validated regex scope")
	}
	for _, path := range []string{"/api/shadow/events?provider=%5B&regex=provider", "/api/shadow/conversations?provider=%5B&regex=provider", "/api/shadow/cartography?provider=%5B&regex=provider"} {
		w := f.call("GET", path, nil, "")
		requireHTTP(t, w, 400)
		var result struct {
			Code string `json:"error"`
		}
		if json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Code != "invalid_search_regex" {
			t.Fatal("invalid regex did not return a stable localized error code")
		}
	}
}
