package app

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"testing"
	"time"
)

func TestShadowRegexReadBudget(t *testing.T) {
	if os.Getenv("MILVAGO_REGEX_LOAD") != "1" {
		t.Skip("requires the bounded million-event regex fixture")
	}
	f := newObservabilityFixture(t)
	ctx := context.Background()
	if _, err := f.admin.Exec(ctx, `INSERT INTO devices(organization_id,id,credential_hash,hostname,platform,version,status)
SELECT $1,md5('regex-device-'||n)::uuid,decode(md5('regex-secret-'||n)||md5('regex-secret-'||n),'hex'),'Synthetic device '||n,'test','test','approved' FROM generate_series(1,1000)n`, f.org); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO shadow_events(organization_id,device_id,id,occurred_at,kind,provider,tool,source,action,policy_revision,characters,labels,sensitivity)
SELECT $1,md5('regex-device-'||((n-1)%1000+1))::uuid,md5('regex-event-'||n)::uuid,now()-n*interval '1 millisecond',CASE WHEN n%1000=0 THEN 'prompt' ELSE 'navigation' END,
'service-'||(n%40)||'.example.invalid','chrome','browser','observed',1,12,'[]','normal' FROM generate_series(1,1000000)n`, f.org); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `ANALYZE shadow_events; ANALYZE devices`); err != nil {
		t.Fatal(err)
	}
	q := url.Values{"provider": {"^service-0[.]example[.]invalid$"}, "regex": {"provider"}, "limit": {"25"}}
	start := time.Now()
	w := f.call("GET", "/api/shadow/conversations?"+q.Encode(), nil, "")
	elapsed := time.Since(start)
	requireHTTP(t, w, 200)
	var result struct {
		Items []json.RawMessage `json:"items"`
		Total int               `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Total != 1000 || len(result.Items) != 25 {
		t.Fatalf("regex lost exact counts: total=%d page=%d", result.Total, len(result.Items))
	}
	if elapsed > 5*time.Second {
		t.Fatalf("million-event regex read took %s", elapsed)
	}
	t.Logf("regex read: events=1000000 devices=1000 matching_threads=%d page=%d elapsed=%s", result.Total, len(result.Items), elapsed)
	for _, pattern := range []string{"^chrome$", "^synthetic-no-match$"} {
		q = url.Values{"query": {pattern}, "regex": {"query"}, "limit": {"25"}}
		start = time.Now()
		w = f.call("GET", "/api/shadow/conversations?"+q.Encode(), nil, "")
		elapsed = time.Since(start)
		requireHTTP(t, w, 200)
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		want := 0
		if pattern == "^chrome$" {
			want = 1000
		}
		if result.Total != want || len(result.Items) != min(25, want) {
			t.Fatalf("global search counts: %#v", result)
		}
		if elapsed > 5*time.Second {
			t.Fatalf("global regex took %s", elapsed)
		}
		t.Logf("global regex: events=1000000 pattern=%s total=%d elapsed=%s", pattern, result.Total, elapsed)
	}
}
