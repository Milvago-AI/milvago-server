package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestLegacyConversationPageMetadataBounded(t *testing.T) {
	f, subject, device := privacyFixture(t)
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	_, err := f.admin.Exec(ctx, `INSERT INTO shadow_events(organization_id,device_id,id,occurred_at,kind,provider,tool,source,action,policy_revision,characters,sensitivity,collaborator_id,conversation_id,url)
	 SELECT $1,$2,gen_random_uuid(),$4::timestamptz+i*interval '1 millisecond',CASE WHEN i%2=1 THEN 'prompt' ELSE 'response' END,
	 'claude.ai','chrome','browser','observed',1,42,'unknown',$3,'synthetic-paged-'||((i-1)/2)::text,
	 'https://synthetic.invalid/'||repeat(md5(i::text),30) FROM generate_series(1,16000) i`, f.org, device, subject, base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(ctx, `VACUUM ANALYZE shadow_events`); err != nil {
		t.Fatal(err)
	}
	trace, restore := traceDataReadFixture(t, f)
	defer restore()
	items, total := readConversationPage(t, f, "?limit=20")
	if len(items) != 20 || total != 8000 {
		t.Fatalf("legacy page/total: %d/%d", len(items), total)
	}
	trace.Lock()
	queries := append([]*dataReadTraceEntry{}, trace.queries...)
	trace.Unlock()
	var query *dataReadTraceEntry
	for _, entry := range queries {
		if strings.HasPrefix(entry.sql, "WITH candidate_events") {
			query = entry
		}
	}
	if query == nil {
		t.Fatal("missing bounded legacy page query")
	}
	tx, err := tenantTx(ctx, f.a.db, f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SET LOCAL jit=off; SET LOCAL plan_cache_mode=force_custom_plan`); err != nil {
		t.Fatal(err)
	}
	var raw json.RawMessage
	if err = tx.QueryRow(ctx, `EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) `+query.sql, query.args...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var plans []struct {
		Plan          map[string]any
		ExecutionTime float64 `json:"Execution Time"`
	}
	if err = json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 {
		t.Fatalf("missing legacy plan: %v", err)
	}
	pageRows, metadataRows := -1.0, -1.0
	var visit func(map[string]any)
	visit = func(node map[string]any) {
		if node["Subplan Name"] == "CTE list_page" {
			pageRows, _ = node["Actual Rows"].(float64)
		}
		if node["Subplan Name"] == "CTE page_keys" {
			metadataRows, _ = node["Actual Rows"].(float64)
		}
		children, _ := node["Plans"].([]any)
		for _, child := range children {
			visit(child.(map[string]any))
		}
	}
	visit(plans[0].Plan)
	hits, _ := plans[0].Plan["Shared Hit Blocks"].(float64)
	reads, _ := plans[0].Plan["Shared Read Blocks"].(float64)
	t.Logf("8000 legacy groups: selected=%.0f metadata=%.0f logical=%.0f SQL=%.3fms", pageRows, metadataRows, hits+reads, plans[0].ExecutionTime)
	if pageRows != 21 || metadataRows != 42 || hits+reads > 10000 {
		t.Fatalf("legacy metadata must be bounded by page size: selected=%.0f metadata=%.0f logical=%.0f", pageRows, metadataRows, hits+reads)
	}
}

func TestLegacyConversationPageCorrelationAndFilters(t *testing.T) {
	f, subject, device := privacyFixture(t)
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	addThreadEvent(t, f, subject, device, threadEvent{base.Add(-48 * time.Hour), "prompt", "", "synthetic-opening", "observed", ""})
	addThreadEvent(t, f, subject, device, threadEvent{base, "navigation", "synthetic-thread", "synthetic-opening", "observed", ""})
	id := addThreadEvent(t, f, subject, device, threadEvent{base.Add(time.Second), "response", "synthetic-thread", "", "observed", ""})
	setModel(t, f, id, "Synthetic selected model", "")
	for _, criteria := range []string{"", "&kind=response", "&model=Synthetic+selected+model"} {
		items, total := readConversationPage(t, f, "?limit=20"+criteria)
		if len(items) != 1 || total != 1 || items[0].Key != "conv:synthetic-thread" || items[0].Prompts != 0 || items[0].Responses != 1 {
			t.Fatalf("record-filtered counters changed for %q: %d/%d %+v", criteria, len(items), total, items)
		}
	}
	items, total := readConversationPage(t, f, "?limit=20&kind=navigation")
	if len(items) != 0 || total != 0 {
		t.Fatal("a navigation-only filtered group became a conversation")
	}
}

func TestLegacyConversationPageStorageIsolation(t *testing.T) {
	f, subject, device := privacyFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Add(-time.Minute)
	addThreadEvent(t, f, subject, device, threadEvent{now, "prompt", "synthetic-correlated", "synthetic-correlation", "observed", ""})
	var safe int
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
	 WHERE n.nspname='public' AND p.proname IN ('milvago_conversation_candidates','milvago_conversation_correlation_keys','milvago_conversation_scope_headers')
	 AND p.provolatile='s' AND p.proisstrict AND NOT p.prosecdef
	 AND p.proconfig @> ARRAY['search_path=pg_catalog, public','enable_sort=off']
	 AND NOT EXISTS(SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE')
	 AND NOT has_function_privilege('milvago_lookup',p.oid,'EXECUTE') AND has_function_privilege($1,p.oid,'EXECUTE')`, f.a.config.RuntimeRole).Scan(&safe); err != nil || safe != 3 {
		t.Fatalf("unsafe page functions: %d (%v)", safe, err)
	}
	for _, tenant := range []string{f.org, "00000000-0000-4000-8000-000000000011"} {
		tx, err := tenantTx(ctx, f.a.db, tenant)
		if err != nil {
			t.Fatal(err)
		}
		want := 0
		if tenant == f.org {
			want = 1
		}
		for _, query := range []string{
			`SELECT count(*) FROM public.milvago_conversation_correlation_keys($1,$2,'browser','chrome','claude.ai',ARRAY['synthetic-correlation'])`,
			`SELECT count(*) FROM public.milvago_conversation_scope_headers($1,$2,'browser','chrome','claude.ai')`,
		} {
			var count int
			if err = tx.QueryRow(ctx, query, f.org, device).Scan(&count); err != nil || count != want {
				tx.Rollback(ctx)
				t.Fatalf("populated tenant boundary: %d (%v)", count, err)
			}
		}
		tx.Rollback(ctx)
	}
}
