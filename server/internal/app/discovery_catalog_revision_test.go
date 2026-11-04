package app

import (
	"context"
	"encoding/json"
	"testing"
)

func TestDiscoveryPublicationAdvancesPastInstalledCatalog(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	if _, err := f.admin.Exec(ctx, `UPDATE sessions SET mfa_verified_at=now() WHERE user_id=$1`, f.user); err != nil {
		t.Fatal(err)
	}
	saved := f.call("PUT", "/api/discovery/catalog/draft", map[string]any{"source": string(discoveryFactory), "revision": 0}, f.csrf)
	requireHTTP(t, saved, 200)
	var draft struct {
		Revision int64 `json:"revision"`
	}
	if err := json.Unmarshal(saved.Body.Bytes(), &draft); err != nil {
		t.Fatal(err)
	}
	const installed = int64(1_000_000_000_000)
	if _, err := f.admin.Exec(ctx, `UPDATE discovery_catalogs SET content=jsonb_set(content,'{revision}',to_jsonb($2::bigint)),revision=$2 WHERE organization_id=$1`, f.org, installed); err != nil {
		t.Fatal(err)
	}
	for round := 1; round <= 2; round++ {
		response := f.call("POST", "/api/discovery/catalog/publish", map[string]any{"revision": draft.Revision, "reason": "Synthetic installed catalogue upgrade"}, f.csrf)
		requireHTTP(t, response, 200)
		var result struct {
			Revision int64 `json:"revision"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Revision != installed+int64(round) {
			t.Fatalf("published revision rolled back: %d", result.Revision)
		}
		var stored int64
		if err := f.admin.QueryRow(ctx, `SELECT (content->>'revision')::bigint FROM discovery_catalogs WHERE organization_id=$1`, f.org).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if stored != result.Revision {
			t.Fatal("response and stored catalogue revisions differ")
		}
	}
	for _, invalid := range []any{nil, "data:image/png", int64(-1), int64(1<<63 - 1)} {
		raw, err := json.Marshal(invalid)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.admin.Exec(ctx, `UPDATE discovery_catalogs SET content=jsonb_set(content,'{revision}',$2::jsonb) WHERE organization_id=$1`, f.org, raw); err != nil {
			t.Fatal(err)
		}
		response := f.call("POST", "/api/discovery/catalog/publish", map[string]any{"revision": draft.Revision, "reason": "Synthetic corrupt catalogue recovery boundary"}, f.csrf)
		requireHTTP(t, response, 500)
		var stored int64
		if err = f.admin.QueryRow(ctx, `SELECT revision FROM discovery_catalogs WHERE organization_id=$1`, f.org).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if stored != installed+2 {
			t.Fatal("a corrupt published catalogue was overwritten")
		}
	}
}
