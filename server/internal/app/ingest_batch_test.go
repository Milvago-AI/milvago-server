package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ingestQueryCounts struct {
	queries, catalogues, batches, writes atomic.Int32
}

func (c *ingestQueryCounts) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	c.queries.Add(1)
	if strings.HasPrefix(data.SQL, "SELECT content FROM detection_catalogs") {
		c.catalogues.Add(1)
	}
	return ctx
}
func (*ingestQueryCounts) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
func (c *ingestQueryCounts) TraceBatchStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceBatchStartData) context.Context {
	c.batches.Add(1)
	c.writes.Add(int32(data.Batch.Len()))
	return ctx
}
func (*ingestQueryCounts) TraceBatchQuery(context.Context, *pgx.Conn, pgx.TraceBatchQueryData) {}
func (*ingestQueryCounts) TraceBatchEnd(context.Context, *pgx.Conn, pgx.TraceBatchEndData)     {}
func (c *ingestQueryCounts) reset() {
	c.queries.Store(0)
	c.catalogues.Store(0)
	c.batches.Store(0)
	c.writes.Store(0)
}

func TestIngestionBatchPipeline(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	credential := randomToken()
	var device, actor string
	if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status)
 VALUES($1,$2,'synthetic-batch-device','test','0.5.8','approved') RETURNING id`, f.org, hash(credential)).Scan(&device); err != nil {
		t.Fatal(err)
	}
	if err := f.admin.QueryRow(ctx, `INSERT INTO collaborators(organization_id,subject,display_name,email)
 VALUES($1,'synthetic-batch-subject','Synthetic account','batch@example.test') RETURNING id`, f.org).Scan(&actor); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := f.admin.Exec(ctx, `INSERT INTO device_collaborators(organization_id,device_id,collaborator_id,bound_at,expires_at)
 VALUES($1,$2,$3,$4,$5)`, f.org, device, actor, now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	config := defaultShadowConfig()
	config.Collection.StoreContent = true
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(ctx, `INSERT INTO shadow_settings(organization_id,configuration) VALUES($1,$2)
 ON CONFLICT(organization_id) DO UPDATE SET configuration=excluded.configuration,revision=nextval('shadow_revision')`, f.org, raw); err != nil {
		t.Fatal(err)
	}
	tx, err := tenantTx(ctx, f.a.db, f.org)
	if err != nil {
		t.Fatal(err)
	}
	effective, err := f.a.effectiveShadow(ctx, tx, f.org, device)
	if err != nil {
		tx.Rollback(ctx)
		t.Fatal(err)
	}
	tx.Rollback(ctx)
	var revision int64
	if err = f.admin.QueryRow(ctx, "SELECT max(revision) FROM detection_catalogs").Scan(&revision); err != nil {
		t.Fatal(err)
	}

	counts := &ingestQueryCounts{}
	poolConfig := f.a.db.Config()
	poolConfig.ConnConfig.Tracer = counts
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	f.a.db = pool

	events := make([]V2Event, 100)
	prompt := "Synthetic batch content"
	for i := range events {
		events[i] = V2Event{
			ID:         fmt.Sprintf("77777777-7777-4777-8777-%012d", i+1),
			OccurredAt: now.Add(-30 * time.Second), Kind: "prompt",
			Provider: "chatgpt.com", Source: "browser", Tool: "chrome",
			Action: "observed", Characters: 23, Labels: []string{},
			PolicyRevision: effective.Revision, CatalogRevision: &revision,
			Detector: "network", User: "synthetic-account",
		}
		if i < 50 {
			events[i].OccurredAt = now.Add(-2 * time.Minute)
			events[i].Prompt = &prompt
		}
	}
	call := func(t *testing.T, values []V2Event, status int) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(map[string]any{"events": values})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest("POST", "/v2/events", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+credential)
		response := httptest.NewRecorder()
		counts.reset()
		f.a.Handler().ServeHTTP(response, request)
		requireHTTP(t, response, status)
		return response
	}
	t.Run("one bounded pipeline preserves identity content and temporal association", func(t *testing.T) {
		w := call(t, events, 200)
		var response struct {
			Accepted []string `json:"accepted_ids"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if len(response.Accepted) != len(events) {
			t.Fatalf("incomplete acknowledgement: %d", len(response.Accepted))
		}
		for i, id := range response.Accepted {
			if id != events[i].ID {
				t.Fatal("acknowledgement identity changed")
			}
		}
		if counts.queries.Load() > 45 || counts.catalogues.Load() != 1 || counts.batches.Load() != 1 || counts.writes.Load() != 100 {
			t.Fatalf("unbounded per-event reads or non-pipelined writes: queries=%d catalogues=%d batches=%d writes=%d",
				counts.queries.Load(), counts.catalogues.Load(), counts.batches.Load(), counts.writes.Load())
		}
		var stored, attributed, userKeys int
		if err := f.admin.QueryRow(ctx, `SELECT count(*),count(collaborator_id),count(DISTINCT user_key)
 FROM shadow_events WHERE organization_id=$1 AND device_id=$2`, f.org, device).Scan(&stored, &attributed, &userKeys); err != nil {
			t.Fatal(err)
		}
		if stored != 100 || attributed != 50 || userKeys != 1 {
			t.Fatalf("batch attribution mismatch: events=%d associated=%d userKeys=%d", stored, attributed, userKeys)
		}
		var contentCount int
		var sealed []byte
		if err := f.admin.QueryRow(ctx, "SELECT count(*) FROM shadow_content WHERE device_id=$1", device).Scan(&contentCount); err != nil || contentCount != 50 {
			t.Fatal("content count", contentCount, err)
		}
		if err := f.admin.QueryRow(ctx, "SELECT encrypted FROM shadow_content WHERE device_id=$1 AND event_id=$2", device, events[0].ID).Scan(&sealed); err != nil {
			t.Fatal(err)
		}
		plain, err := f.a.openShadow(f.org, "event:"+device+":"+events[0].ID, string(sealed))
		if err != nil || !bytes.Contains(plain, []byte(prompt)) || bytes.Contains(sealed, []byte(prompt)) {
			t.Fatal("content encryption binding changed", err)
		}
		if _, err := f.a.openShadow(f.org, "event:"+device+":"+events[1].ID, string(sealed)); err == nil {
			t.Fatal("ciphertext accepted for another event")
		}
	})
	t.Run("replay never overwrites records or recreates purged content", func(t *testing.T) {
		var original []byte
		if err := f.admin.QueryRow(ctx, "SELECT encrypted FROM shadow_content WHERE device_id=$1 AND event_id=$2", device, events[1].ID).Scan(&original); err != nil {
			t.Fatal(err)
		}
		tag, err := f.admin.Exec(ctx, "DELETE FROM shadow_content WHERE device_id=$1 AND event_id=$2", device, events[0].ID)
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatal("content was not removed", err)
		}
		replay := append([]V2Event(nil), events...)
		changed := "Synthetic replacement must not be written"
		replay[0].Prompt, replay[1].Prompt = &changed, &changed
		call(t, replay, 200)
		var count int
		var after []byte
		if err := f.admin.QueryRow(ctx, "SELECT count(*) FROM shadow_content WHERE device_id=$1", device).Scan(&count); err != nil || count != 49 {
			t.Fatal("replay recreated content", count, err)
		}
		if err := f.admin.QueryRow(ctx, "SELECT encrypted FROM shadow_content WHERE device_id=$1 AND event_id=$2", device, events[1].ID).Scan(&after); err != nil || !bytes.Equal(original, after) {
			t.Fatal("replay overwrote content", err)
		}
	})
	t.Run("late database failure rolls back the entire pipeline", func(t *testing.T) {
		next := append([]V2Event(nil), events...)
		for i := range next {
			next[i].ID = fmt.Sprintf("88888888-8888-4888-8888-%012d", i+1)
		}
		if _, err := f.admin.Exec(ctx, `ALTER TABLE shadow_events ADD CONSTRAINT synthetic_batch_failure
 CHECK (id <> '88888888-8888-4888-8888-000000000100'::uuid)`); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := f.admin.Exec(ctx, "ALTER TABLE shadow_events DROP CONSTRAINT synthetic_batch_failure"); err != nil {
				t.Error(err)
			}
		})
		call(t, next, 500)
		var stored int
		if err := f.admin.QueryRow(ctx, "SELECT count(*) FROM shadow_events WHERE id::text LIKE '88888888-%'").Scan(&stored); err != nil || stored != 0 {
			t.Fatal("failed pipeline partially committed", stored, err)
		}
	})
}
