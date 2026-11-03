package app

import (
	"bytes"
	"context"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type heartbeatWriteTrace struct {
	sync.Mutex
	writes int
}

func (trace *heartbeatWriteTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, query pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(query.SQL, "UPDATE devices") {
		trace.Lock()
		trace.writes++
		trace.Unlock()
	}
	return ctx
}

func (*heartbeatWriteTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestHeartbeatStableCapabilitiesSingleDeviceWrite(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	credential := randomToken()
	var device string
	if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,capabilities)
	 VALUES($1,$2,'synthetic-heartbeat','windows','0.7.0','approved',
	 '["browser.navigation","dlp-v1","dlp-confirm-v1","dlp-contextual-v1","discovery-v1"]') RETURNING id`, f.org, hash(credential)).Scan(&device); err != nil {
		t.Fatal(err)
	}
	original := f.a.db
	config := original.Config()
	trace := &heartbeatWriteTrace{}
	config.ConnConfig.Tracer = trace
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	f.a.db = pool
	defer func() { f.a.db = original; pool.Close() }()
	req := httptest.NewRequest("POST", "/v2/heartbeat", bytes.NewBufferString(`{"version":"0.7.0","dlp_engine":3,"discovery_engine":1}`))
	req.Header.Set("Authorization", "Bearer "+credential)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.a.Handler().ServeHTTP(w, req)
	requireHTTP(t, w, 200)
	trace.Lock()
	writes := trace.writes
	trace.Unlock()
	var capabilities []string
	var version string
	var recentlySeen bool
	if err := f.admin.QueryRow(ctx, `SELECT capabilities,version,last_seen>now()-interval '1 minute' FROM devices WHERE organization_id=$1 AND id=$2`, f.org, device).Scan(&capabilities, &version, &recentlySeen); err != nil {
		t.Fatal(err)
	}
	for _, capability := range []string{"browser.navigation", "dlp-v1", "dlp-confirm-v1", "dlp-contextual-v1", "discovery-v1"} {
		if !slices.Contains(capabilities, capability) {
			t.Fatalf("heartbeat discarded capability %s", capability)
		}
	}
	if version != "0.7.0" || !recentlySeen {
		t.Fatal("heartbeat diagnostics were not persisted")
	}
	if writes != 1 {
		t.Fatalf("stable heartbeat must write its device once, got %d writes", writes)
	}
}
