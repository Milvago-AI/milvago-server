package app

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type outageFixture struct {
	f          *observabilityFixture
	credential string
	device     string
}

func newOutageFixture(t *testing.T) outageFixture {
	t.Helper()
	f := newObservabilityFixture(t)
	ctx := context.Background()
	credential := randomToken()
	var device string
	if err := f.admin.QueryRow(ctx, "INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status) VALUES($1,$2,'test-endpoint','windows','0.5.5','approved') RETURNING id", f.org, hash(credential)).Scan(&device); err != nil {
		t.Fatal(err)
	}
	return outageFixture{f: f, credential: credential, device: device}
}
func (fixture outageFixture) request(t *testing.T, token string, status int, code string) {
	t.Helper()
	for _, path := range []string{"/v1/policy", "/v2/policy", "/v3/policy"} {
		request := httptest.NewRequest("GET", path, nil)
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		fixture.f.a.Handler().ServeHTTP(response, request)
		requireHTTP(t, response, status)
		if code != "" {
			var body struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.Error != code {
				t.Fatalf("%s: expected error %q, got %s", path, code, response.Body.String())
			}
		}
	}
}
func (fixture outageFixture) assertClosedPool(t *testing.T, ctx context.Context) {
	pool, err := pgxpool.NewWithConfig(ctx, fixture.f.a.db.Config())
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	if err := pool.Ping(ctx); err == nil {
		t.Fatal("closed pool unexpectedly available")
	}
	original := fixture.f.a.db
	fixture.f.a.db = pool
	t.Cleanup(func() { fixture.f.a.db = original })
	fixture.request(t, fixture.credential, 503, "")
}
func (fixture outageFixture) waitForMinuteHeadroom(t *testing.T, ctx context.Context) {
	t.Helper()
	for {
		var remaining float64
		if err := fixture.f.admin.QueryRow(ctx, "SELECT EXTRACT(EPOCH FROM date_trunc('minute', clock_timestamp()) + interval '1 minute' - clock_timestamp())").Scan(&remaining); err != nil {
			t.Fatal(err)
		}
		if remaining > 10 {
			return
		}
		time.Sleep(time.Duration(remaining*float64(time.Second)) + 100*time.Millisecond)
	}
}
func (fixture outageFixture) policyRequest(requestCtx context.Context, peer string) *httptest.ResponseRecorder {
	request := httptest.NewRequest("GET", "/v3/policy", nil).WithContext(requestCtx)
	request.Header.Set("Authorization", "Bearer "+fixture.credential)
	request.RemoteAddr = peer
	response := httptest.NewRecorder()
	fixture.f.a.Handler().ServeHTTP(response, request)
	return response
}
func (fixture outageFixture) assertSaturatedPool(t *testing.T, ctx context.Context) {
	const peer = "198.51.100.9:41001"
	fixture.waitForMinuteHeadroom(t, ctx)
	poolConfig := fixture.f.a.db.Config().Copy()
	poolConfig.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	original := fixture.f.a.db
	fixture.f.a.db = pool
	t.Cleanup(func() { fixture.f.a.db = original; pool.Close() })
	requireHTTP(t, fixture.policyRequest(ctx, peer), 200)
	held, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	released := false
	t.Cleanup(func() {
		if !released {
			held.Release()
		}
	})
	parent, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := time.Now()
	response := fixture.policyRequest(parent, peer)
	elapsed := time.Since(started)
	requireHTTP(t, response, 503)
	var body map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body["error"] != "device_identity_unavailable" {
		t.Fatalf("expected device_identity_unavailable, got %s", response.Body.String())
	}
	if elapsed >= 4*time.Second {
		t.Fatalf("saturated identity lookup took %s", elapsed)
	}
	if err := parent.Err(); err != nil {
		t.Fatalf("parent context expired: %v", err)
	}
	held.Release()
	released = true
	requireHTTP(t, fixture.policyRequest(ctx, peer), 200)
}
func (fixture outageFixture) assertStatusQueryError(t *testing.T, ctx context.Context) {
	if _, err := fixture.f.admin.Exec(ctx, "REVOKE SELECT ON devices FROM milvago_runtime"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := fixture.f.admin.Exec(ctx, "GRANT SELECT ON devices TO milvago_runtime"); err != nil {
			t.Error(err)
		}
	})
	var org, id string
	if err := fixture.f.a.db.QueryRow(ctx, "SELECT organization_id,device_id FROM device_identity($1)", hash(fixture.credential)).Scan(&org, &id); err != nil || org != fixture.f.org || id != fixture.device {
		t.Fatalf("identity lookup did not reach the expected device: %v", err)
	}
	var selectable bool
	if err := fixture.f.a.db.QueryRow(ctx, "SELECT has_table_privilege(current_user,'devices','SELECT')").Scan(&selectable); err != nil || selectable {
		t.Fatalf("status-query failure not established: %v", err)
	}
	fixture.request(t, fixture.credential, 500, "internal_error")
}
func (fixture outageFixture) assertDeviceState(t *testing.T, ctx context.Context, state string) {
	result, err := fixture.f.admin.Exec(ctx, "UPDATE devices SET status=$1 WHERE id=$2", state, fixture.device)
	if err != nil {
		t.Fatal(err)
	}
	if result.RowsAffected() != 1 {
		t.Fatal("device status was not changed")
	}
	fixture.request(t, fixture.credential, 401, "device_unauthorized")
}
func TestDeviceAuthorizationDatabaseOutage(t *testing.T) {
	fixture := newOutageFixture(t)
	ctx := context.Background()
	t.Run("approved_before_outage", func(t *testing.T) { fixture.request(t, fixture.credential, 200, "") })
	t.Run("identity_database_unavailable", func(t *testing.T) { fixture.assertClosedPool(t, ctx) })
	t.Run("identity_pool_saturated", func(t *testing.T) { fixture.assertSaturatedPool(t, ctx) })
	t.Run("device_status_database_error", func(t *testing.T) { fixture.assertStatusQueryError(t, ctx) })
	t.Run("recovered", func(t *testing.T) { fixture.request(t, fixture.credential, 200, "") })
	t.Run("unknown_credential", func(t *testing.T) { fixture.request(t, randomToken(), 401, "device_unauthorized") })
	for _, state := range []string{"pending", "revoked"} {
		t.Run(state, func(t *testing.T) { fixture.assertDeviceState(t, ctx, state) })
	}
}
