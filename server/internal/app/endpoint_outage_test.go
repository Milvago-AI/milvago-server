package app

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDeviceAuthorizationDatabaseOutage(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	credential := randomToken()
	var device string
	if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status)
 VALUES($1,$2,'test-endpoint','windows','0.5.5','approved') RETURNING id`, f.org, hash(credential)).Scan(&device); err != nil {
		t.Fatal(err)
	}
	request := func(t *testing.T, token string, status int, code string) {
		t.Helper()
		for _, path := range []string{"/v1/policy", "/v2/policy", "/v3/policy"} {
			r := httptest.NewRequest("GET", path, nil)
			r.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			f.a.Handler().ServeHTTP(w, r)
			requireHTTP(t, w, status)
			if code != "" {
				var body struct {
					Error string `json:"error"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Error != code {
					t.Fatalf("%s: expected error %q, got %s", path, code, w.Body.String())
				}
			}
		}
	}
	t.Run("approved_before_outage", func(t *testing.T) { request(t, credential, 200, "") })
	t.Run("identity_database_unavailable", func(t *testing.T) {
		pool, err := pgxpool.NewWithConfig(ctx, f.a.db.Config())
		if err != nil {
			t.Fatal(err)
		}
		pool.Close()
		if err := pool.Ping(ctx); err == nil {
			t.Fatal("closed pool unexpectedly available")
		}
		original := f.a.db
		f.a.db = pool
		t.Cleanup(func() { f.a.db = original })
		request(t, credential, 503, "")
	})
	t.Run("identity_pool_saturated", func(t *testing.T) {
		const peer = "198.51.100.9:41001"
		for {
			var remaining float64
			if err := f.admin.QueryRow(ctx, "SELECT EXTRACT(EPOCH FROM date_trunc('minute', clock_timestamp()) + interval '1 minute' - clock_timestamp())").Scan(&remaining); err != nil {
				t.Fatal(err)
			}
			if remaining > 10 {
				break
			}
			time.Sleep(time.Duration(remaining*float64(time.Second)) + 100*time.Millisecond)
		}
		poolConfig := f.a.db.Config().Copy()
		poolConfig.MaxConns = 1
		pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
		if err != nil {
			t.Fatal(err)
		}
		original := f.a.db
		f.a.db = pool
		t.Cleanup(func() {
			f.a.db = original
			pool.Close()
		})
		policy := func(requestCtx context.Context) *httptest.ResponseRecorder {
			r := httptest.NewRequest("GET", "/v3/policy", nil).WithContext(requestCtx)
			r.Header.Set("Authorization", "Bearer "+credential)
			r.RemoteAddr = peer
			w := httptest.NewRecorder()
			f.a.Handler().ServeHTTP(w, r)
			return w
		}
		// This real handler call fills both device-auth reservations: the peer
		// reservation and the shared global reservation.
		requireHTTP(t, policy(ctx), 200)
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
		w := policy(parent)
		elapsed := time.Since(started)
		requireHTTP(t, w, 503)
		var body map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body["error"] != "device_identity_unavailable" {
			t.Fatalf("expected device_identity_unavailable, got %s", w.Body.String())
		}
		if elapsed >= 4*time.Second {
			t.Fatalf("saturated identity lookup took %s", elapsed)
		}
		if err := parent.Err(); err != nil {
			t.Fatalf("parent context expired: %v", err)
		}
		held.Release()
		released = true
		requireHTTP(t, policy(ctx), 200)
	})
	t.Run("device_status_database_error", func(t *testing.T) {
		if _, err := f.admin.Exec(ctx, `REVOKE SELECT ON devices FROM milvago_runtime`); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := f.admin.Exec(ctx, `GRANT SELECT ON devices TO milvago_runtime`); err != nil {
				t.Error(err)
			}
		})
		// Prove the first lookup still succeeds, then prove the second query
		// cannot read the status. Otherwise this would repeat the first case.
		var org, id string
		if err := f.a.db.QueryRow(ctx, `SELECT organization_id,device_id FROM device_identity($1)`, hash(credential)).Scan(&org, &id); err != nil || org != f.org || id != device {
			t.Fatalf("identity lookup did not reach the expected device: %v", err)
		}
		var selectable bool
		if err := f.a.db.QueryRow(ctx, `SELECT has_table_privilege(current_user,'devices','SELECT')`).Scan(&selectable); err != nil || selectable {
			t.Fatalf("status-query failure not established: %v", err)
		}
		request(t, credential, 500, "internal_error")
	})
	t.Run("recovered", func(t *testing.T) { request(t, credential, 200, "") })
	t.Run("unknown_credential", func(t *testing.T) { request(t, randomToken(), 401, "device_unauthorized") })
	for _, state := range []string{"pending", "revoked"} {
		t.Run(state, func(t *testing.T) {
			result, err := f.admin.Exec(ctx, `UPDATE devices SET status=$1 WHERE id=$2`, state, device)
			if err != nil {
				t.Fatal(err)
			}
			if result.RowsAffected() != 1 {
				t.Fatal("device status was not changed")
			}
			request(t, credential, 401, "device_unauthorized")
		})
	}
}
