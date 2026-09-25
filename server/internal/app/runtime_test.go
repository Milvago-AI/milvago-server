package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func clearRuntimeConfig(t *testing.T) {
	t.Helper()
	for _, key := range []string{"MILVAGO_ROLE", "DATABASE_URL", "MIGRATION_DATABASE_URL", "DB_RUNTIME_ROLE", "APP_URL", "PUBLIC_URL", "OIDC_ISSUER", "OIDC_INTERNAL_URL", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_ADMIN_CLIENT_ID", "OIDC_ADMIN_CLIENT_SECRET", "BOOTSTRAP_EMAIL", "MILVAGO_SETUP_TOKEN", "SESSION_KEY", "CONTENT_KEYS", "POLICY_SIGNING_KEY", "MILVAGO_PUBLISHER_URL", "MILVAGO_PUBLISHER_CREDENTIAL", "MILVAGO_PUBLISHER_PUBLIC_KEY", "MILVAGO_UPDATE_PUBLIC_KEY", "MILVAGO_EXPORT_CA_FILE", "MILVAGO_MCP", "MILVAGO_OTEL_HTTP_HOSTS", "EDITION"} {
		t.Setenv(key, "")
	}
	t.Setenv("DATABASE_URL", "postgres://runtime@localhost/milvago_test")
	t.Setenv("CONTENT_KEYS", "1:"+encodeKey(1))
}

func TestProcessRoleConfiguration(t *testing.T) {
	t.Run("default combined mode still requires migration credentials", assertDefaultRoleConfig)
	t.Run("API requires neither migration URL nor bootstrap identity", assertAPIRoleConfig)
	t.Run("exports has no console or migration secrets", assertExportsRoleConfig)
	t.Run("maintenance only needs identity issuer and durable keys", assertMaintenanceRoleConfig)
	t.Run("migrate has bootstrap but no console signing secrets", assertMigrateRoleConfig)
	t.Run("unknown role is rejected before accepting any config", assertUnknownRoleConfig)
}

func assertDefaultRoleConfig(t *testing.T) {
	clearRuntimeConfig(t)
	t.Setenv("APP_URL", "http://localhost:4020")
	t.Setenv("OIDC_ISSUER", "http://localhost:8080/realms/test")
	t.Setenv("OIDC_CLIENT_ID", "test-console")
	t.Setenv("OIDC_CLIENT_SECRET", "synthetic-client-secret")
	t.Setenv("BOOTSTRAP_EMAIL", "owner@example.test")
	if _, e := LoadConfig(); e == nil || !strings.Contains(e.Error(), "MIGRATION_DATABASE_URL") {
		t.Fatalf("expected required migration URL, got %v", e)
	}
}

func assertAPIRoleConfig(t *testing.T) {
	clearRuntimeConfig(t)
	t.Setenv("MILVAGO_ROLE", RoleAPI)
	t.Setenv("APP_URL", "http://localhost:4020")
	t.Setenv("OIDC_ISSUER", "http://localhost:8080/realms/test")
	t.Setenv("OIDC_CLIENT_ID", "test-console")
	t.Setenv("OIDC_CLIENT_SECRET", "synthetic-client-secret")
	t.Setenv("SESSION_KEY", encodeKey(2))
	t.Setenv("POLICY_SIGNING_KEY", encodeKey(3))
	c, e := LoadConfig()
	if e != nil || c.RunsMigrations() || !c.ServesAPI() || c.MigrationURL != "" || c.BootstrapEmail != "" {
		t.Fatalf("API configuration or responsibility mismatch: %v", e)
	}
	// One secret may not serve as both the session and the policy signing key.
	t.Setenv("POLICY_SIGNING_KEY", encodeKey(2))
	if _, e := LoadConfig(); e == nil || !strings.Contains(e.Error(), "POLICY_SIGNING_KEY") {
		t.Fatalf("a signing key equal to the session key was accepted: %v", e)
	}
}

func assertExportsRoleConfig(t *testing.T) {
	clearRuntimeConfig(t)
	t.Setenv("MILVAGO_ROLE", RoleExports)
	c, e := LoadConfig()
	if Edition == "community" {
		if e == nil || !strings.Contains(e.Error(), "Enterprise") {
			t.Fatalf("Community accepted exports: %v", e)
		}
		return
	}
	if e != nil || c.SessionCipher != nil || len(c.SigningKey) != 0 || c.ServesAPI() || c.RunsMigrations() {
		t.Fatalf("exports configuration mismatch: %v", e)
	}
}

func assertMaintenanceRoleConfig(t *testing.T) {
	clearRuntimeConfig(t)
	t.Setenv("MILVAGO_ROLE", RoleMaintenance)
	t.Setenv("OIDC_ISSUER", "http://localhost:8080/realms/test")
	c, e := LoadConfig()
	if e != nil || c.SessionCipher != nil || len(c.SigningKey) != 0 || c.ServesAPI() || c.RunsMigrations() {
		t.Fatalf("maintenance configuration mismatch: %v", e)
	}
}

func assertMigrateRoleConfig(t *testing.T) {
	clearRuntimeConfig(t)
	t.Setenv("MILVAGO_ROLE", RoleMigrate)
	t.Setenv("MIGRATION_DATABASE_URL", "postgres://migrator@localhost/milvago_test")
	t.Setenv("APP_URL", "http://localhost:4020")
	t.Setenv("BOOTSTRAP_EMAIL", "owner@example.test")
	t.Setenv("OIDC_ISSUER", "http://localhost:8080/realms/test")
	c, e := LoadConfig()
	if e != nil || c.SessionCipher != nil || len(c.SigningKey) != 0 || c.ServesAPI() || !c.RunsMigrations() {
		t.Fatalf("migration configuration mismatch: %v", e)
	}
}

func assertUnknownRoleConfig(t *testing.T) {
	clearRuntimeConfig(t)
	t.Setenv("MILVAGO_ROLE", "worker")
	if _, e := LoadConfig(); e == nil || !strings.Contains(e.Error(), "MILVAGO_ROLE") {
		t.Fatal("unknown role accepted")
	}
}

func TestBackgroundRolesExposeOnlyOperationalRoutes(t *testing.T) {
	for _, role := range []string{RoleMaintenance, RoleExports} {
		t.Run(role, func(t *testing.T) {
			verifyBackgroundRoleRoutes(t, role)
		})
	}
}

func verifyBackgroundRoleRoutes(t *testing.T, role string) {
	t.Helper()
	var identityCalls atomic.Int32
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identityCalls.Add(1)
		http.Error(w, "discovery must not be requested", 500)
	}))
	defer idp.Close()
	a, e := New(context.Background(), Config{Role: role, Issuer: idp.URL, MetricsToken: "synthetic-metrics-token"}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if role == RoleExports && Edition == "community" {
		if e == nil {
			t.Fatal("Community created export worker")
		}
		return
	}
	if e != nil {
		t.Fatal(e)
	}
	if identityCalls.Load() != 0 || a.verifier != nil || a.mcpVerifier != nil {
		t.Fatal("worker initialized console identity")
	}
	assertBackgroundRoleHTTP(t, a)
}

func assertBackgroundRoleHTTP(t *testing.T, a *App) {
	for _, path := range []string{"/", "/api/bootstrap", "/api/session", "/auth/login", "/v1/policy", "/mcp"} {
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		requireHTTP(t, w, http.StatusNotFound)
	}
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/health/live", nil))
	requireHTTP(t, w, http.StatusOK)
	if w.Header().Get("Cross-Origin-Resource-Policy") != "same-origin" || !strings.Contains(w.Header().Get("Permissions-Policy"), "camera=()") {
		t.Fatalf("security headers missing: %v", w.Header())
	}
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	requireHTTP(t, w, http.StatusUnauthorized)
}

func TestRuntimeDatabaseAndMaintenanceIntegration(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	t.Run("runtime opens without migration credential and cannot migrate", func(t *testing.T) { assertRuntimeRoleDatabase(t, f, ctx) })
	t.Run("runtime refuses explicitly granted schema DDL", func(t *testing.T) { assertRuntimeRejectsDDL(t, f, ctx) })
	t.Run("runtime refuses an unapplied schema", func(t *testing.T) { assertRuntimeRejectsUnappliedSchema(t, f, ctx) })
	t.Run("API replica never bootstraps deployment credentials", func(t *testing.T) { assertAPIReplicaNoBootstrap(t, f, ctx) })
	t.Run("maintenance replicas exclude concurrent and same-period work", func(t *testing.T) { assertMaintenanceExclusion(t, f, ctx) })
	t.Run("failed maintenance is retried", func(t *testing.T) { assertMaintenanceRetry(t, f, ctx) })
	t.Run("panicking maintenance is contained and retried", func(t *testing.T) { assertMaintenancePanicRetry(t, f, ctx) })
}

func assertRuntimeRoleDatabase(t *testing.T, f *observabilityFixture, ctx context.Context) {
	c := f.a.config
	c.Role, c.MigrationURL = RoleAPI, ""
	p, e := OpenRuntimeDatabase(ctx, c)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	if _, e = p.Exec(ctx, "CREATE TABLE forbidden_runtime_ddl(id int)"); e == nil {
		t.Fatal("runtime performed DDL")
	}
	if _, e = p.Exec(ctx, "DELETE FROM schema_migrations"); e == nil {
		t.Fatal("runtime changed migration marker")
	}
}

func assertRuntimeRejectsDDL(t *testing.T, f *observabilityFixture, ctx context.Context) {
	if _, err := f.admin.Exec(ctx, "GRANT CREATE ON SCHEMA public TO milvago_runtime"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := f.admin.Exec(ctx, "REVOKE CREATE ON SCHEMA public FROM milvago_runtime"); err != nil {
			t.Error(err)
		}
	})
	var canCreate bool
	if err := f.a.db.QueryRow(ctx, "SELECT has_schema_privilege(current_user,'public','CREATE')").Scan(&canCreate); err != nil || !canCreate {
		t.Fatalf("fixture did not grant DDL: %v", err)
	}
	if pool, err := OpenRuntimeDatabase(ctx, f.a.config); err == nil {
		pool.Close()
		t.Fatal("runtime accepted schema DDL privilege")
	}
}

func assertRuntimeRejectsUnappliedSchema(t *testing.T, f *observabilityFixture, ctx context.Context) {
	if _, e := f.admin.Exec(ctx, "DELETE FROM schema_migrations WHERE version=$1", runtimeSchemaVersion); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if _, e := f.admin.Exec(ctx, "INSERT INTO schema_migrations(version) VALUES($1) ON CONFLICT DO NOTHING", runtimeSchemaVersion); e != nil {
			t.Error(e)
		}
	})
	if p, e := OpenRuntimeDatabase(ctx, f.a.config); e == nil {
		p.Close()
		t.Fatal("runtime accepted missing schema marker")
	}
}

func assertAPIReplicaNoBootstrap(t *testing.T, f *observabilityFixture, ctx context.Context) {
	setTenant(t, f.admin, f.org)
	if _, e := f.admin.Exec(ctx, "DELETE FROM installer_profiles"); e != nil {
		t.Fatal(e)
	}
	c := f.a.config
	c.Role = RoleAPI
	if _, e := New(ctx, c, f.a.db, f.a.log); e != nil {
		t.Fatal(e)
	}
	var count int
	if e := f.admin.QueryRow(ctx, "SELECT count(*) FROM installer_profiles").Scan(&count); e != nil || count != 0 {
		t.Fatalf("API startup wrote bootstrap credentials, count=%d error=%v", count, e)
	}
	if e := Bootstrap(ctx, c, f.a.db, f.a.log); e != nil {
		t.Fatal(e)
	}
	if e := f.admin.QueryRow(ctx, "SELECT count(*) FROM installer_profiles").Scan(&count); e != nil || count != 1 {
		t.Fatalf("migration bootstrap did not mint its key, count=%d error=%v", count, e)
	}
}

func assertMaintenanceExclusion(t *testing.T, f *observabilityFixture, ctx context.Context) {
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- f.a.maintenanceOnce(ctx, "hour", func(context.Context) error {
			calls.Add(1)
			close(started)
			<-release
			return nil
		})
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("first maintenance never acquired lock")
	}
	second := &App{db: f.a.db}
	e := second.maintenanceOnce(ctx, "hour", func(context.Context) error { calls.Add(1); return nil })
	close(release)
	if e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if e = second.maintenanceOnce(ctx, "hour", func(context.Context) error { calls.Add(1); return nil }); e != nil {
		t.Fatal(e)
	}
	if calls.Load() != 1 {
		t.Fatalf("maintenance ran %d times", calls.Load())
	}
}

func assertMaintenanceRetry(t *testing.T, f *observabilityFixture, ctx context.Context) {
	want := errors.New("synthetic failure")
	if e := f.a.maintenanceOnce(ctx, "minute", func(context.Context) error { return want }); !errors.Is(e, want) {
		t.Fatal(e)
	}
	called := false
	if e := f.a.maintenanceOnce(ctx, "minute", func(context.Context) error { called = true; return nil }); e != nil || !called {
		t.Fatalf("failed work not retried: called=%v error=%v", called, e)
	}
}

func assertMaintenancePanicRetry(t *testing.T, f *observabilityFixture, ctx context.Context) {
	// The previous subtest completed this minute's bucket; reopen it.
	if _, e := f.admin.Exec(ctx, `DELETE FROM runtime_maintenance WHERE task='minute'`); e != nil {
		t.Fatal(e)
	}
	if f.a.maintenanceOnce(ctx, "minute", func(context.Context) error { panic("synthetic panic") }) == nil {
		t.Fatal("panic not reported as a failure")
	}
	called := false
	if e := f.a.maintenanceOnce(ctx, "minute", func(context.Context) error { called = true; return nil }); e != nil || !called {
		t.Fatalf("work after a panic not retried: called=%v error=%v", called, e)
	}
}

func TestContainLogsTaskAndStackButNeverThePanicValue(t *testing.T) {
	var logs strings.Builder
	a := &App{log: slog.New(slog.NewTextHandler(&logs, nil))}
	panicking := func() (failed bool) {
		defer func() { failed = a.contain(recover(), "probe") }()
		panic("https://collector.example.test/?token=synthetic-secret")
	}
	if !panicking() {
		t.Fatal("panic not reported")
	}
	if a.contain(nil, "quiet") {
		t.Fatal("no panic reported as one")
	}
	out := logs.String()
	if strings.Contains(out, "synthetic-secret") || strings.Contains(out, "collector.example.test") {
		t.Fatalf("panic value logged: %s", out)
	}
	if !strings.Contains(out, "task=probe") || !strings.Contains(out, "TestContainLogsTaskAndStackButNeverThePanicValue") {
		t.Fatalf("task or stack missing: %s", out)
	}
}
