package app

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The decision reason constraint is added NOT VALID in the migration transaction and validated
// after it, in a transaction of its own. A start that stopped between the two steps leaves the
// constraint unvalidated with the migration recorded: the next start must still validate it.
func TestDecisionReasonsValidatedAfterTheMigration(t *testing.T) {
	runtimeURL, migrationURL := os.Getenv("TEST_DATABASE_URL"), os.Getenv("TEST_MIGRATION_DATABASE_URL")
	if runtimeURL == "" || migrationURL == "" {
		t.Skip("requires disposable milvago_test database")
	}
	requireDisposableObservabilityURLs(t, runtimeURL, migrationURL)
	ctx := context.Background()
	admin, e := pgxpool.New(ctx, migrationURL)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(admin.Close)
	if _, e = admin.Exec(ctx, "DROP SCHEMA public CASCADE; CREATE SCHEMA public"); e != nil {
		t.Fatal(e)
	}
	block, _ := aes.NewCipher(make([]byte, 32))
	gcm, _ := cipher.NewGCM(block)
	idp := identityProvider(t)
	cfg := Config{DatabaseURL: runtimeURL, MigrationURL: migrationURL, RuntimeRole: "milvago_runtime", OrganizationName: "Test organization", BootstrapEmail: "owner@example.test", AppURL: "http://localhost:4020", PublicURL: "http://localhost:4020", Issuer: idp.server.URL, ClientID: "test-console", SessionCipher: gcm, ContentKeys: testContentKeys(), ContentVersion: 1, SigningKey: ed25519.NewKeyFromSeed(make([]byte, 32))}
	validated := func() bool {
		var ok bool
		if e := admin.QueryRow(ctx, `SELECT convalidated FROM pg_constraint WHERE conname='shadow_events_decision_reason_check' AND conrelid='shadow_events'::regclass`).Scan(&ok); e != nil {
			t.Fatal(e)
		}
		return ok
	}
	open := func() {
		pool, e := OpenDatabase(ctx, cfg)
		if e != nil {
			t.Fatal(e)
		}
		pool.Close()
	}
	open()
	if !validated() {
		t.Fatal("a fresh database ends with the constraint validated")
	}
	if _, e = admin.Exec(ctx, `ALTER TABLE shadow_events DROP CONSTRAINT shadow_events_decision_reason_check;
ALTER TABLE shadow_events ADD CONSTRAINT shadow_events_decision_reason_check CHECK(decision_reason IN ('','model_denied','model_unknown','control_unavailable','service_blocked','service_redirected','upload_blocked','keyword')) NOT VALID`); e != nil {
		t.Fatal(e)
	}
	open()
	if !validated() {
		t.Fatal("a constraint left NOT VALID by an interrupted start is validated by the next one")
	}
	open()
	if !validated() {
		t.Fatal("restart stays idempotent")
	}
}
