package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const testDatabaseLockKey = 521987143
const testDatabaseLockWait = 15 * time.Minute

func TestMain(m *testing.M) {
	release, err := lockTestDatabase()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// Every suite runs licensed, with no device quota; license_test.go clears it.
	unlimited := 0
	licenseTestGrant = &licenseClaims{Kind: "enterprise", MaxDevices: &unlimited}
	code := m.Run()
	release()
	os.Exit(code)
}

func integrationRequired() bool {
	return os.Getenv("MILVAGO_REQUIRE_INTEGRATION") == "1"
}

// lockTestDatabase serializes this binary against any other one using the shared
// test database. Integration tests drop its public schema, so concurrent test
// binaries must queue rather than destroy each other's fixtures.
func lockTestDatabase() (func(), error) {
	runtimeURL := os.Getenv("TEST_DATABASE_URL")
	migrationURL := os.Getenv("TEST_MIGRATION_DATABASE_URL")
	required := integrationRequired()
	if required && (runtimeURL == "" || migrationURL == "") {
		return nil, errors.New("integration tests require TEST_DATABASE_URL and TEST_MIGRATION_DATABASE_URL")
	}
	if migrationURL == "" {
		return func() {}, nil
	}

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, migrationURL)
	if err != nil {
		if required {
			return nil, fmt.Errorf("integration tests cannot connect to the disposable migration database: %w", err)
		}
		return func() {}, nil
	}

	return waitForTestDatabaseLock(ctx, conn, required)
}

func waitForTestDatabaseLock(ctx context.Context, conn *pgx.Conn, required bool) (func(), error) {
	deadline := time.Now().Add(testDatabaseLockWait)
	announced := false
	for {
		var held bool
		err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", testDatabaseLockKey).Scan(&held)
		if err != nil {
			_ = conn.Close(ctx)
			if required {
				return nil, fmt.Errorf("integration tests cannot acquire the database advisory lock: %w", err)
			}
			return func() {}, nil
		}
		if held {
			return func() {
				_, _ = conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", testDatabaseLockKey)
				_ = conn.Close(ctx)
			}, nil
		}
		if time.Now().After(deadline) {
			_ = conn.Close(ctx)
			return nil, fmt.Errorf("another test binary has held milvago_test for over %s; refusing to run and drop its schema", testDatabaseLockWait)
		}
		if !announced {
			fmt.Fprintln(os.Stderr, "waiting for another test binary to release milvago_test")
			announced = true
		}
		time.Sleep(2 * time.Second)
	}
}
