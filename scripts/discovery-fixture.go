// Command discovery-fixture initializes only the named disposable CI database.
package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
)

func main() {
	address := os.Getenv("DISCOVERY_FIXTURE_ADMIN_URL")
	parsed, err := url.Parse(address)
	if err != nil || parsed.User == nil || parsed.User.Username() != "fixture_admin" || parsed.Path != "/milvago_test" || (parsed.Hostname() != "database" && parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1") {
		fmt.Fprintln(os.Stderr, "requires the isolated fixture_admin@database/milvago_test CI database")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var connection *pgx.Conn
	for ctx.Err() == nil {
		connection, err = pgx.Connect(ctx, address)
		if err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err == nil {
		defer connection.Close(context.Background())
		_, err = connection.Exec(ctx, `
CREATE ROLE milvago_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD 'fixture-runtime';
CREATE ROLE milvago_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD 'fixture-migration';
CREATE ROLE milvago_lookup NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
GRANT milvago_lookup TO milvago_migration;
ALTER DATABASE milvago_test OWNER TO milvago_migration;
ALTER SCHEMA public OWNER TO milvago_migration;
GRANT USAGE ON SCHEMA public TO milvago_runtime;
`)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "disposable discovery database initialization failed")
		os.Exit(1)
	}
}
