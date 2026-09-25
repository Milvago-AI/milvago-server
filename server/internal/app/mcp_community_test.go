//go:build !commercial

package app

import (
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The MCP endpoint is an Enterprise module, so Community has no subsystem to
// exercise: what matters here is that the route does not exist at all, and that
// is asserted in the edition-routes subtest of TestDatabaseSecurityAndHTTP.
//
// This stub keeps the call site in that test unconditional. An edition branch
// around the call would read as "MCP is disabled in Community", which is the
// wrong idea about a module that is not compiled.
func testMCPSubsystem(*testing.T, *App, *pgxpool.Pool, *http.Cookie, string, string, string, *testIdentity) {
}
