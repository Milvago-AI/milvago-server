//go:build !commercial

package app

import (
	"context"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"
)

const Edition = "community"

// The providers this edition covers. Community qualifies ChatGPT and Claude only,
// and the browser package is built on the same list: a catalogue naming anything
// else would describe sites no Community extension is even injected into.
var editionProviders = []string{"chatgpt", "claude"}

const editionMigration = ""

func editionGrants(role string) string                { return "" }
func initializeEdition(context.Context, pgx.Tx) error { return nil }

func (a *App) registerEditionRoutes() {}

// This edition has one bearer credential, the API key: no MCP endpoint, therefore
// no OAuth resource, nothing to discover and no access token to verify. The
// challenge says what it has always said, and a bearer is resolved the one way
// there is.
func (a *App) initMCPVerifier(*oidc.Provider) {}

// Nothing to declare on the identity provider either: no endpoint, no resource, no
// connector client.
func (a *App) ensureMCPIdentity(context.Context) {}

func (a *App) bearerTx(r *http.Request, mode credentialMode) (pgx.Tx, *Session, error) {
	return a.apiKeyTx(r)
}
func (a *App) bearerChallenge(r *http.Request) string { return `Bearer realm="Milvago"` }

// warnTenantDirectories: one organization in Community, nothing to warn about.
func (a *App) warnTenantDirectories(context.Context) {}
