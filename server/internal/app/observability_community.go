//go:build !commercial

package app

import (
	"context"
	"github.com/jackc/pgx/v5"
)

var observabilityPermissions = []string{}

func initializeObservability(context.Context, pgx.Tx, string) error { return nil }
func (a *App) forwardObservability(context.Context) {
	// Community does not include observability forwarding.
}
