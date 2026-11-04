//go:build !commercial

package app

import (
	"context"
	"github.com/jackc/pgx/v5"
)

func (a *App) aiGovernanceAncestors(context.Context, pgx.Tx, string) ([]aiGovernanceLayer, error) {
	return []aiGovernanceLayer{}, nil
}
