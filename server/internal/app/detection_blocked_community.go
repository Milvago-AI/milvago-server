//go:build !commercial

package app

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// Community blocks no known platform: the table does not exist in this edition.
func blockedPlatformSet(context.Context, pgx.Tx) (map[string]bool, error) { return nil, nil }

func blockedPlatformPolicy(context.Context, pgx.Tx, DetectionContent) ([]BlockedPlatform, error) {
	return nil, nil
}
