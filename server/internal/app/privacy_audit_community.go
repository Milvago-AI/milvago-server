//go:build !commercial

package app

import (
	"context"
	"github.com/jackc/pgx/v5"
)

func enqueuePrivacyAudit(context.Context, pgx.Tx, string, string) error { return nil }
