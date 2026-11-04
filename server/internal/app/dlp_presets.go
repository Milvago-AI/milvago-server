package app

import (
	"context"
	"github.com/jackc/pgx/v5"
)

func previewDLPTemplates(_ context.Context, _ pgx.Tx, _ string, policy DLPPolicy) (DLPPolicy, error) {
	return policy, nil
}
func seedStoredDLPTemplates(_ context.Context, _ pgx.Tx) error { return nil }

func defaultDLPTemplateIDs(_ DLPPolicy) []string                           { return []string{} }
func initializeDLPDefaultRuleProtection(_ context.Context, _ pgx.Tx) error { return nil }
