package app

import (
	"context"
	"github.com/jackc/pgx/v5"
)

// Seed only newly created organizations. An upgrade must preserve the existing
// inspection consent, including legacy configurations without a dedicated row.
func seedNewDLPDefaults(ctx context.Context, tx pgx.Tx, org string) error {
	var previous string
	if err := tx.QueryRow(ctx, `SELECT COALESCE(current_setting('milvago.organization_id',true),'')`).Scan(&previous); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, sqlSetOrganizationContext, org); err != nil {
		return err
	}
	policy := defaultDLP("endpoint")
	policy.Inspection = true
	policy.NativeInspection = Edition == "commercial"
	policy.Journal = true
	policy = withDefaultDLPDetectors(policy)
	var err error
	policy, err = previewDLPTemplates(ctx, tx, org, policy)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO dlp_settings(organization_id,domain,scope_kind,scope_id,policy,default_rule_ids) VALUES($1,'endpoint','organization',$1,$2,$3) ON CONFLICT DO NOTHING`, org, dlpJSON(policy), dlpJSON(defaultDLPTemplateIDs(policy)))
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, sqlSetOrganizationContext, previous)
	return err
}

func seedBootstrapDLPDefaults(ctx context.Context, tx pgx.Tx) error {
	var org string
	if err := tx.QueryRow(ctx, `SELECT COALESCE(current_setting('milvago.new_dlp_organization',true),'')`).Scan(&org); err != nil {
		return err
	}
	if org == "" {
		return nil
	}
	return seedNewDLPDefaults(ctx, tx, org)
}
