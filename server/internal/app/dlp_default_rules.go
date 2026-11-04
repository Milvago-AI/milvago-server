package app

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
)

func readDLPDefaultRules(ctx context.Context, tx pgx.Tx, domain, kind, id string) ([]string, error) {
	ids := []string{}
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT default_rule_ids FROM dlp_settings WHERE domain=$1 AND scope_kind=$2 AND scope_id=$3`, domain, kind, id).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return ids, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(raw, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// Default provenance belongs to the stored scope, never to a client flag or ID prefix.
func protectDLPDefaultRules(ctx context.Context, tx pgx.Tx, domain, kind, id string, old DLPSettings, next DLPPolicy, inherited bool) (DLPPolicy, []string, bool, error) {
	var raw, idsRaw []byte
	err := tx.QueryRow(ctx, `SELECT policy,default_rule_ids FROM dlp_settings WHERE domain=$1 AND scope_kind=$2 AND scope_id=$3`, domain, kind, id).Scan(&raw, &idsRaw)
	exists := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return next, nil, false, err
	}
	ids := []string{}
	if exists {
		if err = json.Unmarshal(idsRaw, &ids); err != nil {
			return next, nil, false, err
		}
	} else if !old.Inherited {
		ids = append(ids, old.DefaultRuleIDs...)
	}
	// Inheritance suspends the local policy; keep its protected objects as dormant data.
	if inherited && len(ids) > 0 {
		stored := old.Policy
		if exists {
			if err = json.Unmarshal(raw, &stored); err != nil {
				return next, nil, false, err
			}
		}
		return stored, ids, true, nil
	}
	remaining := map[string]bool{}
	for _, rule := range next.Rules {
		remaining[rule.ID] = true
	}
	protected := map[string]bool{}
	for _, id := range ids {
		if !remaining[id] {
			return next, nil, false, apiError{409, "dlp_default_rule_protected", "Default DLP rules cannot be deleted. Disable them instead."}
		}
		protected[id] = true
	}
	// A new local copy may adopt defaults from the effective source policy.
	for _, id := range old.DefaultRuleIDs {
		if remaining[id] && !protected[id] {
			ids = append(ids, id)
			protected[id] = true
		}
	}
	return next, ids, false, nil
}
