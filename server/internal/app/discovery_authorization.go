package app

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
)

func (a *App) effectiveDiscovery(ctx context.Context, tx pgx.Tx, org, device string, sourceRevision int64, configuration DiscoverySettings, catalog json.RawMessage) (DiscoverySettings, string, error) {
	shadow, err := a.effectiveShadow(ctx, tx, org, device)
	if err != nil {
		return configuration, "", err
	}
	if !shadow.Config.Collection.Enabled {
		configuration = DiscoverySettings{IntervalSeconds: configuration.IntervalSeconds}
	}
	// Consent is freshly resolved above, even when the pure digest is reusable.
	fingerprint, err := a.discoveryFingerprints.fingerprint(org, sourceRevision, configuration, catalog)
	return configuration, fingerprint, err
}

func discoveryDeliveryRevision(ctx context.Context, tx pgx.Tx, org, device, fingerprint string) (int64, error) {
	var revision int64
	var current string
	err := tx.QueryRow(ctx, `SELECT revision,fingerprint FROM discovery_device_authorizations WHERE organization_id=$1 AND device_id=$2 FOR UPDATE`, org, device).Scan(&revision, &current)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `INSERT INTO discovery_device_authorizations(organization_id,device_id,fingerprint) VALUES($1,$2,$3) RETURNING revision`, org, device, fingerprint).Scan(&revision)
		return revision, err
	}
	if err != nil {
		return 0, err
	}
	if current != fingerprint {
		err = tx.QueryRow(ctx, `UPDATE discovery_device_authorizations SET fingerprint=$3,revision=nextval('shadow_revision') WHERE organization_id=$1 AND device_id=$2 RETURNING revision`, org, device, fingerprint).Scan(&revision)
	}
	return revision, err
}
