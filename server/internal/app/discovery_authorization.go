package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	var canonical any
	decoder := json.NewDecoder(bytes.NewReader(catalog))
	decoder.UseNumber()
	if err = decoder.Decode(&canonical); err != nil {
		return configuration, "", err
	}
	raw, err := json.Marshal(struct {
		SourceRevision int64             `json:"source_revision"`
		Configuration  DiscoverySettings `json:"configuration"`
		Catalog        any               `json:"catalog"`
	}{sourceRevision, configuration, canonical})
	if err != nil {
		return configuration, "", err
	}
	digest := sha256.Sum256(raw)
	return configuration, hex.EncodeToString(digest[:]), nil
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
