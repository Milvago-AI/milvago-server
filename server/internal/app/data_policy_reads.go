package app

import (
	"context"
	"encoding/json"
	"maps"
	"slices"

	"github.com/jackc/pgx/v5"
)

// effectiveShadowBatch resolves a bounded page on the caller's tenant transaction.
// The organization is read once; joins retrieve all group/device overrides in one
// round trip. There is no cross-request cache or additional pooled connection.
func (a *App) effectiveShadowBatch(ctx context.Context, tx pgx.Tx, org string, ids []string) (map[string]ShadowSettings, error) {
	out := map[string]ShadowSettings{}
	if len(ids) == 0 {
		return out, nil
	}
	if len(ids) > 100 {
		return nil, bad("Policy read page exceeds 100 devices.")
	}
	base, err := a.readShadow(ctx, tx, org, 0)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT d.id,d.group_id,d.group_revision,g.name,
 COALESCE(gp.revision,0),gp.configuration,COALESCE(dp.revision,0),dp.configuration
 FROM devices d LEFT JOIN device_groups g ON g.organization_id=d.organization_id AND g.id=d.group_id
 LEFT JOIN shadow_group_overrides gp ON gp.organization_id=d.organization_id AND gp.group_id=d.group_id
 LEFT JOIN shadow_device_overrides dp ON dp.organization_id=d.organization_id AND dp.device_id=d.id
 WHERE d.organization_id=$1 AND d.id=ANY($2::uuid[])`, org, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var group, name *string
		var assigned, groupRev, deviceRev int64
		var groupRaw, deviceRaw map[string]json.RawMessage
		if err = rows.Scan(&id, &group, &assigned, &name, &groupRev, &groupRaw, &deviceRev, &deviceRaw); err != nil {
			return nil, err
		}
		if group != nil && name == nil {
			return nil, pgx.ErrNoRows
		}
		if groupRaw == nil {
			groupRev = 0
		}
		v := base
		v.Capabilities = maps.Clone(base.Capabilities)
		v.ModelCatalog = slices.Clone(base.ModelCatalog)
		for i := range v.ModelCatalog {
			v.ModelCatalog[i].Models = slices.Clone(v.ModelCatalog[i].Models)
		}
		v.InheritedFrom = map[string]InheritedFrom{}
		for section, origin := range base.InheritedFrom {
			v.InheritedFrom[section] = origin
		}
		// A fresh decode also isolates every nested slice/map from the organization
		// and the other devices, even when neither level has a stored override.
		v.Config, err = overlayShadow(base.Config, groupRaw)
		if err != nil {
			return nil, err
		}
		if group != nil && groupRaw != nil {
			for section := range groupRaw {
				v.InheritedFrom[section] = InheritedFrom{GroupID: *group, Name: *name}
			}
		}
		if deviceRaw != nil {
			v.Config, err = overlayShadow(v.Config, deviceRaw)
			if err != nil {
				return nil, err
			}
		}
		v.Revision += max(assigned, groupRev) + deviceRev
		v.InheritSections = inheritedSections(deviceRaw)
		out[id] = v
	}
	return out, rows.Err()
}
