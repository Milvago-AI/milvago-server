package app

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

// One durable deployment credential per organization.
//
// It replaces the short-lived, per-platform installation package. Windows
// receives it in a separately authorized provisioning file; the generic MSI has
// no organization secret. Linux still carries it in the assembled RPM. The device
// presents the key once at `/v2/install` and receives a credential of its own.
// The console reports whether a key exists, when it last rotated, and offers to
// rotate or revoke it. Revealing Windows provisioning requires recent MFA.
//
// It is deliberately durable: a fleet deployed by GPO or an endpoint manager must not
// need a fresh package every thirty days. What bounds the exposure instead is that it
// only ever buys an enrollment, that the device it creates is subject to the
// organization's approval policy, and that rotating it invalidates every installer
// already distributed.
type DeploymentKey struct {
	ID        string     `json:"id"`
	CreatedAt time.Time  `json:"created_at"`
	RotatedAt *time.Time `json:"rotated_at,omitempty"`
	Uses      int        `json:"uses"`
}

// A deployment key does not expire on its own. The column is kept because the
// resolution function and the package model share it; a far horizon means "no
// expiry" without loosening the query that reads it.
const deploymentHorizon = 100 * 365 * 24 * time.Hour

// mintDeploymentKey issues an organization's key. Called when an organization is
// created, and again on rotation.
func (a *App) mintDeploymentKey(ctx context.Context, tx pgx.Tx, org string) error {
	token := randomToken()
	sealed, e := a.sealShadow(org, "deployment-key:"+org, []byte(token))
	if e != nil {
		return e
	}
	// A key that replaces one records when the replacement happened; the first key of
	// an organization has no rotation date, which is what the console shows.
	_, e = tx.Exec(ctx, `INSERT INTO installer_profiles(organization_id,secret_hash,secret_ciphertext,edition,platform,version,expires_at,max_uses,rotated_at)
		VALUES($1,$2,$3,$4,NULL,'',now()+$5::interval,$6,
		  (SELECT now() FROM installer_profiles WHERE organization_id=$1 AND platform IS NULL LIMIT 1))`,
		org, hash(token), sealed, Edition, deploymentHorizon.String(), 10_000)
	return e
}

// deploymentKey reads the organization's active key. `platform IS NULL` is what
// separates a durable key from a package of the retired per-platform model. The secret itself is never part
// of what this returns.
func (a *App) deploymentKey(ctx context.Context, tx pgx.Tx, org string) (*DeploymentKey, error) {
	var key DeploymentKey
	e := tx.QueryRow(ctx, `SELECT id,created_at,rotated_at,uses FROM installer_profiles
		WHERE organization_id=$1 AND platform IS NULL AND NOT revoked AND expires_at>now() ORDER BY created_at DESC LIMIT 1`, org).
		Scan(&key.ID, &key.CreatedAt, &key.RotatedAt, &key.Uses)
	if e == pgx.ErrNoRows {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	return &key, nil
}

// retireDeploymentKeys revokes every active key of an organization and destroys the
// stored copies. An installer already distributed stops working immediately; devices
// already installed are untouched, and stay independently revocable.
func (a *App) retireDeploymentKeys(ctx context.Context, tx pgx.Tx, org string) error {
	// Only the key itself is destroyed. The per-installation ciphertexts are left
	// alone deliberately: they are what lets an MSI repair recover a device instead
	// of creating a second one, and a rotation is a routine act. Nothing is gained
	// by erasing them, because a retired key is refused at the first lookup and can
	// no longer reach them at all.
	_, e := tx.Exec(ctx, `UPDATE installer_profiles SET revoked=true,revoked_at=now(),secret_ciphertext='' WHERE organization_id=$1 AND platform IS NULL AND NOT revoked`, org)
	return e
}

// targetOrganization resolves which organization a request acts on, and re-checks the
// permission **against that organization** rather than against the session's — a
// parent owner acting on a child must be authorized by the child.
//
// The tenant setting follows, because row-level security compares against it and
// nothing else. Without an identifier in the path, the session's own organization is
// the target, which is how Community reaches this at all.
func (a *App) targetOrganization(r *http.Request, tx pgx.Tx, s *Session, permission string) (string, error) {
	id := r.PathValue("id")
	if id == "" || id == s.OrganizationID {
		return s.OrganizationID, nil
	}
	if Edition != "commercial" || !uuidPattern.MatchString(id) {
		return "", forbidden()
	}
	// permissionsFor applies the API key's own subset and refuses any organization
	// but the key's own; effective_access enforces that pin in SQL as well, so a
	// route added later fails closed even if it forgets this helper.
	perms, e := a.permissionsFor(r.Context(), tx, s, id)
	if e != nil || !hasPermission(perms, permission) {
		return "", forbidden()
	}
	if _, e := tx.Exec(r.Context(), `SELECT set_config('milvago.organization_id',$1,true)`, id); e != nil {
		return "", e
	}
	return id, nil
}

func (a *App) organizationKey(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	org, e := a.targetOrganization(r, tx, s, permInstallersManage)
	if e != nil {
		return e
	}
	key, e := a.deploymentKey(r.Context(), tx, org)
	if e != nil {
		return e
	}
	reply(w, 200, map[string]any{"key": key})
	return nil
}

func (a *App) rotateOrganizationKey(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	return a.changeDeploymentKey(w, r, tx, s, true)
}

func (a *App) revokeOrganizationKey(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	return a.changeDeploymentKey(w, r, tx, s, false)
}

func (a *App) changeDeploymentKey(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session, mint bool) error {
	org, e := a.targetOrganization(r, tx, s, permInstallersManage)
	if e != nil {
		return e
	}
	if e = a.retireDeploymentKeys(r.Context(), tx, org); e != nil {
		return e
	}
	action := "deployment_key.revoke"
	if mint {
		if e = a.mintDeploymentKey(r.Context(), tx, org); e != nil {
			return e
		}
		action = "deployment_key.rotate"
	}
	// The tenant setting now names the target organization, and the audit table is
	// under FORCE row-level security with a WITH CHECK on it: auditing against the
	// session's organization here rolls the whole rotation back.
	if e = audit(r.Context(), tx, org, s.UserID, action, org); e != nil {
		return e
	}
	key, e := a.deploymentKey(r.Context(), tx, org)
	if e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]any{"key": key})
	return nil
}

// ensureDeploymentKeys gives every organization a key at startup: the root
// organization the boot migration creates, and any organization that predates the
// durable key. It only ever mints where none is active, so restarting is a no-op.
func (a *App) ensureDeploymentKeys(ctx context.Context) error {
	rows, e := a.db.Query(ctx, `SELECT id FROM organizations`)
	if e != nil {
		return e
	}
	var orgs []string
	for rows.Next() {
		var org string
		if e = rows.Scan(&org); e != nil {
			rows.Close()
			return e
		}
		orgs = append(orgs, org)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return e
	}
	for _, org := range orgs {
		tx, e := tenantTx(ctx, a.db, org)
		if e != nil {
			return e
		}
		// Mint only where the organization has never had a key. Minting wherever
		// none is *active* would quietly undo a deliberate revocation on the next
		// restart, and the console has just promised the administrator that no
		// installation is possible until they issue one themselves.
		var existing bool
		e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM installer_profiles WHERE organization_id=$1 AND platform IS NULL)`, org).Scan(&existing)
		if e == nil && !existing {
			e = a.mintDeploymentKey(ctx, tx, org)
		}
		if e == nil {
			e = tx.Commit(ctx)
		} else {
			tx.Rollback(ctx)
		}
		if e != nil {
			return e
		}
	}
	return nil
}
