package app

import (
	"context"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Permission keys, declared once. A route registration, the catalog and an
// authorization check used to repeat the same literal, so a typo in one of them
// could open or close a route without anything failing to build.
//
// The tests keep the literals on purpose: they pin the wire values these
// constants must keep, which a test written against the constant could not do.
const (
	permOverviewRead        = "overview.read"
	permEventsRead          = "events.read"
	permDevicesRead         = "devices.read"
	permDevicesManage       = "devices.manage"
	permMembersRead         = "members.read"
	permMembersManage       = "members.manage"
	permRolesManage         = "roles.manage"
	permSettingsManage      = "settings.manage"
	permPolicyManage        = "policy.manage"
	permInstallersManage    = "installers.manage"
	permContentRead         = "content.read"
	permContentPurge        = "content.purge"
	permAuditRead           = "audit.read"
	permOrganizationsManage = "organizations.manage"
	permDirectoryManage     = "directory.manage"
	permReportsAggregate    = "reports.aggregate"
	permIdentityReveal      = "identity.reveal"
	permIdentityErase       = "identity.erase"
	permObservabilityManage = "observability.manage"
)

// permissionCatalog is the full set of permission keys. Custom roles may hold
// any subset; built-in roles use the fixed sets below.
var permissionCatalog = append([]string{
	permOverviewRead, permEventsRead, permDevicesRead, permDevicesManage,
	permMembersRead, permMembersManage, permRolesManage, permSettingsManage,
	permPolicyManage, permInstallersManage, permContentRead, permContentPurge, permAuditRead,
	permOrganizationsManage, permDirectoryManage, permReportsAggregate, permIdentityReveal, permIdentityErase,
}, observabilityPermissions...)

// builtinRolePermissions defines the seeded, non-deletable roles.
// owner = everything; admin = everything except audit, roles, organizations, the
// directory, observability, and the destructive or identity-revealing keys
// (identity.reveal, identity.erase, content.purge); viewer = read-only.
//
// These permissions are also stated as SQL literals in db.go -- the seed loop and the
// repair block that follows it. That duplication is deliberate and stays: `roles` is
// tenant-scoped under FORCE RLS, so any DML on it must run inside a per-organization
// loop with the organization context set, which is why the seed is one `DO $$` block
// rather than a set-based statement. Driving it from this map instead would mean a Go
// loop and N round trips on every boot, to remove a duplication rather than a risk.
//
// The risk is removed instead by TestBuiltinRolePermissionsConverge, which reads what
// the database actually holds after a boot AND after a second boot on an
// already-migrated schema, and fails on any drift from this map. Keep the literals in
// step; the test will say so if you do not.
//
// `content.read` joined admin on 2026-09-15 (product decision), when reading retained
// text stopped being a per-member flag and became this permission itself.
//
// `content.purge` is owner-only, added 2026-09-21 (product decision). It guards an
// irreversible mass deletion of the evidence base, which puts it with `identity.erase`
// rather than with `content.read`. Admin keeps `content.read`, the routine act, and
// `settings.manage`, the non-destructive way to shrink what is retained. The console
// shows the purge panel to any role holding this permission
// (shadow/ShadowAdministration.tsx gates on `content.purge`, not on a role name), so
// keeping it owner-only is a policy choice, not a constraint of the interface.
var builtinRolePermissions = map[string][]string{
	"owner": permissionCatalog,
	"admin": {
		permOverviewRead, permEventsRead, permDevicesRead, permDevicesManage,
		permMembersRead, permMembersManage, permSettingsManage, permPolicyManage,
		permInstallersManage, permContentRead, permReportsAggregate,
	},
	"viewer":   {permOverviewRead, permEventsRead, permDevicesRead, permReportsAggregate},
	"reporter": {permOverviewRead, permReportsAggregate},
}

// seedBuiltinRoles inserts the built-in roles for a freshly created organization
// (the org context must already be set for RLS). Idempotent.
func seedBuiltinRoles(ctx context.Context, tx pgx.Tx, org string) error {
	_, e := tx.Exec(ctx,
		`INSERT INTO roles(organization_id,name,permissions,builtin) VALUES ($1,'owner',$2,true),($1,'admin',$3,true),($1,'viewer',$4,true),($1,'reporter',$5,true) ON CONFLICT (organization_id,name) DO NOTHING`,
		org, builtinRolePermissions["owner"], builtinRolePermissions["admin"], builtinRolePermissions["viewer"], builtinRolePermissions["reporter"])
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, "INSERT INTO privacy_settings(organization_id) VALUES($1) ON CONFLICT DO NOTHING", org)
	return e
}

func validPermissions(perms []string) bool {
	for _, p := range perms {
		if !hasPermission(permissionCatalog, p) {
			return false
		}
	}
	return true
}

func (a *App) roles(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	rows, e := tx.Query(r.Context(), `SELECT name,permissions,builtin FROM roles ORDER BY builtin DESC,name`)
	if e != nil {
		return e
	}
	defer rows.Close()
	type role struct {
		Name        string   `json:"name"`
		Permissions []string `json:"permissions"`
		Builtin     bool     `json:"builtin"`
	}
	items := []role{}
	for rows.Next() {
		var it role
		if e := rows.Scan(&it.Name, &it.Permissions, &it.Builtin); e != nil {
			return e
		}
		items = append(items, it)
	}
	if e := rows.Err(); e != nil {
		return e
	}
	reply(w, 200, map[string]any{"items": items, "catalog": permissionCatalog})
	return nil
}

// roleMemberLimit caps the list returned with a role_in_use conflict; the total
// count is always exact so the console can say how many are left.
const roleMemberLimit = 50

type roleMember struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

// roleHolders lists the members of the current organization that hold a role.
// RLS scopes memberships to that organization, which is exactly the set that
// blocks a deletion.
func roleHolders(ctx context.Context, tx pgx.Tx, name string) ([]roleMember, int, error) {
	var total int
	if e := tx.QueryRow(ctx, `SELECT count(*) FROM memberships WHERE role=$1`, name).Scan(&total); e != nil {
		return nil, 0, e
	}
	rows, e := tx.Query(ctx, `SELECT u.id,u.email,u.display_name FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.role=$1 ORDER BY u.email LIMIT $2`, name, roleMemberLimit)
	if e != nil {
		return nil, 0, e
	}
	defer rows.Close()
	items := []roleMember{}
	for rows.Next() {
		var it roleMember
		if e := rows.Scan(&it.ID, &it.Email, &it.DisplayName); e != nil {
			return nil, 0, e
		}
		items = append(items, it)
	}
	return items, total, rows.Err()
}

// roleMembers answers "who still holds this role?" so the console can offer the
// reassignment or removal that unblocks a deletion.
func (a *App) roleMembers(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if s.Role != "owner" {
		return forbidden()
	}
	items, total, e := roleHolders(r.Context(), tx, r.PathValue("name"))
	if e != nil {
		return e
	}
	reply(w, 200, map[string]any{"items": items, "total": total})
	return nil
}

func (a *App) createRole(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if s.Role != "owner" {
		return forbidden()
	}
	var body struct {
		Name        string   `json:"name"`
		Permissions []string `json:"permissions"`
	}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	body.Name = strings.TrimSpace(body.Name)
	if len(body.Name) < 1 || len(body.Name) > 60 {
		return bad("Role name must contain 1 to 60 characters.")
	}
	if _, reserved := builtinRolePermissions[body.Name]; reserved {
		return bad("This role name is reserved.")
	}
	if !validPermissions(body.Permissions) {
		return bad("Unknown permission.")
	}
	// A key must not define a role carrying more than the key itself holds:
	// otherwise a narrow key assigns that role to a second account and the
	// per-request intersection has been walked around rather than enforced.
	if !s.mayGrant(body.Permissions) {
		return notGranted()
	}
	tag, e := tx.Exec(r.Context(), `INSERT INTO roles(organization_id,name,permissions,builtin) VALUES($1,$2,$3,false) ON CONFLICT (organization_id,name) DO NOTHING`, s.OrganizationID, body.Name, body.Permissions)
	if e != nil {
		return e
	}
	if tag.RowsAffected() == 0 {
		return apiError{409, "role_exists", "A role with this name already exists."}
	}
	if e := audit(r.Context(), tx, s.OrganizationID, s.UserID, "role.create", body.Name); e != nil {
		return e
	}
	if e := tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 201, map[string]any{"name": body.Name, "permissions": body.Permissions, "builtin": false})
	return nil
}

func (a *App) updateRole(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if s.Role != "owner" {
		return forbidden()
	}
	name := r.PathValue("name")
	var body struct {
		Permissions []string `json:"permissions"`
	}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	if !validPermissions(body.Permissions) {
		return bad("Unknown permission.")
	}
	if !s.mayGrant(body.Permissions) {
		return notGranted()
	}
	tag, e := tx.Exec(r.Context(), `UPDATE roles SET permissions=$1 WHERE name=$2 AND NOT builtin`, body.Permissions, name)
	if e != nil {
		return e
	}
	if tag.RowsAffected() == 0 {
		return apiError{404, "role_not_editable", "Only custom roles can be edited."}
	}
	if e := audit(r.Context(), tx, s.OrganizationID, s.UserID, "role.update", name); e != nil {
		return e
	}
	if e := tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]any{"name": name, "permissions": body.Permissions, "builtin": false})
	return nil
}

func (a *App) deleteRole(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if s.Role != "owner" {
		return forbidden()
	}
	name := r.PathValue("name")
	// A user can never delete the role they currently hold in this organization.
	if name == s.Role {
		return apiError{409, "own_role", "You cannot delete the role you currently hold."}
	}
	_, used, e := roleHolders(r.Context(), tx, name)
	if e != nil {
		return e
	}
	if used > 0 {
		return apiError{409, "role_in_use", "Reassign the members that hold this role before deleting it."}
	}
	tag, e := tx.Exec(r.Context(), `DELETE FROM roles WHERE name=$1 AND NOT builtin`, name)
	if e != nil {
		return e
	}
	if tag.RowsAffected() == 0 {
		return apiError{404, "role_not_found", "Only custom roles can be deleted."}
	}
	if e := audit(r.Context(), tx, s.OrganizationID, s.UserID, "role.delete", name); e != nil {
		return e
	}
	if e := tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]bool{"ok": true})
	return nil
}
