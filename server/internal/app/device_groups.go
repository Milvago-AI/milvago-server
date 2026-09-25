package app

import (
	"context"
	// Required by go:embed directives in this file.
	_ "embed"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

//go:embed device_groups_migration.sql
var deviceGroupsMigration string

const (
	msgInvalidGroupID = "Invalid group ID."
)

// deviceGroupLimit bounds the groups one organization may hold. Far above any
// real fleet layout, and a hard stop for a credential used to flood the table.
const deviceGroupLimit = 200

func initializeDeviceGroups(ctx context.Context, tx pgx.Tx, role string) error {
	if _, e := tx.Exec(ctx, deviceGroupsMigration); e != nil {
		return fmt.Errorf("device groups migration: %w", e)
	}
	_, e := tx.Exec(ctx, `GRANT SELECT,INSERT,UPDATE,DELETE ON device_groups,shadow_group_overrides TO `+role)
	return e
}

func (a *App) registerDeviceGroupRoutes() {
	a.console("GET /api/groups", permDevicesRead, a.deviceGroups)
	a.console("POST /api/groups", permDevicesManage, a.createDeviceGroup)
	a.console("PUT /api/groups/{id}", permDevicesManage, a.updateDeviceGroup)
	a.console("DELETE /api/groups/{id}", permDevicesManage, a.deleteDeviceGroup)
	a.console("PUT /api/devices/{id}/group", permDevicesManage, a.assignDeviceGroup)
	a.console("GET /api/groups/{id}/shadow", permPolicyManage, a.groupShadowSettings)
	a.console("PUT /api/groups/{id}/shadow", permPolicyManage, a.putGroupShadow)
}

func groupNotFound() error { return apiError{404, "group_not_found", "Device group not found."} }

type deviceGroupBody struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (b *deviceGroupBody) validate() error {
	b.Name = strings.TrimSpace(b.Name)
	b.Description = strings.TrimSpace(b.Description)
	if n := len([]rune(b.Name)); n < 1 || n > 80 {
		return bad("Group name must contain 1 to 80 characters.")
	}
	if len([]rune(b.Description)) > 300 {
		return bad("Group description must not exceed 300 characters.")
	}
	for _, r := range b.Name + b.Description {
		if unicode.IsControl(r) {
			return bad("Group name and description cannot contain control characters.")
		}
	}
	return nil
}

// groupView is the JSON shape of one group in every answer of this file.
const groupView = `jsonb_build_object('id',g.id,'name',g.name,'description',g.description,'device_count',(SELECT count(*) FROM devices d WHERE d.group_id=g.id),'created_at',g.created_at,'updated_at',g.updated_at)`

func (a *App) deviceGroups(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	return jsonQuery(w, r, tx, `SELECT jsonb_build_object('items',COALESCE(jsonb_agg(`+groupView+` ORDER BY g.name),'[]'::jsonb)) FROM device_groups g`)
}

// duplicateGroupName refuses two groups that differ only by case: the unique
// index is exact, and an administrator reading "Sales" next to "sales" cannot
// tell which one a device follows.
func duplicateGroupName(ctx context.Context, tx pgx.Tx, name, except string) error {
	var exists bool
	if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM device_groups WHERE lower(name)=lower($1) AND id::text<>$2)`, name, except).Scan(&exists); e != nil {
		return e
	}
	if exists {
		return apiError{409, "group_exists", "A device group with this name already exists."}
	}
	return nil
}

// uniqueViolation turns the race two concurrent creations can still lose into
// the same 409 the pre-check answers, instead of a 500.
func uniqueViolation(e error) error {
	var pg *pgconn.PgError
	if errors.As(e, &pg) && pg.Code == "23505" {
		return apiError{409, "group_exists", "A device group with this name already exists."}
	}
	return e
}

func (a *App) createDeviceGroup(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	var body deviceGroupBody
	if e := decode(w, r, &body); e != nil {
		return e
	}
	if e := body.validate(); e != nil {
		return e
	}
	// Creations of one organization serialize, so parallel requests cannot all read
	// the count below the ceiling and all insert.
	if _, e := tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtextextended('milvago-groups:'||$1,0))`, s.OrganizationID); e != nil {
		return e
	}
	var count int
	if e := tx.QueryRow(r.Context(), `SELECT count(*) FROM device_groups`).Scan(&count); e != nil {
		return e
	}
	if count >= deviceGroupLimit {
		return apiError{409, "group_limit", "This organization has reached the maximum number of device groups."}
	}
	if e := duplicateGroupName(r.Context(), tx, body.Name, ""); e != nil {
		return e
	}
	var id string
	if e := tx.QueryRow(r.Context(), `INSERT INTO device_groups(organization_id,name,description) VALUES($1,$2,$3) RETURNING id`, s.OrganizationID, body.Name, body.Description).Scan(&id); e != nil {
		return uniqueViolation(e)
	}
	if e := audit(r.Context(), tx, s.OrganizationID, s.UserID, "device_group.create", id); e != nil {
		return e
	}
	var view []byte
	if e := tx.QueryRow(r.Context(), `SELECT `+groupView+` FROM device_groups g WHERE g.id=$1`, id).Scan(&view); e != nil {
		return e
	}
	if e := tx.Commit(r.Context()); e != nil {
		return e
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	_, _ = w.Write(view)
	return nil
}

func (a *App) updateDeviceGroup(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	id := r.PathValue("id")
	if !uuidPattern.MatchString(id) {
		return bad(msgInvalidGroupID)
	}
	var body deviceGroupBody
	if e := decode(w, r, &body); e != nil {
		return e
	}
	if e := body.validate(); e != nil {
		return e
	}
	if e := duplicateGroupName(r.Context(), tx, body.Name, id); e != nil {
		return e
	}
	command, e := tx.Exec(r.Context(), `UPDATE device_groups SET name=$2,description=$3,updated_at=now() WHERE id=$1`, id, body.Name, body.Description)
	if e != nil {
		return uniqueViolation(e)
	}
	if command.RowsAffected() != 1 {
		return groupNotFound()
	}
	if e = audit(r.Context(), tx, s.OrganizationID, s.UserID, "device_group.update", id); e != nil {
		return e
	}
	var view []byte
	if e = tx.QueryRow(r.Context(), `SELECT `+groupView+` FROM device_groups g WHERE g.id=$1`, id).Scan(&view); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(view)
	return nil
}

// deleteDeviceGroup detaches the members before removing the group. Each
// detached device draws a fresh group_revision so its effective policy revision
// keeps growing; the cascade then removes the group's override.
func (a *App) deleteDeviceGroup(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	id := r.PathValue("id")
	if !uuidPattern.MatchString(id) {
		return bad(msgInvalidGroupID)
	}
	if _, e := tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(7069202)`); e != nil {
		return e
	}
	// The members fall back to the organization's policy: when the group kept them
	// from retaining prompts and the organization retains them, deleting the group
	// switches retention on for all of them, like moving them out one by one.
	var exists bool
	if e := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM device_groups WHERE id=$1)`, id).Scan(&exists); e != nil {
		return e
	}
	if exists {
		group, e := a.groupShadow(r.Context(), tx, s.OrganizationID, id)
		if e != nil {
			return e
		}
		org, e := a.readShadow(r.Context(), tx, s.OrganizationID, 0)
		if e != nil {
			return e
		}
		if org.Config.Collection.StoreContent && !group.Config.Collection.StoreContent {
			if e = a.requireFreshPerson(r, tx, s); e != nil {
				return e
			}
		}
	}
	if _, e := tx.Exec(r.Context(), `UPDATE devices SET group_id=NULL,group_revision=nextval('shadow_revision') WHERE group_id=$1`, id); e != nil {
		return e
	}
	command, e := tx.Exec(r.Context(), `DELETE FROM device_groups WHERE id=$1`, id)
	if e != nil {
		return e
	}
	if command.RowsAffected() != 1 {
		return groupNotFound()
	}
	if e = audit(r.Context(), tx, s.OrganizationID, s.UserID, "device_group.delete", id); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]bool{"ok": true})
	return nil
}

// assignDeviceGroup moves a device into a group, or out of any group with a null
// group_id. Row-level security hides the groups of other organizations, so a
// foreign identifier reads exactly like an unknown one.
func (a *App) assignDeviceGroup(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	id := r.PathValue("id")
	if !uuidPattern.MatchString(id) {
		return bad("Invalid device ID.")
	}
	var body struct {
		GroupID *string `json:"group_id"`
	}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	if body.GroupID != nil && !uuidPattern.MatchString(*body.GroupID) {
		return bad(msgInvalidGroupID)
	}
	// Exclusive with the ingestion path, like every policy writer: an event
	// batch must see the revision before or after the move, never a mix.
	if _, e := tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(7069202)`); e != nil {
		return e
	}
	var current *string
	if tx.QueryRow(r.Context(), `SELECT group_id FROM devices WHERE id=$1 FOR UPDATE`, id).Scan(&current) != nil {
		return apiError{404, "device_not_found", "This device does not exist in this organization."}
	}
	if body.GroupID != nil {
		var exists bool
		if e := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM device_groups WHERE id=$1)`, *body.GroupID).Scan(&exists); e != nil {
			return e
		}
		if !exists {
			return groupNotFound()
		}
	}
	unchanged := (current == nil && body.GroupID == nil) || (current != nil && body.GroupID != nil && *current == *body.GroupID)
	if !unchanged {
		// Moving a device into a group that retains prompts switches retention on for
		// it: the same guard as switching it on in the settings themselves.
		before, e := a.effectiveShadow(r.Context(), tx, s.OrganizationID, id)
		if e != nil {
			return e
		}
		if _, e := tx.Exec(r.Context(), `UPDATE devices SET group_id=$2,group_revision=nextval('shadow_revision') WHERE id=$1`, id, body.GroupID); e != nil {
			return e
		}
		after, e := a.effectiveShadow(r.Context(), tx, s.OrganizationID, id)
		if e != nil {
			return e
		}
		if after.Config.Collection.StoreContent && !before.Config.Collection.StoreContent {
			if e = a.requireFreshPerson(r, tx, s); e != nil {
				return e
			}
		}
		if e := audit(r.Context(), tx, s.OrganizationID, s.UserID, "device.group", id); e != nil {
			return e
		}
		if e := tx.Commit(r.Context()); e != nil {
			return e
		}
	}
	reply(w, 200, map[string]any{"id": id, "group_id": body.GroupID})
	return nil
}
