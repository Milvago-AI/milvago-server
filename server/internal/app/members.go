package app

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5"
)

// guardParentControl keeps a child organization from cutting its parent's control
// over it (Enterprise hierarchy). The nearest membership wins, so a direct membership
// written here replaces what a person inherits from an ancestor: a child owner could
// invite a parent owner as viewer, or demote the service-provider account, and the
// parent would lose members.manage on its own child for good (audit of 2026-09-24).
// A person who reaches this organization through its parent may therefore only be
// invited, imported, demoted or removed here by someone who manages members of that
// parent. A pinned credential never resolves the parent, so it fails closed.
func guardParentControl(ctx context.Context, tx pgx.Tx, s *Session, user string) error {
	var above bool
	if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_organizations($1) u JOIN organizations o ON o.parent_id=u.id WHERE o.id=$2)`, user, s.OrganizationID).Scan(&above); e != nil || !above {
		return e
	}
	var manages bool
	if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM organizations o, effective_access($1,o.parent_id) e WHERE o.id=$2 AND 'members.manage'=ANY(e.permissions))`, s.UserID, s.OrganizationID).Scan(&manages); e != nil {
		return e
	}
	if !manages {
		return apiError{403, "inherited_member", "This person's access comes from the parent organization; manage it there."}
	}
	return nil
}

// outsideTree reports whether a person already belongs to an organization tree the
// acting organization neither sits under nor contains: a sibling tenant (Enterprise).
// Adding such an account, or changing what is global to it (its language, its
// sessions), would let one tenant act on another's members without their consent —
// an invitation of a sibling tenant's owner followed by role changes logged them out
// everywhere, as often as wanted (audit of 2026-09-24). The top memberships are the
// reachable organizations whose parent is not reachable; an ancestor of the acting
// organization is guardParentControl's case.
func outsideTree(ctx context.Context, tx pgx.Tx, org, user string) (bool, error) {
	var outside bool
	e := tx.QueryRow(ctx, `WITH RECURSIVE reach AS (SELECT id FROM user_organizations($1)),
up(org) AS (SELECT $2::uuid UNION ALL SELECT o.parent_id FROM organizations o JOIN up ON o.id=up.org WHERE o.parent_id IS NOT NULL),
down(org) AS (SELECT $2::uuid UNION ALL SELECT o.id FROM organizations o JOIN down ON o.parent_id=down.org)
SELECT EXISTS(SELECT 1 FROM reach r JOIN organizations o ON o.id=r.id
 WHERE (o.parent_id IS NULL OR o.parent_id NOT IN (SELECT id FROM reach))
 AND r.id NOT IN (SELECT org FROM up) AND r.id NOT IN (SELECT org FROM down))`, user, org).Scan(&outside)
	return outside, e
}

func (a *App) changeMemberRole(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	var body struct {
		Role string `json:"role"`
	}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	if body.Role == "" {
		return bad("A role is required.")
	}
	return a.mutateMember(w, r, tx, s, body.Role)
}
func (a *App) removeMember(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	return a.mutateMember(w, r, tx, s, "")
}

// changeMemberLanguage sets the console language of a member of the current
// organization. It grants nothing, so — unlike role and removal — it is also
// allowed on one's own account and leaves existing sessions alone.
func (a *App) changeMemberLanguage(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	id := r.PathValue("id")
	if !uuidPattern.MatchString(id) {
		return bad("Invalid member ID.")
	}
	var body struct {
		Language string `json:"language"`
	}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	if !languageAllowed(body.Language) {
		return bad("Language must be one of fr, en, es, pt-BR, or empty to follow the browser.")
	}
	var member bool
	if e := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM memberships WHERE organization_id=$1 AND user_id=$2)`, s.OrganizationID, id).Scan(&member); e != nil {
		return e
	}
	if !member {
		return apiError{404, "member_not_found", "This member does not belong to the organization."}
	}
	if id != s.UserID {
		if e := guardParentControl(r.Context(), tx, s, id); e != nil {
			return e
		}
		if outside, e := outsideTree(r.Context(), tx, s.OrganizationID, id); e != nil {
			return e
		} else if outside {
			return apiError{403, "member_of_other_organization", "This person also belongs to another organization; only they can change their language."}
		}
	}
	if _, e := tx.Exec(r.Context(), `UPDATE users SET language=$1 WHERE id=$2`, body.Language, id); e != nil {
		return e
	}
	if e := audit(r.Context(), tx, s.OrganizationID, s.UserID, "member.language", id); e != nil {
		return e
	}
	if e := tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]string{"id": id, "language": body.Language})
	return nil
}
func (a *App) mutateMember(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session, newRole string) error {
	id := r.PathValue("id")
	if !uuidPattern.MatchString(id) {
		return bad("Invalid member ID.")
	}
	// A user cannot modify or remove their own membership.
	if id == s.UserID {
		return apiError{403, "self_forbidden", "You cannot change your own membership."}
	}
	// Serialize all membership mutations per organization, including the last-owner check.
	if _, e := tx.Exec(r.Context(), `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, s.OrganizationID); e != nil {
		return e
	}
	// The acting role/permissions were resolved (with hierarchy) by console().
	actorRole := s.Role
	var previous string
	if e := tx.QueryRow(r.Context(), `SELECT role FROM memberships WHERE organization_id=$1 AND user_id=$2 FOR UPDATE`, s.OrganizationID, id).Scan(&previous); e == pgx.ErrNoRows {
		return apiError{404, "member_not_found", "This member does not belong to the organization."}
	} else if e != nil {
		return e
	}
	if actorRole != "owner" && (previous == "owner" || newRole == "owner") {
		return forbidden()
	}
	// Removing or demoting is bounded like granting: nobody takes away a role broader
	// than what they hold. Otherwise a key whose creator is an owner could remove every
	// co-owner, and an admin a member holding permissions the admin lacks (2026-09-24).
	if may, e := mayGrantRole(r.Context(), tx, s, previous); e != nil {
		return e
	} else if !may {
		return notGranted()
	}
	if e := guardParentControl(r.Context(), tx, s, id); e != nil {
		return e
	}
	if newRole != "" {
		var exists bool
		if e := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM roles WHERE name=$1)`, newRole).Scan(&exists); e != nil {
			return e
		}
		if !exists {
			return bad("Unknown role for this organization.")
		}
		// A key cannot move a member into a role broader than the key itself
		// holds: promoting a second account is the one way a narrow key could
		// otherwise recover authority the per-request intersection took from it.
		// Checked after the existence test so an unknown role still reads as 400.
		if may, e := mayGrantRole(r.Context(), tx, s, newRole); e != nil {
			return e
		} else if !may {
			return notGranted()
		}
	}
	if previous == "owner" && newRole != "owner" {
		var owners int
		if e := tx.QueryRow(r.Context(), `SELECT count(*) FROM memberships WHERE role='owner'`).Scan(&owners); e != nil {
			return e
		}
		if owners <= 1 {
			return apiError{409, "last_owner", "Assign another owner before removing or demoting the last owner."}
		}
	}
	action := "member.role"
	if newRole == "" {
		action = "member.remove"
		if _, e := tx.Exec(r.Context(), `DELETE FROM memberships WHERE organization_id=$1 AND user_id=$2`, s.OrganizationID, id); e != nil {
			return e
		}
	} else {
		if _, e := tx.Exec(r.Context(), `UPDATE memberships SET role=$1 WHERE organization_id=$2 AND user_id=$3`, newRole, s.OrganizationID, id); e != nil {
			return e
		}
	}
	// Access is resolved on every request, so this is belt and braces; it stays within
	// the acting subtree, never the sessions a person holds in another tenant.
	if _, e := tx.Exec(r.Context(), `WITH RECURSIVE down(org) AS (SELECT $2::uuid UNION ALL SELECT o.id FROM organizations o JOIN down ON o.parent_id=down.org)
DELETE FROM sessions WHERE user_id=$1 AND organization_id IN (SELECT org FROM down)`, id, s.OrganizationID); e != nil {
		return e
	}
	if e := audit(r.Context(), tx, s.OrganizationID, s.UserID, action, id); e != nil {
		return e
	}
	if e := tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]string{"id": id, "role": newRole})
	return nil
}
