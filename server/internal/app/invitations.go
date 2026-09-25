package app

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"
)

func (a *App) invite(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	var body struct {
		Email    string `json:"email"`
		Role     string `json:"role"`
		Language string `json:"language"`
	}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	// The same address rule as the setup wizard, so an invitation never creates an
	// account whose e-mail the sign-in would refuse.
	email, ok := plainAddress(body.Email)
	if !ok || body.Role == "" {
		return bad("Provide a valid email and role.")
	}
	body.Email = email
	if !languageAllowed(body.Language) {
		return bad("Language must be one of fr, en, es, pt-BR, or empty to follow the browser.")
	}
	if body.Role == "owner" && s.Role != "owner" {
		return forbidden()
	}
	// A key cannot invite someone into a role broader than the key itself, which
	// would otherwise turn a narrow key into full authority through a new account.
	if may, e := mayGrantRole(r.Context(), tx, s, body.Role); e != nil {
		return e
	} else if !may {
		return notGranted()
	}
	var known bool
	if e := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM roles WHERE name=$1)`, body.Role).Scan(&known); e != nil {
		return e
	}
	if !known {
		return bad("Unknown role for this organization.")
	}
	admin, e := a.identityAdmin(r.Context())
	if e != nil {
		return e
	}
	lookup := func() (string, error) {
		status, _, raw, e := admin.call("GET", "/users?email="+url.QueryEscape(body.Email)+"&exact=true", nil)
		if e != nil || status != 200 {
			return "", apiError{502, "identity_unavailable", "Could not query identity users."}
		}
		var users []identityUser
		if json.Unmarshal(raw, &users) != nil {
			return "", apiError{502, "identity_unavailable", "Invalid identity administration response."}
		}
		for _, u := range users {
			if strings.EqualFold(u.Email, body.Email) {
				return u.ID, nil
			}
		}
		return "", nil
	}
	subject, e := lookup()
	if e != nil {
		return e
	}
	kind, name := "local", ""
	if subject == "" {
		// No requiredActions on the account itself: the activation link below
		// carries them, so an account later auto-linked to a brokered identity
		// is never asked to set a local password.
		status, _, _, e := admin.call("POST", "/users", map[string]any{"username": body.Email, "email": body.Email, "enabled": true, "emailVerified": false})
		if e != nil || (status != 201 && status != 409) {
			return apiError{502, "identity_unavailable", "Could not create the identity account."}
		}
		if subject, e = lookup(); e != nil {
			return e
		}
		if subject == "" {
			return apiError{502, "identity_unavailable", "The created identity account could not be found."}
		}
	} else {
		// An existing account may be brokered (SSO) or federated (LDAP): its
		// access is then granted without any activation e-mail.
		u, e := admin.user(subject)
		if e != nil {
			return e
		}
		if u == nil {
			return apiError{502, "identity_unavailable", "The identity account could not be read."}
		}
		if kind, e = admin.identityType(u); e != nil {
			return e
		}
		name = u.displayName()
		if kind == "ldap" {
			// Only accounts provided by this organization's own directory may be
			// granted access here (Enterprise: directories of other tenants are
			// never a valid identity source for this organization).
			var component string
			e := tx.QueryRow(r.Context(), `SELECT component_id FROM ldap_directories WHERE organization_id=$1`, s.OrganizationID).Scan(&component)
			if e != nil && !errors.Is(e, pgx.ErrNoRows) {
				return e
			}
			if e != nil || component != u.FederationLink {
				return apiError{409, "directory_mismatch", "This account belongs to a directory that is not this organization's."}
			}
		}
	}
	// The barrier is shared for an addition (see exclusiveBarrier): additions of one
	// account serialize here, before the checks that depend on its other memberships.
	if e = lockAccount(r, tx, subject); e != nil {
		return e
	}
	// Never overwrite a current member's role through an invitation.
	var existing bool
	if e = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM memberships m JOIN users u ON u.id=m.user_id WHERE u.subject=$1)`, subject).Scan(&existing); e != nil {
		return e
	}
	if existing {
		return apiError{409, "already_member", "This account is already a member."}
	}
	// Checked before the invitation e-mail leaves: a refused invitation sends nothing.
	var existingUser string
	if e = tx.QueryRow(r.Context(), `SELECT id FROM users WHERE subject=$1`, subject).Scan(&existingUser); e == nil {
		if e = guardParentControl(r.Context(), tx, s, existingUser); e != nil {
			return e
		}
		if outside, e := outsideTree(r.Context(), tx, s.OrganizationID, existingUser); e != nil {
			return e
		} else if outside {
			return apiError{409, "member_of_other_organization", "This account belongs to another organization. Invite it from an organization that contains both."}
		}
	} else if !errors.Is(e, pgx.ErrNoRows) {
		return e
	}
	if kind == "local" {
		status, _, _, e := admin.call("PUT", "/users/"+url.PathEscape(subject)+"/execute-actions-email?lifespan=86400", []string{"VERIFY_EMAIL", "UPDATE_PASSWORD"})
		if e != nil || status != 204 {
			return apiError{502, "invitation_email_failed", "The identity provider could not send the invitation. Check its SMTP configuration."}
		}
	}
	var user string
	// An account already known here is reused: inviting it into another
	// organization must not reset what it already owns. Like the display name,
	// the stored language survives an invitation that does not choose one.
	if e = tx.QueryRow(r.Context(), `INSERT INTO users(subject,email,display_name,identity_type,language) VALUES($1,$2,$3,$4,$5) ON CONFLICT(subject) DO UPDATE SET email=excluded.email,identity_type=excluded.identity_type,language=CASE WHEN excluded.language<>'' THEN excluded.language ELSE users.language END,display_name=CASE WHEN excluded.display_name<>'' THEN excluded.display_name ELSE users.display_name END RETURNING id`, subject, body.Email, name, kind, body.Language).Scan(&user); e != nil {
		return e
	}
	if _, e = tx.Exec(r.Context(), `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,$3)`, s.OrganizationID, user, body.Role); e != nil {
		return e
	}
	if e = audit(r.Context(), tx, s.OrganizationID, s.UserID, "member.invite", user); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 201, map[string]string{"id": user, "email": body.Email, "role": body.Role, "identity_type": kind, "language": body.Language})
	return nil
}
