package app

import (
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Self-service profile actions are delegated to Keycloak Application Initiated
// Actions (kc_action). The map keys are the only values accepted on
// /auth/login?action= ; the server decides per identity type which ones a
// signed-in user may trigger.
var profileActions = map[string]string{
	"update_profile":  "UPDATE_PROFILE",
	"update_email":    "UPDATE_EMAIL",
	"update_password": "UPDATE_PASSWORD",
	"configure_totp":  "CONFIGURE_TOTP",
}

// profileActionAllowed enforces who manages what: an SSO (brokered) account is
// entirely managed by its identity provider; an LDAP account only owns its
// Keycloak second factor; a local account owns everything.
func profileActionAllowed(identityType, action string) bool {
	switch identityType {
	case "sso":
		return false
	case "ldap":
		return action == "configure_totp" || action == "manage_mfa"
	}
	return true
}

// splitName is the fallback when identity administration cannot be reached:
// the stored display name is cut at its first space, matching how Keycloak
// joins firstName and lastName into the "name" claim.
func splitName(display string) (string, string) {
	display = strings.TrimSpace(display)
	if i := strings.Index(display, " "); i >= 0 {
		return display[:i], strings.TrimSpace(display[i+1:])
	}
	return display, ""
}

func (a *App) profile(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	kind := s.IdentityType
	if kind == "" {
		kind = "local"
	}
	var language string
	if e := tx.QueryRow(r.Context(), `SELECT language FROM users WHERE id=$1`, s.UserID).Scan(&language); e != nil {
		return e
	}
	first, last := splitName(s.DisplayName)
	// Whether an OTP credential exists is only known to Keycloak; report null
	// when identity administration is unavailable rather than guessing.
	var mfaConfigured any
	if admin, e := a.identityAdmin(r.Context()); e == nil {
		if u, e := admin.user(r.Context(), s.Subject); e == nil && u != nil {
			first, last = strings.TrimSpace(u.FirstName), strings.TrimSpace(u.LastName)
		}
		if configured, e := admin.hasOTP(r.Context(), s.Subject); e == nil {
			mfaConfigured = configured
		}
	}
	reply(w, 200, map[string]any{
		"email":          s.Email,
		"display_name":   s.DisplayName,
		"first_name":     first,
		"last_name":      last,
		"language":       language,
		"identity_type":  kind,
		"mfa_configured": mfaConfigured,
		"editable": map[string]bool{
			"profile":  profileActionAllowed(kind, "update_profile"),
			"email":    profileActionAllowed(kind, "update_email"),
			"password": profileActionAllowed(kind, "update_password"),
			"mfa":      profileActionAllowed(kind, "configure_totp"),
		},
	})
	return nil
}

// languageAllowed accepts the supported console languages, plus the empty
// value meaning "follow this reader's browser" — resolved by the console, which
// is the only side that knows what the browser asks for (product decision,
// 2026-09-17); English answers a browser asking for none of them.
// consoleLanguages is the single list the whole server validates against: the
// column CHECK in migration.sql, this gate, the instance default and the
// ui_locales passed to the identity provider must not drift apart.
var consoleLanguages = []string{"fr", "en", "es", "pt-BR"}

func languageAllowed(v string) bool { return v == "" || slices.Contains(consoleLanguages, v) }

// putProfile applies the changes a user may make to their own account without
// leaving the console: the display name (local accounts only — an SSO or LDAP
// name belongs to its provider) and the console language.
func validateProfileNames(kind string, firstName, lastName *string, displayName string) (string, string, error) {
	first, last := splitName(displayName)
	if firstName != nil || lastName != nil {
		if !profileActionAllowed(kind, "update_profile") {
			return "", "", apiError{403, "action_forbidden", "This account setting is managed by your identity provider."}
		}
		if firstName == nil || lastName == nil {
			return "", "", bad("Both the first name and the last name are required.")
		}
		first, last = strings.TrimSpace(*firstName), strings.TrimSpace(*lastName)
		for _, v := range []string{first, last} {
			if v == "" || len(v) > 60 || hasControl(v) || v != identityText(v) {
				return "", "", bad("First name and last name must each contain 1 to 60 characters without control characters.")
			}
		}
	}
	return first, last, nil
}

func (a *App) updateProfileName(r *http.Request, tx pgx.Tx, s *Session, first, last string) (bool, error) {
	changed := false
	// Keycloak owns the name: the ID token's "name" claim overwrites the local
	// copy at the next session refresh, so the provider must be updated first.
	admin, e := a.identityAdmin(r.Context())
	if e != nil {
		return false, e
	}
	// The name the provider already holds is not a change: no write, no audit line
	// (compared field by field there, not with the local joined copy).
	current, e := admin.user(r.Context(), s.Subject)
	if e != nil {
		return false, e
	}
	if current == nil || strings.TrimSpace(current.FirstName) != first || strings.TrimSpace(current.LastName) != last {
		changed = true
		status, _, _, e := admin.call(r.Context(), "PUT", "/users/"+url.PathEscape(s.Subject), map[string]any{"firstName": first, "lastName": last})
		if e != nil {
			return false, e
		}
		if status == 400 {
			return false, bad("The identity provider refused this name.")
		}
		if status != 204 {
			return false, apiError{502, "identity_unavailable", "Could not update the identity account."}
		}
	}
	if _, e := tx.Exec(r.Context(), `UPDATE users SET display_name=$1 WHERE id=$2`, strings.TrimSpace(first+" "+last), s.UserID); e != nil {
		return false, e
	}
	return changed, nil
}

func (a *App) putProfile(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	var body struct {
		FirstName *string `json:"first_name"`
		LastName  *string `json:"last_name"`
		Language  *string `json:"language"`
	}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	kind := s.IdentityType
	if kind == "" {
		kind = "local"
	}
	language := ""
	if e := tx.QueryRow(r.Context(), `SELECT language FROM users WHERE id=$1`, s.UserID).Scan(&language); e != nil {
		return e
	}
	// A change that changes nothing writes no audit line: any member could otherwise
	// fill the journal with one request after another (audit of 2026-09-24).
	changed := body.Language != nil && *body.Language != language
	if body.Language != nil {
		if !languageAllowed(*body.Language) {
			return bad("Language must be one of fr, en, es, pt-BR, or empty to follow the browser.")
		}
		language = *body.Language
		if _, e := tx.Exec(r.Context(), `UPDATE users SET language=$1 WHERE id=$2`, language, s.UserID); e != nil {
			return e
		}
	}
	first, last, e := validateProfileNames(kind, body.FirstName, body.LastName, s.DisplayName)
	if e != nil {
		return e
	}
	if body.FirstName != nil || body.LastName != nil {
		nameChanged, e := a.updateProfileName(r, tx, s, first, last)
		if e != nil {
			return e
		}
		changed = changed || nameChanged
	}
	if changed {
		if e := audit(r.Context(), tx, s.OrganizationID, s.UserID, "profile.update", s.UserID); e != nil {
			return e
		}
	}
	if e := tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]any{"display_name": strings.TrimSpace(first + " " + last), "first_name": first, "last_name": last, "language": language})
	return nil
}
