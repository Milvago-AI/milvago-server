package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type inviteRequest struct {
	Email    string `json:"email"`
	Role     string `json:"role"`
	Language string `json:"language"`
}

type knownInviteAccount struct{ id, realm, subject, kind string }

func validateInviteRequest(r *http.Request, tx pgx.Tx, s *Session, body *inviteRequest) error {
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
	return nil
}

func lookupInviteSubject(ctx context.Context, admin *identityAdmin, email string) (string, error) {
	status, _, raw, e := admin.call(ctx, "GET", "/users?email="+url.QueryEscape(email)+"&exact=true", nil)
	if e != nil || status != 200 {
		return "", apiError{502, "identity_unavailable", "Could not query identity users."}
	}
	var users []identityUser
	if json.Unmarshal(raw, &users) != nil {
		return "", apiError{502, "identity_unavailable", "Invalid identity administration response."}
	}
	for _, u := range users {
		if strings.EqualFold(u.Email, email) {
			return u.ID, nil
		}
	}
	return "", nil
}

func createInviteIdentity(ctx context.Context, admin *identityAdmin, email, language string) (string, bool, error) {
	// The activation link carries required actions, allowing later SSO linking.
	account := map[string]any{"username": email, "email": email, "enabled": true, "emailVerified": false}
	if language != "" {
		// The invitation e-mail and the activation pages follow the account locale.
		account["attributes"] = map[string][]string{"locale": {language}}
	}
	status, _, _, err := admin.call(ctx, "POST", "/users", account)
	if err != nil || (status != 201 && status != 409) {
		return "", false, apiError{502, "identity_unavailable", "Could not create the identity account."}
	}
	subject, err := lookupInviteSubject(ctx, admin, email)
	if err != nil {
		return "", false, err
	}
	if subject == "" {
		return "", false, apiError{502, "identity_unavailable", "The created identity account could not be found."}
	}
	// A concurrent creation (409) is not this invitation's own account.
	return subject, status == 201, nil
}

func validateInviteLDAP(ctx context.Context, tx pgx.Tx, organizationID, federationLink string) error {
	// An LDAP account must come from this organization's own directory.
	var component string
	err := tx.QueryRow(ctx, "SELECT component_id FROM ldap_directories WHERE organization_id=$1", organizationID).Scan(&component)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err != nil || component != federationLink {
		return apiError{409, "directory_mismatch", "This account belongs to a directory that is not this organization's."}
	}
	return nil
}

func resolveInviteIdentity(r *http.Request, tx pgx.Tx, s *Session, admin *identityAdmin, email, language string) (subject, kind, name string, created bool, err error) {
	subject, err = lookupInviteSubject(r.Context(), admin, email)
	if err != nil {
		return "", "", "", false, err
	}
	if subject == "" {
		subject, created, err = createInviteIdentity(r.Context(), admin, email, language)
		if err != nil {
			return "", "", "", false, err
		}
		return subject, "local", "", created, nil
	}
	u, err := admin.user(r.Context(), subject)
	if err != nil {
		return "", "", "", false, err
	}
	if u == nil {
		return "", "", "", false, apiError{502, "identity_unavailable", "The identity account could not be read."}
	}
	kind, err = admin.identityType(r.Context(), u)
	if err != nil {
		return "", "", "", false, err
	}
	if kind == "ldap" {
		if err = validateInviteLDAP(r.Context(), tx, s.OrganizationID, u.FederationLink); err != nil {
			return "", "", "", false, err
		}
	}
	return subject, kind, u.displayName(), false, nil
}

// invitationLifespan is the validity of the invitation link, and of the direct
// provider link an invitation of the organization's domain grants.
const invitationLifespan = 24 * time.Hour

// inviteKnownAccount adds an account that already lives in another organization's realm:
// the person keeps that single account, and the membership is Milvago's alone.
func (a *App) inviteKnownAccount(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session, body inviteRequest, known knownInviteAccount) error {
	if e := a.requireAncestorRealm(r.Context(), tx, s.OrganizationID, known.realm); e != nil {
		return e
	}
	if e := validateInviteMembership(r, tx, s, known.subject); e != nil {
		return e
	}
	if _, e := tx.Exec(r.Context(), `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,$3)`, s.OrganizationID, known.id, body.Role); e != nil {
		return e
	}
	if e := audit(r.Context(), tx, s.OrganizationID, s.UserID, "member.invite", known.id); e != nil {
		return e
	}
	if e := tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 201, map[string]string{"id": known.id, "email": body.Email, "role": body.Role, "identity_type": known.kind, "language": body.Language})
	return nil
}

// requireAncestorRealm accepts an account only from the realm of org or of one of its
// ancestors. Any other organization runs its own sign-in -- its directory or provider
// can present any address as verified -- so an account it holds never receives this
// organization's access: the address could name someone else entirely.
func (a *App) requireAncestorRealm(ctx context.Context, tx pgx.Tx, org, home string) error {
	realms, e := a.ancestorRealms(ctx, tx, org)
	if e != nil {
		return e
	}
	if slices.Contains(realms, home) {
		return nil
	}
	return apiError{409, "account_in_other_realm", "This address belongs to an account another organization signs in. Invite it from that organization or one of its sub-organizations."}
}

// ancestorRealms are the realms of org and of its ancestors, in stored form.
func (a *App) ancestorRealms(ctx context.Context, tx pgx.Tx, org string) ([]string, error) {
	chain, e := barrierChain(ctx, tx, org)
	if e != nil {
		return nil, e
	}
	realms := make([]string, 0, len(chain))
	for _, id := range chain {
		realm, e := a.organizationRealm(ctx, tx, id)
		if e != nil {
			return nil, e
		}
		realms = append(realms, realm)
	}
	return realms, nil
}

func validateInviteMembership(r *http.Request, tx pgx.Tx, s *Session, subject string) error {
	// Additions of the same account serialize before membership checks.
	if e := lockAccount(r, tx, subject); e != nil {
		return e
	}
	var existing bool
	if e := tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM memberships m JOIN users u ON u.id=m.user_id WHERE u.subject=$1)", subject).Scan(&existing); e != nil {
		return e
	}
	if existing {
		return apiError{409, "already_member", "This account is already a member."}
	}
	var existingUser string
	if e := tx.QueryRow(r.Context(), "SELECT id FROM users WHERE subject=$1", subject).Scan(&existingUser); e == nil {
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
	return nil
}

func (a *App) sendInviteIdentityEmail(ctx context.Context, tx pgx.Tx, s *Session, admin *identityAdmin, body inviteRequest, subject string, created bool) (*time.Time, error) {
	actions := []string{"VERIFY_EMAIL", "UPDATE_PASSWORD"}
	var pendingUntil *time.Time
	if created {
		// A proven domain signs in with its provider; the link only confirms
		// the mailbox and lasts as long as the invitation itself.
		direct, e := invitationProvider(ctx, admin, body.Email)
		if e == nil && direct {
			_, domain, _ := strings.Cut(body.Email, "@")
			if requireProvenDomain(ctx, tx, s.OrganizationID, domain) != nil {
				direct = false
			}
		}
		if e == nil && direct {
			e = markPendingInvitation(ctx, admin, subject)
		}
		if e != nil {
			return nil, e
		}
		if direct {
			actions = []string{"VERIFY_EMAIL"}
			until := time.Now().Add(invitationLifespan)
			pendingUntil = &until
		}
	}
	// The client base URL takes the account to the console after activation.
	query := url.Values{"lifespan": {strconv.Itoa(int(invitationLifespan.Seconds()))}, "client_id": {a.config.ClientID}}
	status, _, _, e := admin.call(ctx, "PUT", "/users/"+url.PathEscape(subject)+"/execute-actions-email?"+query.Encode(), actions)
	if e != nil || status != 204 {
		return nil, apiError{502, "invitation_email_failed", "The identity provider could not send the invitation. Check its SMTP configuration."}
	}
	return pendingUntil, nil
}

type resolvedInvite struct {
	subject, kind, name, realm, username string
	pendingUntil                         *time.Time
}

func (a *App) lookupKnownInviteAccount(ctx context.Context, tx pgx.Tx, organizationID, email string) (knownInviteAccount, error) {
	var known knownInviteAccount
	// Prefer the organization's realm and its ancestors. A separate directory
	// can hold a copy of the address that must not shadow the original account.
	chain, e := a.ancestorRealms(ctx, tx, organizationID)
	if e != nil {
		return known, e
	}
	e = tx.QueryRow(ctx, `SELECT id,realm,subject,identity_type FROM users WHERE lower(email)=$1 ORDER BY realm<>ALL($2::text[]), realm LIMIT 1`, email, chain).Scan(&known.id, &known.realm, &known.subject, &known.kind)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return known, e
	}
	return known, nil
}

func persistInvitedMember(ctx context.Context, tx pgx.Tx, s *Session, body inviteRequest, identity resolvedInvite) (string, error) {
	var user string
	// Reuse an account already known in this realm without resetting what it owns.
	// An omitted language or display name keeps the existing stored value.
	e := tx.QueryRow(ctx, `INSERT INTO users(subject,email,display_name,identity_type,language,realm,pending_invitation_until,username) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(subject) DO UPDATE SET email=excluded.email,identity_type=excluded.identity_type,language=CASE WHEN excluded.language<>'' THEN excluded.language ELSE users.language END,display_name=CASE WHEN excluded.display_name<>'' THEN excluded.display_name ELSE users.display_name END,pending_invitation_until=COALESCE(excluded.pending_invitation_until,users.pending_invitation_until),username=COALESCE(NULLIF(excluded.username,''),users.username) WHERE users.realm=excluded.realm RETURNING id`, identity.subject, body.Email, identity.name, identity.kind, body.Language, identity.realm, identity.pendingUntil, identity.username).Scan(&user)
	if e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return "", apiError{409, "already_member", "This account is already a member."}
		}
		return "", e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,$3)`, s.OrganizationID, user, body.Role); e != nil {
		return "", e
	}
	if e = audit(ctx, tx, s.OrganizationID, s.UserID, "member.invite", user); e != nil {
		return "", e
	}
	if e = tx.Commit(ctx); e != nil {
		return "", e
	}
	return user, nil
}

func (a *App) invite(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	var body inviteRequest
	if e := decode(w, r, &body); e != nil {
		return e
	}
	if e := validateInviteRequest(r, tx, s, &body); e != nil {
		return e
	}
	// An existing account keeps its home realm and joins with that account.
	known, e := a.lookupKnownInviteAccount(r.Context(), tx, s.OrganizationID, body.Email)
	if e != nil {
		return e
	}
	realm, e := a.organizationRealm(r.Context(), tx, s.OrganizationID)
	if e != nil {
		return e
	}
	if known.id != "" && known.realm != realm {
		return a.inviteKnownAccount(w, r, tx, s, body, known)
	}
	admin, e := a.identityAdminFor(r.Context(), realm)
	if e != nil {
		return e
	}
	subject, kind, name, created, e := resolveInviteIdentity(r, tx, s, admin, body.Email, body.Language)
	if e != nil {
		return e
	}
	if e = validateInviteMembership(r, tx, s, subject); e != nil {
		return e
	}
	var pendingUntil *time.Time
	if kind == "local" {
		pendingUntil, e = a.sendInviteIdentityEmail(r.Context(), tx, s, admin, body, subject, created)
		if e != nil {
			return e
		}
	}
	// The sign-in name, so that the entry page routes the person before their first
	// sign-in too: the address for an account this invitation created, Keycloak's own
	// name for an existing one (an LDAP account signs in with its directory name).
	username := body.Email
	if !created {
		if u, e := admin.user(r.Context(), subject); e == nil && u != nil {
			username = loginName(u.Username)
		}
	}
	identity := resolvedInvite{subject: subject, kind: kind, name: name, realm: realm, username: username, pendingUntil: pendingUntil}
	user, e := persistInvitedMember(r.Context(), tx, s, body, identity)
	if e != nil {
		return e
	}
	reply(w, 201, map[string]string{"id": user, "email": body.Email, "role": body.Role, "identity_type": kind, "language": body.Language})
	return nil
}
