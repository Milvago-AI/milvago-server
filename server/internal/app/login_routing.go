package app

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// loginTarget is where a sign-in starts: the realm (stored form, "" for the root one),
// the address the person typed, and the organization provider that answers for it.
type loginTarget struct {
	realm, hint, provider string
}

// loginName normalizes what a person typed to sign in (an e-mail address or a sign-in
// name) the way Keycloak keeps names: lower case, no space or control character. Empty
// when unusable.
func loginName(raw string) string {
	v := asciiLower(strings.TrimSpace(raw))
	if v == "" || len(v) > 254 || identityText(v) != v || strings.ContainsAny(v, " \t") {
		return ""
	}
	return v
}

// loginDestination routes a sign-in. A signed-in person (a step-up, an account action)
// continues in the realm of their account. Otherwise what the person typed decides: a
// domain an organization has proven sends an address to that organization's realm and
// provider; in Enterprise a known account, by address or by sign-in name, goes to its
// own realm; anything else to the root realm, whose sign-in page tells nobody whether
// the account exists.
func (a *App) loginDestination(r *http.Request) (loginTarget, error) {
	if c, e := r.Cookie(a.cookieName("session")); e == nil {
		if s, e := a.loadSession(r, c.Value); e == nil {
			return loginTarget{realm: s.Realm}, nil
		}
	}
	raw := r.URL.Query().Get("login_hint")
	hint, ok := plainAddress(raw)
	if !ok {
		return a.nameDestination(r.Context(), loginName(raw))
	}
	ctx := r.Context()
	target := loginTarget{hint: hint}
	_, domain, _ := strings.Cut(hint, "@")
	org, e := a.domainOrganization(ctx, domain)
	if e != nil {
		return target, e
	}
	if org != "" {
		tx, e := tenantTx(ctx, a.db, org)
		if e != nil {
			return target, e
		}
		defer tx.Rollback(ctx)
		if target.realm, e = a.organizationRealm(ctx, tx, org); e != nil {
			return target, e
		}
		admin, e := a.identityAdminFor(ctx, target.realm)
		if e != nil {
			return target, e
		}
		// A provider unreachable now is no reason to refuse the sign-in: the person
		// still reaches the right realm and can choose there.
		target.provider, _ = domainProvider(ctx, admin, domain)
		return target, nil
	}
	if Edition == "commercial" {
		// Like a name, an address routes only when one realm holds it. A child's directory
		// or provider can present any address as verified: a copy of a person's address in
		// a second realm must not pull their sign-in, and the password they type, into it.
		realms, e := a.accountRealms(ctx, `SELECT DISTINCT realm FROM users WHERE lower(email)=$1 LIMIT 2`, hint)
		if e != nil {
			return target, e
		}
		if len(realms) == 0 {
			// An address can also be a sign-in name.
			return a.nameDestination(ctx, hint)
		}
		if len(realms) == 1 {
			target.realm = realms[0]
		}
	}
	return target, nil
}

// nameDestination routes a sign-in name to the realm of the one account that bears it.
// A name can repeat across organizations' realms: then nothing tells them apart, and
// the person signs in from the root realm, which needs no routing.
func (a *App) nameDestination(ctx context.Context, name string) (loginTarget, error) {
	target := loginTarget{hint: name}
	if name == "" || Edition != "commercial" {
		return target, nil
	}
	realms, e := a.accountRealms(ctx, `SELECT DISTINCT realm FROM users WHERE username=$1 LIMIT 2`, name)
	if e != nil {
		return target, e
	}
	if len(realms) == 1 {
		target.realm = realms[0]
	}
	return target, nil
}

func (a *App) accountRealms(ctx context.Context, query, value string) ([]string, error) {
	rows, e := a.db.Query(ctx, query, value)
	if e != nil {
		return nil, e
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// domainOrganization is the organization a domain routes to. In Enterprise only a
// domain proven through DNS counts, and it names one organization of the instance;
// Community has one organization, whose providers name their own domain.
func (a *App) domainOrganization(ctx context.Context, domain string) (string, error) {
	if Edition != "commercial" {
		var root string
		e := a.db.QueryRow(ctx, "SELECT organization_id FROM app_config").Scan(&root)
		return root, e
	}
	var org string
	e := a.db.QueryRow(ctx, `SELECT organization_id FROM sso_domain_owner($1)`, domain).Scan(&org)
	if errors.Is(e, pgx.ErrNoRows) {
		return "", nil
	}
	return org, e
}

// domainProvider is the offered provider of a realm that answers for domain.
func domainProvider(ctx context.Context, admin *identityAdmin, domain string) (string, error) {
	for _, alias := range ssoProviders {
		current, e := readSSOProvider(ctx, admin, alias)
		if e != nil {
			return "", e
		}
		if current == nil {
			continue
		}
		enabled, _ := current["enabled"].(bool)
		if enabled && strings.EqualFold(providerDomain(alias, current), domain) {
			return alias, nil
		}
	}
	return "", nil
}

// providerDomain is the domain a provider answers for: Google's Workspace domain, the
// Microsoft invitation domain.
func providerDomain(alias string, current map[string]any) string {
	if alias == "microsoft" {
		return ssoConfigValue(current, ssoInvitationDomain)
	}
	return ssoConfigValue(current, "hostedDomain")
}

// endPendingInvitation closes the direct link of an invitation at the account's first
// sign-in. It must succeed: a role left in place would let another provider account of
// the domain link to this one later without proof.
func (a *App) endPendingInvitation(ctx context.Context, tx pgx.Tx, realm, user, subject string) error {
	var until *time.Time
	if e := tx.QueryRow(ctx, `SELECT pending_invitation_until FROM users WHERE id=$1`, user).Scan(&until); e != nil {
		return e
	}
	if until == nil {
		return nil
	}
	if e := a.clearInvitationRole(ctx, realm, subject); e != nil {
		return e
	}
	_, e := tx.Exec(ctx, `UPDATE users SET pending_invitation_until=NULL WHERE id=$1`, user)
	return e
}

func (a *App) clearInvitationRole(ctx context.Context, realm, subject string) error {
	admin, e := a.identityAdminFor(ctx, realm)
	if e == nil {
		e = clearPendingInvitation(ctx, admin, subject)
	}
	if e != nil {
		a.log.Warn("pending invitation role not cleared", "error", e)
		return apiError{503, "identity_unavailable", "Could not complete the invitation. Try again in a moment."}
	}
	return nil
}

// expirePendingInvitations removes the direct link of every invitation whose link has
// expired, so that a later provider sign-in needs the usual proof.
func (a *App) expirePendingInvitations(ctx context.Context) {
	rows, e := a.db.Query(ctx, `SELECT id,subject,realm FROM users WHERE pending_invitation_until<now()`)
	if e != nil {
		a.log.Warn("pending invitations not read", "error", e)
		return
	}
	type pending struct{ id, subject, realm string }
	var due []pending
	for rows.Next() {
		var p pending
		if rows.Scan(&p.id, &p.subject, &p.realm) == nil {
			due = append(due, p)
		}
	}
	rows.Close()
	for _, p := range due {
		if a.clearInvitationRole(ctx, p.realm, p.subject) != nil {
			continue
		}
		if _, e := a.db.Exec(ctx, `UPDATE users SET pending_invitation_until=NULL WHERE id=$1`, p.id); e != nil {
			a.log.Warn("pending invitation not closed", "error", e)
		}
	}
}
