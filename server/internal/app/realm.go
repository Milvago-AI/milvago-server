package app

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Every organization has its own Keycloak realm in Enterprise: its single sign-on
// providers, its LDAP directory, its password and second-factor policy apply to its own
// accounts only. A realm shared by several organizations cannot keep one tenant's
// directory away from another's sign-ins: Keycloak asks every directory of the realm
// about a name it does not know yet. Community has one organization and one realm.
//
// A person has one account, in the realm of the organization that created it; rights
// on other organizations are Milvago memberships. users.realm stores that realm, empty
// for the root one.

// rootRealm is the realm named by the configured issuer: the root organization's.
func (a *App) rootRealm() string {
	u, e := url.Parse(a.config.Issuer)
	if e != nil {
		return ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) == 2 && parts[0] == "realms" {
		return parts[1]
	}
	return ""
}

// childRealm is the realm name of a non-root organization, derived from its identifier
// so that no lookup table can disagree with it.
func childRealm(organization string) string {
	return "org-" + strings.ReplaceAll(organization, "-", "")
}

// realmIssuer swaps the realm of an issuer URL.
func realmIssuer(rootIssuer, realm string) (string, error) {
	i := strings.LastIndex(rootIssuer, "/realms/")
	if i < 0 || realm == "" || strings.ContainsAny(realm, "/?#%") {
		return "", errors.New("the identity issuer names no realm")
	}
	return rootIssuer[:i] + "/realms/" + realm, nil
}

// organizationRealm is the realm of org: the root realm for the root organization and
// for every organization in Community, its own realm otherwise. The stored form is
// empty for the root realm, like users.realm.
func (a *App) organizationRealm(ctx context.Context, tx pgx.Tx, org string) (string, error) {
	if Edition != "commercial" {
		return "", nil
	}
	var root string
	if e := tx.QueryRow(ctx, "SELECT organization_id FROM app_config").Scan(&root); e != nil {
		return "", e
	}
	if org == root {
		return "", nil
	}
	return childRealm(org), nil
}

// organizationAdmin administers the realm of org.
func (a *App) organizationAdmin(ctx context.Context, tx pgx.Tx, org string) (*identityAdmin, error) {
	realm, e := a.organizationRealm(ctx, tx, org)
	if e != nil {
		return nil, e
	}
	return a.identityAdminFor(ctx, realm)
}

// signInURL is where a realm's own pages send a person to sign in to the console. The
// root realm goes straight to its sign-in; another realm goes to the entry page, whose
// e-mail-first sign-in routes to it, because /auth/login alone would open the root realm.
func signInURL(origin, stored string) string {
	if stored == "" {
		return origin + "/auth/login"
	}
	return origin + "/"
}

// realmName turns a stored realm ("" for the root one) into Keycloak's name.
func (a *App) realmName(stored string) string {
	if stored == "" {
		return a.rootRealm()
	}
	return stored
}

// publicRealmIssuer is the issuer browsers reach for a stored realm.
func (a *App) publicRealmIssuer(stored string) string {
	root := a.publicIssuer()
	if stored == "" {
		return root
	}
	issuer, e := realmIssuer(root, stored)
	if e != nil {
		return root
	}
	return issuer
}
