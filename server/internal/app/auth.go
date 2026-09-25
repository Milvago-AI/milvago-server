package app

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"
)

const (
	sqlDefaultLanguage = "SELECT default_language FROM app_config"
)

// Rewrite transport preserves the public issuer/audience validation while routing
// only that issuer's requests to the configured private container address.
type oidcTransport struct {
	public, internal *url.URL
	base             http.RoundTripper
}

func (t oidcTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	q := r.Clone(r.Context())
	u := *r.URL
	q.URL = &u
	if q.URL.Scheme == t.public.Scheme && q.URL.Host == t.public.Host {
		q.URL.Scheme = t.internal.Scheme
		q.URL.Host = t.internal.Host
	}
	return t.base.RoundTrip(q)
}
func (a *App) initOIDC(ctx context.Context) error {
	client := &http.Client{Timeout: 15 * time.Second}
	if a.config.InternalOIDC != "" {
		public, _ := url.Parse(a.config.Issuer)
		internal, e := url.Parse(a.config.InternalOIDC)
		if e != nil || internal.Host == "" || (internal.Scheme != "http" && internal.Scheme != "https") || internal.User != nil || internal.Path != "" {
			return errors.New("invalid OIDC_INTERNAL_URL")
		}
		client.Transport = oidcTransport{public, internal, http.DefaultTransport}
	}
	a.oidcClient = client
	ctx = oidc.ClientContext(ctx, client)
	provider, e := oidc.NewProvider(ctx, a.config.Issuer)
	if e != nil {
		return fmt.Errorf("OIDC discovery: %w", e)
	}
	a.oauth = oauth2.Config{ClientID: a.config.ClientID, ClientSecret: a.config.ClientSecret, Endpoint: provider.Endpoint(), RedirectURL: a.config.AppURL + "/auth/callback", Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}
	var discovery struct {
		Logout string `json:"end_session_endpoint"`
	}
	if e = provider.Claims(&discovery); e != nil {
		return e
	}
	a.logoutURL = discovery.Logout
	a.verifier = provider.VerifierContext(oidc.ClientContext(context.Background(), client), &oidc.Config{ClientID: a.config.ClientID, SupportedSigningAlgs: []string{oidc.RS256}})
	// The second verifier, for the MCP endpoint: another audience -- the endpoint as
	// an OAuth resource -- on the same keys and the same rotation. Built here, once,
	// because a verifier built per request fetches JWKS per request. A no-op in
	// Community, where the endpoint does not exist.
	a.initMCPVerifier(provider)
	return nil
}
func (a *App) cookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: a.config.SecureCookies, SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
}
func cookieName(kind string) string { return "milvago_" + Edition + "_" + kind }

// Over HTTPS the session and login cookies carry the __Host- prefix: the browser then
// refuses one set by a sibling subdomain or with a Domain attribute, which would
// otherwise let such a host plant its own login binding or session (login CSRF into
// an attacker's account). Plain HTTP (local development) cannot use the prefix.
func (a *App) cookieName(kind string) string {
	if a.config.SecureCookies {
		return "__Host-" + cookieName(kind)
	}
	return cookieName(kind)
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if err := a.checkPublicRequest(r, "login", 120, 1200); err != nil {
		a.fail(w, err)
		return
	}
	// Self-service profile actions (Keycloak AIA) require a signed-in user and
	// must pass the identity-type lock before kc_action is ever forwarded.
	//
	// A read-only instance forwards none of them. `demoRefuses` cannot see this one:
	// it judges the method, and this is a GET — yet it changes the password, the
	// e-mail address or the second factor of the account everyone shares, which is the
	// one change that locks every other visitor out (product decision, 2026-09-17). The
	// refusal is explicit rather than a silent drop, so a reader learns why nothing
	// happened instead of landing on a bare sign-in page.
	var kcAction string
	if a.config.DemoReadOnly && r.URL.Query().Get("action") != "" {
		a.fail(w, apiError{403, "demo_read_only", "This demonstration instance is read-only."})
		return
	}
	if action := r.URL.Query().Get("action"); action != "" {
		if kc, ok := profileActions[action]; ok || action == "manage_mfa" {
			if c, e := r.Cookie(a.cookieName("session")); e == nil {
				if s, e := a.loadSession(r, c.Value); e == nil {
					if !profileActionAllowed(s.IdentityType, action) {
						a.fail(w, apiError{403, "action_forbidden", "This account setting is managed by your identity provider."})
						return
					}
					if action == "manage_mfa" {
						// Keycloak owns credential listing, enrollment and removal.
						// Only the configured issuer can receive this redirect.
						accountURL := strings.TrimRight(a.config.Issuer, "/") + "/account/account-security/signing-in"
						if language := r.URL.Query().Get("lang"); slices.Contains(consoleLanguages, language) {
							accountURL += "?" + url.Values{"kc_locale": {language}}.Encode()
						}
						http.Redirect(w, r, accountURL, http.StatusFound)
						return
					}
					kcAction = kc
				}
			}
		}
	}
	stepUp := r.URL.Query().Get("mfa") == "1"
	state, binding, nonce, verifier := randomToken(), randomToken(), randomToken(), oauth2.GenerateVerifier()
	_, e := a.db.Exec(r.Context(), `INSERT INTO login_attempts(state_hash,binding_hash,verifier,nonce,expires_at,step_up) VALUES($1,$2,$3,$4,now()+interval '10 minutes',$5)`, hash(state), hash(binding), verifier, nonce, stepUp)
	if e != nil {
		a.fail(w, e)
		return
	}
	a.cookie(w, a.cookieName("login"), binding, 600)
	language := r.URL.Query().Get("lang")
	if !slices.Contains(consoleLanguages, language) {
		if e = a.db.QueryRow(r.Context(), sqlDefaultLanguage).Scan(&language); e != nil {
			a.fail(w, e)
			return
		}
	}
	opts := []oauth2.AuthCodeOption{oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("ui_locales", language)}
	if stepUp {
		// Step up to the OTP level of the browser flow; Keycloak enrols a TOTP
		// when the account has none yet.
		opts = append(opts, oauth2.SetAuthURLParam("acr_values", "2"), oauth2.SetAuthURLParam("max_age", "0"), oauth2.SetAuthURLParam("prompt", "login"))
	}
	if kcAction != "" {
		opts = append(opts, oauth2.SetAuthURLParam("kc_action", kcAction))
	}
	http.Redirect(w, r, a.oauth.AuthCodeURL(state, opts...), http.StatusFound)
}
func (a *App) callback(w http.ResponseWriter, r *http.Request) {
	cookie, e := r.Cookie(a.cookieName("login"))
	if e != nil {
		a.fail(w, bad("The login attempt has expired."))
		return
	}
	a.cookie(w, a.cookieName("login"), "", -1)
	var verifier, nonce string
	var associationOrg, associationDevice *string
	var associationHash []byte
	var stepUp bool
	e = a.db.QueryRow(r.Context(), `DELETE FROM login_attempts WHERE state_hash=$1 AND binding_hash=$2 AND expires_at>now() RETURNING verifier,nonce,association_org,association_device,association_hash,step_up`, hash(r.URL.Query().Get("state")), hash(cookie.Value)).Scan(&verifier, &nonce, &associationOrg, &associationDevice, &associationHash, &stepUp)
	if e != nil || r.URL.Query().Get("code") == "" {
		a.fail(w, bad("Invalid or reused login attempt."))
		return
	}
	ctx := oidc.ClientContext(r.Context(), a.oidcClient)
	token, e := a.oauth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(verifier))
	if e != nil {
		a.fail(w, apiError{401, "identity_failed", "Identity provider rejected the authorization code."})
		return
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		a.fail(w, apiError{401, "identity_failed", "Identity token is missing."})
		return
	}
	id, e := a.verifier.Verify(ctx, raw)
	if e != nil || !equal(id.Nonce, nonce) {
		a.fail(w, apiError{401, "identity_failed", "Identity token validation failed."})
		return
	}
	var claims struct {
		Email    string   `json:"email"`
		Name     string   `json:"name"`
		Verified bool     `json:"email_verified"`
		AMR      []string `json:"amr"`
		ACR      string   `json:"acr"`
		AuthTime int64    `json:"auth_time"`
	}
	if e = id.Claims(&claims); e == nil {
		claims.Name = identityText(claims.Name)
	}
	// An e-mail is refused, not cleaned: folded, "admin<U+200E>@corp.example" -- a
	// distinct verified address for Keycloak -- would match the bootstrap e-mail and
	// take the first owner's place (audit of 2026-09-24).
	if e != nil || !claims.Verified || claims.Email == "" || identityText(claims.Email) != claims.Email {
		a.fail(w, apiError{403, "verified_email_required", "A verified email address is required."})
		return
	}
	if associationOrg != nil && associationDevice != nil {
		var associationClaims map[string]json.RawMessage
		if e = id.Claims(&associationClaims); e != nil {
			a.fail(w, bad("Invalid verified association claims."))
			return
		}
		if e = a.finishDeviceAssociation(w, r, *associationOrg, *associationDevice, associationHash, id.Subject, claims.Email, claims.Name, associationClaims); e != nil {
			a.fail(w, e)
		}
		return
	}
	mfa := claims.ACR == "2"
	for _, amr := range claims.AMR {
		if amr == "mfa" || amr == "otp" {
			mfa = true
		}
	}
	// Account source (local / sso / ldap) as known by Keycloak. A lookup
	// failure never blocks sign-in: the last stored type is kept.
	kind := ""
	if admin, e := a.identityAdmin(ctx); e == nil {
		if u, e := admin.user(id.Subject); e == nil && u != nil {
			if k, e := admin.identityType(u); e == nil {
				kind = k
			} else {
				a.log.Warn("identity type lookup failed", "error", e)
			}
		} else if e != nil {
			a.log.Warn("identity account lookup failed", "error", e)
		}
	}
	tx, e := a.db.Begin(ctx)
	if e != nil {
		a.fail(w, e)
		return
	}
	defer tx.Rollback(ctx)
	var org, bootstrapEmail string
	var consumed bool
	e = tx.QueryRow(ctx, `SELECT organization_id,bootstrap_email,bootstrap_consumed FROM app_config WHERE singleton FOR UPDATE`).Scan(&org, &bootstrapEmail, &consumed)
	if e != nil {
		a.fail(w, e)
		return
	}
	if _, e = tx.Exec(ctx, `SELECT set_config('milvago.organization_id',$1,true)`, org); e != nil {
		a.fail(w, e)
		return
	}
	// Only invited or imported accounts have a row; an unknown identity must
	// leave no trace behind.
	var user string
	if e = tx.QueryRow(ctx, `SELECT id FROM users WHERE subject=$1`, id.Subject).Scan(&user); e != nil && !errors.Is(e, pgx.ErrNoRows) {
		a.fail(w, e)
		return
	}
	// An empty bootstrap address means the setup wizard has not run yet: it must
	// never match an identity that simply has no e-mail.
	// ASCII case only: Unicode folding matched "ſupport@" (U+017F), a distinct realm
	// account, to a bootstrap "support@" and made it the first owner (audit of
	// 2026-09-24). The bootstrap address is stored lower-cased by plainAddress.
	if !consumed && bootstrapEmail != "" && asciiLower(claims.Email) == bootstrapEmail {
		var n int
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM memberships WHERE organization_id=$1`, org).Scan(&n); e != nil {
			a.fail(w, e)
			return
		}
		if n != 0 {
			a.fail(w, forbidden())
			return
		}
		if user == "" {
			if e = tx.QueryRow(ctx, `INSERT INTO users(subject,email,display_name,identity_type) VALUES($1,$2,$3,COALESCE(NULLIF($4,''),'local')) RETURNING id`, id.Subject, claims.Email, claims.Name, kind).Scan(&user); e != nil {
				a.fail(w, e)
				return
			}
		}
		if _, e = tx.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner');`, org, user); e != nil {
			a.fail(w, e)
			return
		}
		if _, e = tx.Exec(ctx, `UPDATE app_config SET bootstrap_consumed=true WHERE singleton`); e != nil {
			a.fail(w, e)
			return
		}
		if e = audit(ctx, tx, org, user, "organization.bootstrap", org); e != nil {
			a.fail(w, e)
			return
		}
	}
	if user == "" {
		a.fail(w, apiError{403, "membership_required", "Your account has no organization membership."})
		return
	}
	var identityType string
	if e = tx.QueryRow(ctx, `UPDATE users SET email=$1,display_name=$2,identity_type=COALESCE(NULLIF($3,''),identity_type) WHERE id=$4 RETURNING identity_type`, claims.Email, claims.Name, kind, user).Scan(&identityType); e != nil {
		a.fail(w, e)
		return
	}
	// Without a licence, Community signs in local accounts only: no SSO, no
	// directory. The stored type stands in when the live lookup above failed.
	if identityType != "local" {
		l, e := a.licenseStatus(ctx)
		if e != nil {
			a.fail(w, e)
			return
		}
		if l.Restricted {
			a.fail(w, errLicenseRestricted)
			return
		}
	}
	// Resolve explicit membership or the nearest inherited MSP membership.
	//
	// The order is a choice, not an accident. Sorting on the identifier alone landed a
	// member of several organizations on whichever one happened to own the smallest
	// random UUID -- a different one per deployment, and never the one they think of as
	// theirs. The topmost organization reachable comes first, then alphabetical order,
	// so the landing place is stable across sign-ins and is the one a human would name.
	//
	// `organizations` carries no row-level policy, unlike `memberships`: joining the
	// latter here would be filtered by a tenant that is not set yet and would quietly
	// contribute nothing to the ordering.
	if e = tx.QueryRow(ctx, `SELECT u.id FROM user_organizations($1) u
		JOIN organizations o ON o.id=u.id
		ORDER BY (o.parent_id IS NOT NULL), u.name, u.id LIMIT 1`, user).Scan(&org); e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			a.fail(w, apiError{403, "membership_required", "Your account has no organization membership."})
		} else {
			a.fail(w, e)
		}
		return
	}
	if _, e = tx.Exec(ctx, `SELECT set_config('milvago.organization_id',$1,true)`, org); e != nil {
		a.fail(w, e)
		return
	}
	var requireMFA bool
	if e = tx.QueryRow(ctx, `SELECT require_mfa FROM settings WHERE organization_id=$1`, org).Scan(&requireMFA); e != nil {
		a.fail(w, e)
		return
	}
	// MFA is evidence from this verified ID token, never an account-type exemption.
	// Step up once when the issuer did not attest the required assurance.
	if requireMFA && !mfa {
		if stepUp {
			a.fail(w, apiError{403, "mfa_required", "Multi-factor authentication is required for this organization."})
			return
		}
		var language string
		if e = tx.QueryRow(ctx, sqlDefaultLanguage).Scan(&language); e != nil {
			a.fail(w, e)
			return
		}
		http.Redirect(w, r, "/auth/login?mfa=1&lang="+url.QueryEscape(language), http.StatusFound)
		return
	}
	session, csrf := randomToken(), randomToken()
	digest := hash(session)
	tokens, e := json.Marshal(sessionTokens{Token: *token, IDToken: raw})
	if e != nil {
		a.fail(w, e)
		return
	}
	nonceBytes := make([]byte, a.config.SessionCipher.NonceSize())
	if _, e = rand.Read(nonceBytes); e != nil {
		a.fail(w, e)
		return
	}
	encrypted := a.config.SessionCipher.Seal(nonceBytes, nonceBytes, tokens, digest)
	expiry := time.Now().Add(8 * time.Hour)
	var verifiedAt *time.Time
	if mfa && claims.AuthTime > 0 {
		t := time.Unix(claims.AuthTime, 0)
		if !t.After(time.Now().Add(30 * time.Second)) {
			verifiedAt = &t
		}
	}
	// A step-up asked for `prompt=login` with `max_age=0`: the issuer must re-authenticate
	// or refuse, so a code returned on that flow attests an authentication that just
	// happened. Keycloak does not put `auth_time` in this token, which left
	// `mfa_verified_at` empty on every step-up — and `requireFreshMFA` reads only that
	// column, so it refused for ever: the person verified their second factor, came back,
	// and was asked again, with no way through. The timestamp is taken here only for a
	// step-up, never for an ordinary sign-in, where a silent SSO could carry an old one.
	// The prompt and max_age travel through the browser, which can strip them: what
	// actually forces a fresh second factor is the realm's `loa-max-age: 0` for level 2
	// (scripts/identity-flows.mjs). A realm reconfigured without it makes this
	// timestamp claim a freshness it did not check (audit of 2026-09-24).
	if verifiedAt == nil && mfa && stepUp {
		now := time.Now()
		verifiedAt = &now
	}
	_, e = tx.Exec(ctx, `INSERT INTO sessions(token_hash,user_id,organization_id,csrf_token,encrypted_tokens,mfa,expires_at,identity_expires_at,oidc_nonce,mfa_verified_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, digest, user, org, csrf, encrypted, mfa, expiry, id.Expiry, nonce, verifiedAt)
	if e != nil {
		a.fail(w, e)
		return
	}
	if e = audit(ctx, tx, org, user, "session.login", user); e != nil {
		a.fail(w, e)
		return
	}
	if e = tx.Commit(ctx); e != nil {
		a.fail(w, e)
		return
	}
	a.cookie(w, a.cookieName("session"), session, int(time.Until(expiry).Seconds()))
	target := "/"
	if r.URL.Query().Get("kc_action_status") != "" {
		// Return from a Keycloak application-initiated profile action.
		target = "/#profile"
	}
	http.Redirect(w, r, target, http.StatusFound)
}
func (a *App) logout(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	// Read the sealed ID token before the row goes away: it turns the identity
	// provider's sign-out into a direct redirect instead of a confirmation page.
	var encrypted []byte
	if e := tx.QueryRow(r.Context(), `SELECT encrypted_tokens FROM sessions WHERE token_hash=$1`, s.TokenHash).Scan(&encrypted); e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return e
	}
	idToken := a.storedIDToken(encrypted, s.TokenHash)
	if _, e := tx.Exec(r.Context(), `DELETE FROM sessions WHERE token_hash=$1`, s.TokenHash); e != nil {
		return e
	}
	if e := audit(r.Context(), tx, s.OrganizationID, s.UserID, "session.logout", s.UserID); e != nil {
		return e
	}
	if e := tx.Commit(r.Context()); e != nil {
		return e
	}
	a.cookie(w, a.cookieName("session"), "", -1)
	target := a.config.AppURL + "/"
	if a.logoutURL != "" {
		u, e := url.Parse(a.logoutURL)
		if e != nil {
			return e
		}
		q := u.Query()
		q.Set("post_logout_redirect_uri", a.config.AppURL+"/")
		if idToken != "" {
			q.Set("id_token_hint", idToken)
		} else {
			// Without a hint the provider must ask the user to confirm; the local
			// session is already gone either way.
			q.Set("client_id", a.config.ClientID)
		}
		u.RawQuery = q.Encode()
		target = u.String()
	}
	reply(w, 200, map[string]any{"ok": true, "logout_url": target})
	return nil
}

type Organization struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Role     string  `json:"role"`
	ParentID *string `json:"parent_id"`
}

func (a *App) session(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	instanceOwner := isInstanceOwner(r.Context(), tx, s)
	rows, e := tx.Query(r.Context(), `SELECT u.id,u.name,u.role,o.parent_id FROM user_organizations($1) u JOIN organizations o ON o.id=u.id ORDER BY u.name,u.id`, s.UserID)
	if e != nil {
		return e
	}
	defer rows.Close()
	orgs := []Organization{}
	var current Organization
	for rows.Next() {
		var org Organization
		if e = rows.Scan(&org.ID, &org.Name, &org.Role, &org.ParentID); e != nil {
			return e
		}
		orgs = append(orgs, org)
		if org.ID == s.OrganizationID {
			current = org
		}
	}
	if e = rows.Err(); e != nil {
		return e
	}
	// A machine credential is pinned to one organization, so listing the holder's
	// whole reachable tree here -- names and roles included -- discloses structure it
	// can never act on. The pin in effective_access already blocks acting; this closes
	// the confidentiality half.
	if s.pinned() {
		orgs = []Organization{current}
	}
	var language, userLanguage string
	if e = tx.QueryRow(r.Context(), sqlDefaultLanguage).Scan(&language); e != nil {
		return e
	}
	// A stored personal language is served as is; empty leaves the choice to the
	// console, which follows this reader's browser and then English.
	if e = tx.QueryRow(r.Context(), "SELECT language FROM users WHERE id=$1", s.UserID).Scan(&userLanguage); e != nil {
		return e
	}
	// demo_read_only tells the console that every mutation will be refused before
	// it is even routed, so it can withhold the controls that would raise one. It
	// is a rendering hint and nothing else: the refusal itself lives in
	// demoRefuses(), which does not consult the console, and the permissions above
	// are unchanged. A console that ignored this flag would simply show buttons
	// that answer 403 -- ugly, never unsafe.
	// license is a rendering hint as well: every refusal it announces is enforced by
	// the server (license.go).
	license, e := a.licenseStatus(r.Context())
	if e != nil {
		return e
	}
	reply(w, 200, map[string]any{"license": license, "is_instance_owner": instanceOwner,"console_debug": a.config.ConsoleDebug, "demo_read_only": a.config.DemoReadOnly, "privacy": map[string]bool{"aggregate_only": privacyFor(r).view.Config.AggregateOnly}, "default_language": language, "user": map[string]string{"id": s.UserID, "email": s.Email, "display_name": s.DisplayName, "language": userLanguage}, "organization": current, "organizations": orgs, "permissions": s.Permissions, "csrf_token": s.CSRF, "edition": Edition})
	return nil
}
