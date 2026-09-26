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
// an attacker's account). Plain HTTP cannot use the prefix.
func (a *App) cookieName(kind string) string {
	if a.config.SecureCookies {
		return "__Host-" + cookieName(kind)
	}
	return cookieName(kind)
}
func (a *App) loginProfileAction(w http.ResponseWriter, r *http.Request) (string, bool) {
	action := r.URL.Query().Get("action")
	// A read-only demonstration must refuse account-changing actions even though
	// this entry point uses GET.
	if a.config.DemoReadOnly && action != "" {
		a.fail(w, apiError{403, "demo_read_only", "This demonstration instance is read-only."})
		return "", true
	}
	kcAction, known := profileActions[action]
	if action == "" || (!known && action != "manage_mfa") {
		return "", false
	}
	cookie, e := r.Cookie(a.cookieName("session"))
	if e != nil {
		return "", false
	}
	session, e := a.loadSession(r, cookie.Value)
	if e != nil {
		return "", false
	}
	if !profileActionAllowed(session.IdentityType, action) {
		a.fail(w, apiError{403, "action_forbidden", "This account setting is managed by your identity provider."})
		return "", true
	}
	if action == "manage_mfa" {
		// Keycloak owns credential management; only the configured issuer receives this redirect.
		accountURL := strings.TrimRight(a.config.Issuer, "/") + "/account/account-security/signing-in"
		if language := r.URL.Query().Get("lang"); slices.Contains(consoleLanguages, language) {
			accountURL += "?" + url.Values{"kc_locale": {language}}.Encode()
		}
		http.Redirect(w, r, accountURL, http.StatusFound)
		return "", true
	}
	return kcAction, false
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if err := a.checkPublicRequest(r, "login", 120, 1200); err != nil {
		a.fail(w, err)
		return
	}
	kcAction, handled := a.loginProfileAction(w, r)
	if handled {
		return
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

type loginAttempt struct {
	verifier, nonce                   string
	associationOrg, associationDevice *string
	associationHash                   []byte
	stepUp                            bool
}

type loginClaims struct {
	Email    string   `json:"email"`
	Name     string   `json:"name"`
	Verified bool     `json:"email_verified"`
	AMR      []string `json:"amr"`
	ACR      string   `json:"acr"`
	AuthTime int64    `json:"auth_time"`
}

func (a *App) consumeLoginAttempt(w http.ResponseWriter, r *http.Request) (loginAttempt, error) {
	var attempt loginAttempt
	cookie, e := r.Cookie(a.cookieName("login"))
	if e != nil {
		return attempt, bad("The login attempt has expired.")
	}
	a.cookie(w, a.cookieName("login"), "", -1)
	e = a.db.QueryRow(r.Context(), "DELETE FROM login_attempts WHERE state_hash=$1 AND binding_hash=$2 AND expires_at>now() RETURNING verifier,nonce,association_org,association_device,association_hash,step_up", hash(r.URL.Query().Get("state")), hash(cookie.Value)).
		Scan(&attempt.verifier, &attempt.nonce, &attempt.associationOrg, &attempt.associationDevice, &attempt.associationHash, &attempt.stepUp)
	if e != nil || r.URL.Query().Get("code") == "" {
		return attempt, bad("Invalid or reused login attempt.")
	}
	return attempt, nil
}

func (a *App) verifyLoginToken(ctx context.Context, code string, attempt loginAttempt) (*oauth2.Token, *oidc.IDToken, string, loginClaims, error) {
	var claims loginClaims
	token, e := a.oauth.Exchange(ctx, code, oauth2.VerifierOption(attempt.verifier))
	if e != nil {
		return nil, nil, "", claims, apiError{401, "identity_failed", "Identity provider rejected the authorization code."}
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, nil, "", claims, apiError{401, "identity_failed", "Identity token is missing."}
	}
	id, e := a.verifier.Verify(ctx, raw)
	if e != nil || !equal(id.Nonce, attempt.nonce) {
		return nil, nil, "", claims, apiError{401, "identity_failed", "Identity token validation failed."}
	}
	if e = id.Claims(&claims); e == nil {
		claims.Name = identityText(claims.Name)
	}
	// A verified address with control characters must be refused, not folded:
	// distinct identity provider accounts could otherwise match the bootstrap.
	if e != nil || !claims.Verified || claims.Email == "" || identityText(claims.Email) != claims.Email {
		return nil, nil, "", claims, apiError{403, "verified_email_required", "A verified email address is required."}
	}
	return token, id, raw, claims, nil
}

func loginMFAEvidence(claims loginClaims) bool {
	if claims.ACR == "2" {
		return true
	}
	for _, amr := range claims.AMR {
		if amr == "mfa" || amr == "otp" {
			return true
		}
	}
	return false
}

func (a *App) loginIdentityKind(ctx context.Context, subject string) string {
	// A lookup failure never blocks sign-in; the stored identity type survives.
	admin, e := a.identityAdmin(ctx)
	if e != nil {
		return ""
	}
	u, e := admin.user(ctx, subject)
	if e != nil {
		a.log.Warn("identity account lookup failed", "error", e)
		return ""
	}
	if u == nil {
		return ""
	}
	kind, e := admin.identityType(ctx, u)
	if e != nil {
		a.log.Warn("identity type lookup failed", "error", e)
		return ""
	}
	return kind
}

func (a *App) bootstrapLoginAccount(ctx context.Context, tx pgx.Tx, org, user, kind string, id *oidc.IDToken, claims loginClaims) (string, error) {
	var members int
	if e := tx.QueryRow(ctx, "SELECT count(*) FROM memberships WHERE organization_id=$1", org).Scan(&members); e != nil {
		return "", e
	}
	if members != 0 {
		return "", forbidden()
	}
	if user == "" {
		if e := tx.QueryRow(ctx, "INSERT INTO users(subject,email,display_name,identity_type) VALUES($1,$2,$3,COALESCE(NULLIF($4,''),'local')) RETURNING id", id.Subject, claims.Email, claims.Name, kind).Scan(&user); e != nil {
			return "", e
		}
	}
	if _, e := tx.Exec(ctx, "INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')", org, user); e != nil {
		return "", e
	}
	if _, e := tx.Exec(ctx, "UPDATE app_config SET bootstrap_consumed=true WHERE singleton"); e != nil {
		return "", e
	}
	if e := audit(ctx, tx, org, user, "organization.bootstrap", org); e != nil {
		return "", e
	}
	return user, nil
}

func (a *App) loadLoginUser(ctx context.Context, tx pgx.Tx, id *oidc.IDToken, claims loginClaims, kind string) (string, string, error) {
	var org, bootstrapEmail string
	var consumed bool
	if e := tx.QueryRow(ctx, "SELECT organization_id,bootstrap_email,bootstrap_consumed FROM app_config WHERE singleton FOR UPDATE").Scan(&org, &bootstrapEmail, &consumed); e != nil {
		return "", "", e
	}
	if _, e := tx.Exec(ctx, "SELECT set_config('milvago.organization_id',$1,true)", org); e != nil {
		return "", "", e
	}
	var user string
	if e := tx.QueryRow(ctx, "SELECT id FROM users WHERE subject=$1", id.Subject).Scan(&user); e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return "", "", e
	}
	// An empty bootstrap address cannot match an account with no email.
	// ASCII case is deliberate; Unicode folding can conflate different accounts.
	if !consumed && bootstrapEmail != "" && asciiLower(claims.Email) == bootstrapEmail {
		var e error
		user, e = a.bootstrapLoginAccount(ctx, tx, org, user, kind, id, claims)
		if e != nil {
			return "", "", e
		}
	}
	if user == "" {
		return "", "", apiError{403, "membership_required", "Your account has no organization membership."}
	}
	return user, org, nil
}

func (a *App) establishLoginAccount(ctx context.Context, tx pgx.Tx, id *oidc.IDToken, claims loginClaims, kind string) (string, string, error) {
	user, org, e := a.loadLoginUser(ctx, tx, id, claims, kind)
	if e != nil {
		return "", "", e
	}
	var identityType string
	if e := tx.QueryRow(ctx, "UPDATE users SET email=$1,display_name=$2,identity_type=COALESCE(NULLIF($3,''),identity_type) WHERE id=$4 RETURNING identity_type", claims.Email, claims.Name, kind, user).Scan(&identityType); e != nil {
		return "", "", e
	}
	if identityType != "local" {
		license, e := a.licenseStatus(ctx)
		if e != nil {
			return "", "", e
		}
		if license.Restricted {
			return "", "", errLicenseRestricted
		}
	}
	// Prefer an explicit top-level organization, then a stable name order.
	if e := tx.QueryRow(ctx, "SELECT u.id FROM user_organizations($1) u JOIN organizations o ON o.id=u.id ORDER BY (o.parent_id IS NOT NULL), u.name, u.id LIMIT 1", user).Scan(&org); e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return "", "", apiError{403, "membership_required", "Your account has no organization membership."}
		}
		return "", "", e
	}
	if _, e := tx.Exec(ctx, "SELECT set_config('milvago.organization_id',$1,true)", org); e != nil {
		return "", "", e
	}
	return user, org, nil
}

func loginVerifiedAt(mfa, stepUp bool, authTime int64) *time.Time {
	var verifiedAt *time.Time
	if mfa && authTime > 0 {
		t := time.Unix(authTime, 0)
		if !t.After(time.Now().Add(30 * time.Second)) {
			verifiedAt = &t
		}
	}
	// A step-up carries prompt=login and max_age=0; the configured identity
	// realm enforces fresh level-two authentication even without auth_time.
	if verifiedAt == nil && mfa && stepUp {
		now := time.Now()
		verifiedAt = &now
	}
	return verifiedAt
}

type verifiedLogin struct {
	attempt loginAttempt
	token   *oauth2.Token
	id      *oidc.IDToken
	raw     string
	claims  loginClaims
}

func (a *App) createLoginSession(ctx context.Context, tx pgx.Tx, org, user string, flow verifiedLogin, mfa bool) (string, time.Time, error) {
	session, csrf := randomToken(), randomToken()
	digest := hash(session)
	tokens, e := json.Marshal(sessionTokens{Token: *flow.token, IDToken: flow.raw})
	if e != nil {
		return "", time.Time{}, e
	}
	nonceBytes := make([]byte, a.config.SessionCipher.NonceSize())
	if _, e = rand.Read(nonceBytes); e != nil {
		return "", time.Time{}, e
	}
	encrypted := a.config.SessionCipher.Seal(nonceBytes, nonceBytes, tokens, digest)
	expiry := time.Now().Add(8 * time.Hour)
	verifiedAt := loginVerifiedAt(mfa, flow.attempt.stepUp, flow.claims.AuthTime)
	if _, e = tx.Exec(ctx, "INSERT INTO sessions(token_hash,user_id,organization_id,csrf_token,encrypted_tokens,mfa,expires_at,identity_expires_at,oidc_nonce,mfa_verified_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", digest, user, org, csrf, encrypted, mfa, expiry, flow.id.Expiry, flow.attempt.nonce, verifiedAt); e != nil {
		return "", time.Time{}, e
	}
	if e = audit(ctx, tx, org, user, "session.login", user); e != nil {
		return "", time.Time{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return "", time.Time{}, e
	}
	return session, expiry, nil
}

func (a *App) completeLogin(w http.ResponseWriter, r *http.Request, ctx context.Context, flow verifiedLogin) error {
	mfa := loginMFAEvidence(flow.claims)
	kind := a.loginIdentityKind(ctx, flow.id.Subject)
	tx, e := a.db.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	user, org, e := a.establishLoginAccount(ctx, tx, flow.id, flow.claims, kind)
	if e != nil {
		return e
	}
	var requireMFA bool
	if e = tx.QueryRow(ctx, "SELECT require_mfa FROM settings WHERE organization_id=$1", org).Scan(&requireMFA); e != nil {
		return e
	}
	if !requireMFA && !mfa {
		admin, err := a.identityAdmin(ctx)
		if err != nil {
			return apiError{503, "identity_admin_unavailable", "Could not verify the account MFA configuration."}
		}
		requireMFA, err = admin.hasOTP(ctx, flow.id.Subject)
		if err != nil {
			a.log.Warn("identity credential lookup failed", "error", err)
			return apiError{503, "identity_admin_unavailable", "Could not verify the account MFA configuration."}
		}
	}
	if requireMFA && !mfa {
		if flow.attempt.stepUp {
			return apiError{403, "mfa_required", "Multi-factor authentication is required for this organization."}
		}
		var language string
		if e = tx.QueryRow(ctx, sqlDefaultLanguage).Scan(&language); e != nil {
			return e
		}
		http.Redirect(w, r, "/auth/login?mfa=1&lang="+url.QueryEscape(language), http.StatusFound)
		return nil
	}
	session, expiry, e := a.createLoginSession(ctx, tx, org, user, flow, mfa)
	if e != nil {
		return e
	}
	a.cookie(w, a.cookieName("session"), session, int(time.Until(expiry).Seconds()))
	target := "/"
	if r.URL.Query().Get("kc_action_status") != "" {
		target = "/#profile"
	}
	http.Redirect(w, r, target, http.StatusFound)
	return nil
}

func (a *App) callback(w http.ResponseWriter, r *http.Request) {
	attempt, e := a.consumeLoginAttempt(w, r)
	if e != nil {
		a.fail(w, e)
		return
	}
	ctx := oidc.ClientContext(r.Context(), a.oidcClient)
	token, id, raw, claims, e := a.verifyLoginToken(ctx, r.URL.Query().Get("code"), attempt)
	if e != nil {
		a.fail(w, e)
		return
	}
	if attempt.associationOrg != nil && attempt.associationDevice != nil {
		var associationClaims map[string]json.RawMessage
		if e = id.Claims(&associationClaims); e != nil {
			a.fail(w, bad("Invalid verified association claims."))
			return
		}
		if e = a.finishDeviceAssociation(w, r, *attempt.associationOrg, *attempt.associationDevice, attempt.associationHash, deviceAssociationIdentity{subject: id.Subject, email: claims.Email, name: claims.Name, claims: associationClaims}); e != nil {
			a.fail(w, e)
		}
		return
	}
	if e = a.completeLogin(w, r, ctx, verifiedLogin{attempt: attempt, token: token, id: id, raw: raw, claims: claims}); e != nil {
		a.fail(w, e)
	}
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
	reply(w, 200, map[string]any{"license": license, "is_instance_owner": instanceOwner, "console_debug": a.config.ConsoleDebug, "demo_read_only": a.config.DemoReadOnly, "privacy": map[string]bool{"aggregate_only": privacyFor(r).view.Config.AggregateOnly}, "default_language": language, "user": map[string]string{"id": s.UserID, "email": s.Email, "display_name": s.DisplayName, "language": userLanguage}, "organization": current, "organizations": orgs, "permissions": s.Permissions, "csrf_token": s.CSRF, "edition": Edition})
	return nil
}
