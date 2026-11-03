package app

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type loginTrustOptions struct {
	allowed, remember bool
}

// Keycloak's OTP page records consent against both halves of the login attempt.
// The OIDC state keeps an old tab from changing a newer tab's login preference.
func (a *App) loginDeviceTrust(w http.ResponseWriter, r *http.Request) {
	if e := a.recordLoginDeviceTrust(w, r); e != nil {
		a.fail(w, e)
	}
}

func (a *App) recordLoginDeviceTrust(w http.ResponseWriter, r *http.Request) error {
	if a.config.DemoReadOnly || r.Header.Get("Authorization") != "" {
		return forbidden()
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return forbidden()
	}
	if r.Method == http.MethodPost && r.Header.Get("Origin") != a.browserOrigin() {
		return forbidden()
	}
	if e := a.checkPublicRequest(r, "login-device-trust", 120, 1200); e != nil {
		return e
	}
	cookie, e := r.Cookie(a.cookieName("login"))
	state := r.URL.Query().Get("state")
	if e != nil || len(cookie.Value) != 43 || len(state) != 43 {
		return apiError{401, "login_expired", "The login attempt has expired."}
	}
	var allowed, remember bool
	e = a.db.QueryRow(r.Context(), `SELECT allow_trusted_device,remember_device FROM login_attempts WHERE state_hash=$1 AND binding_hash=$2 AND expires_at>now() AND association_device IS NULL`, hash(state), hash(cookie.Value)).Scan(&allowed, &remember)
	if errors.Is(e, pgx.ErrNoRows) {
		return apiError{401, "login_expired", "The login attempt has expired."}
	}
	if e != nil {
		return e
	}
	if !allowed {
		return forbidden()
	}
	csrf := base64.RawURLEncoding.EncodeToString(hash("login-device-trust:" + state + ":" + cookie.Value))
	if r.Method == http.MethodGet {
		reply(w, 200, map[string]any{"csrf_token": csrf, "remember": remember})
		return nil
	}
	if !equal(r.Header.Get("X-CSRF-Token"), csrf) {
		return forbidden()
	}
	var body struct {
		Remember bool `json:"remember"`
	}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	result, e := a.db.Exec(r.Context(), `UPDATE login_attempts SET remember_device=$3 WHERE state_hash=$1 AND binding_hash=$2 AND expires_at>now() AND allow_trusted_device AND association_device IS NULL`, hash(state), hash(cookie.Value), body.Remember)
	if e != nil {
		return e
	}
	if result.RowsAffected() != 1 {
		return apiError{401, "login_expired", "The login attempt has expired."}
	}
	reply(w, 200, map[string]bool{"remember": body.Remember})
	return nil
}

// Credentials, rather than labels, bind trust to the account's current authentication
// methods. Removing/replacing a factor or changing a local password invalidates it.
func credentialFingerprint(credentials []identityCredential) []byte {
	parts := make([]string, 0, len(credentials))
	hasOTP := false
	for _, c := range credentials {
		if c.Type != "otp" && c.Type != "password" {
			continue
		}
		if c.ID == "" {
			return nil
		}
		hasOTP = hasOTP || c.Type == "otp"
		parts = append(parts, c.Type+":"+c.ID+":"+strconv.FormatInt(c.CreatedDate, 10))
	}
	if !hasOTP {
		return nil
	}
	slices.Sort(parts)
	return hash(strings.Join(parts, "\n"))
}

func (a *App) loginCredentialFingerprint(ctx context.Context, realm, subject string) ([]byte, error) {
	admin, e := a.identityAdminFor(ctx, realm)
	if e != nil {
		return nil, e
	}
	credentials, e := admin.credentials(ctx, subject)
	if e != nil {
		return nil, e
	}
	return credentialFingerprint(credentials), nil
}

func (a *App) trustedDeviceForLogin(ctx context.Context, tx pgx.Tx, r *http.Request, user, realm, subject string) (*time.Time, error) {
	cookie, e := r.Cookie(a.cookieName("trusted_device"))
	if e != nil || len(cookie.Value) != 43 {
		return nil, nil
	}
	if decoded, e := base64.RawURLEncoding.DecodeString(cookie.Value); e != nil || len(decoded) != 32 {
		return nil, nil
	}
	var stored []byte
	var expiry time.Time
	e = tx.QueryRow(ctx, `SELECT credential_hash,expires_at FROM trusted_login_devices WHERE token_hash=$1 AND user_id=$2 AND realm=$3 AND expires_at>clock_timestamp()`, hash(cookie.Value), user, realm).Scan(&stored, &expiry)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	current, e := a.loginCredentialFingerprint(ctx, realm, subject)
	if e != nil {
		return nil, e
	}
	if len(current) == 0 || !equal(hex.EncodeToString(stored), hex.EncodeToString(current)) {
		return nil, nil
	}
	return &expiry, nil
}

func (a *App) rememberLoginDevice(ctx context.Context, tx pgx.Tx, r *http.Request, org, user string, flow verifiedLogin) (string, time.Time, error) {
	verified := loginVerifiedAt(loginMFAEvidence(flow.claims), flow.claims.AuthTime)
	if verified == nil || !verified.After(time.Now().Add(-5*time.Minute)) {
		return "", time.Time{}, nil
	}
	fingerprint, e := a.loginCredentialFingerprint(ctx, flow.attempt.realm, flow.id.Subject)
	if e != nil || len(fingerprint) == 0 {
		return "", time.Time{}, e
	}
	// Explicit enrollment replaces this browser's previous credential. Ordinary
	// trusted logins never extend the original six calendar months.
	if previous, e := r.Cookie(a.cookieName("trusted_device")); e == nil {
		if _, e = tx.Exec(ctx, `DELETE FROM trusted_login_devices WHERE token_hash=$1 AND user_id=$2`, hash(previous.Value), user); e != nil {
			return "", time.Time{}, e
		}
	}
	token, expiry := randomToken(), time.Now().UTC().AddDate(0, 6, 0)
	if _, e = tx.Exec(ctx, `INSERT INTO trusted_login_devices(token_hash,user_id,realm,credential_hash,expires_at) VALUES($1,$2,$3,$4,$5)`, hash(token), user, flow.attempt.realm, fingerprint, expiry); e != nil {
		return "", time.Time{}, e
	}
	if e = audit(ctx, tx, org, user, "session.trust_device", user); e != nil {
		return "", time.Time{}, e
	}
	return token, expiry, nil
}

func (a *App) setTrustedDeviceCookie(w http.ResponseWriter, token string, expiry time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: a.cookieName("trusted_device"), Value: token, Path: "/",
		HttpOnly: true, Secure: a.browserSecure(), SameSite: http.SameSiteLaxMode,
		MaxAge: int(time.Until(expiry).Seconds()), Expires: expiry,
	})
}
