package app

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"
)

// sessionTokens is the sealed session payload: the OAuth token plus the raw ID
// token. The ID token is kept so RP-initiated logout can send id_token_hint —
// without it Keycloak stops on a "Do you want to log out?" confirmation page.
// Rows sealed before this field decode with an empty IDToken.
type sessionTokens struct {
	oauth2.Token
	IDToken string `json:"id_token"`
}

// storedIDToken opens a sealed session payload; "" when it cannot be recovered
// (legacy row, rotated key, tampered ciphertext). Logout then falls back to the
// confirmation-based URL rather than failing.
func (a *App) storedIDToken(encrypted, aad []byte) string {
	size := a.config.SessionCipher.NonceSize()
	if len(encrypted) < size {
		return ""
	}
	plain, e := a.config.SessionCipher.Open(nil, encrypted[:size], encrypted[size:], aad)
	if e != nil {
		return ""
	}
	var stored sessionTokens
	if json.Unmarshal(plain, &stored) != nil {
		return ""
	}
	return stored.IDToken
}

type refreshedSessionClaims struct {
	Email    string   `json:"email"`
	Name     string   `json:"name"`
	Verified bool     `json:"email_verified"`
	ACR      string   `json:"acr"`
	AMR      []string `json:"amr"`
}

func (a *App) invalidateSession(ctx context.Context, tx pgx.Tx, s *Session) error {
	if _, e := tx.Exec(ctx, "DELETE FROM sessions WHERE token_hash=$1", s.TokenHash); e != nil {
		return e
	}
	if e := tx.Commit(ctx); e != nil {
		return e
	}
	return apiError{401, "session_expired", "The identity session expired. Sign in again."}
}

func (a *App) openRefreshCredentials(encrypted, digest []byte) (sessionTokens, bool) {
	var stored sessionTokens
	size := a.config.SessionCipher.NonceSize()
	if len(encrypted) < size {
		return stored, false
	}
	plain, e := a.config.SessionCipher.Open(nil, encrypted[:size], encrypted[size:], digest)
	if e != nil || json.Unmarshal(plain, &stored) != nil || stored.RefreshToken == "" {
		return stored, false
	}
	return stored, true
}

func (a *App) refreshSession(ctx context.Context, tx pgx.Tx, s *Session, encrypted []byte, nonce string) error {
	stored, ok := a.openRefreshCredentials(encrypted, s.TokenHash)
	if !ok {
		return a.invalidateSession(ctx, tx, s)
	}
	token := stored.Token
	token.Expiry = time.Now().Add(-time.Minute)
	// The account's own realm: a refresh token of one realm is never sent to another.
	identity, e := a.currentOIDCFor(ctx, s.Realm)
	if e != nil {
		return apiError{503, "identity_unavailable", "Identity configuration is unavailable."}
	}
	oidcCtx := oidc.ClientContext(ctx, identity.client)
	fresh, e := identity.oauth.TokenSource(oidcCtx, &token).Token()
	if e != nil {
		var response *oauth2.RetrieveError
		if errors.As(e, &response) && response.ErrorCode == "invalid_grant" {
			return a.invalidateSession(ctx, tx, s)
		}
		return apiError{503, "identity_unavailable", "Could not refresh your identity session. Try again."}
	}
	raw, ok := fresh.Extra("id_token").(string)
	if !ok {
		return a.invalidateSession(ctx, tx, s)
	}
	verified, e := identity.verifier.Verify(oidcCtx, raw)
	if e != nil || verified.Subject != s.Subject || (verified.Nonce != "" && !equal(verified.Nonce, nonce)) {
		return a.invalidateSession(ctx, tx, s)
	}
	var claims refreshedSessionClaims
	if verified.Claims(&claims) != nil || !claims.Verified || claims.Email == "" {
		return a.invalidateSession(ctx, tx, s)
	}
	return a.storeRefreshedSession(ctx, tx, s, fresh, raw, verified, claims)
}

func (a *App) storeRefreshedSession(ctx context.Context, tx pgx.Tx, s *Session, fresh *oauth2.Token, raw string, identity *oidc.IDToken, claims refreshedSessionClaims) error {
	s.MFA = claims.ACR == "2"
	for _, amr := range claims.AMR {
		if amr == "mfa" || amr == "otp" {
			s.MFA = true
		}
	}
	serialized, e := json.Marshal(sessionTokens{Token: *fresh, IDToken: raw})
	if e != nil {
		return e
	}
	nextNonce := make([]byte, a.config.SessionCipher.NonceSize())
	if _, e = rand.Read(nextNonce); e != nil {
		return e
	}
	sealed := a.config.SessionCipher.Seal(nextNonce, nextNonce, serialized, s.TokenHash)
	if _, e = tx.Exec(ctx, "UPDATE sessions SET encrypted_tokens=$1,identity_expires_at=$2,mfa=$3 WHERE token_hash=$4", sealed, identity.Expiry, s.MFA, s.TokenHash); e != nil {
		return e
	}
	// A changed email carrying controls is refused by sign-in and cannot replace
	// the previously verified address during refresh.
	claims.Name = identityText(claims.Name)
	if identityText(claims.Email) != claims.Email {
		claims.Email = s.Email
	}
	if _, e = tx.Exec(ctx, "UPDATE users SET email=$1,display_name=$2 WHERE id=$3", claims.Email, claims.Name, s.UserID); e != nil {
		return e
	}
	s.Email = claims.Email
	s.DisplayName = claims.Name
	return nil
}

func (a *App) loadSession(r *http.Request, opaque string) (*Session, error) {
	ctx := r.Context()
	tx, e := a.db.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	s := &Session{TokenHash: hash(opaque)}
	var encrypted []byte
	var identityExpiry time.Time
	var nonce string
	e = tx.QueryRow(ctx, `SELECT s.user_id,u.email,u.display_name,s.organization_id,s.csrf_token,s.mfa,s.encrypted_tokens,s.identity_expires_at,u.subject,u.identity_type,u.realm,s.oidc_nonce FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now() FOR UPDATE OF s`, s.TokenHash).Scan(&s.UserID, &s.Email, &s.DisplayName, &s.OrganizationID, &s.CSRF, &s.MFA, &encrypted, &identityExpiry, &s.Subject, &s.IdentityType, &s.Realm, &nonce)
	if e != nil {
		return nil, apiError{401, "unauthenticated", "Sign in to continue."}
	}
	if r.Method != "GET" && (r.Header.Get("Origin") != a.browserOrigin() || !equal(r.Header.Get("X-CSRF-Token"), s.CSRF)) {
		return nil, apiError{403, "csrf_failed", "The request origin or CSRF token is invalid."}
	}
	if identityExpiry.Before(time.Now().Add(30*time.Second)) && r.URL.Path != "/auth/logout" {
		if e = a.refreshSession(ctx, tx, s, encrypted, nonce); e != nil {
			return nil, e
		}
	}
	if e = tx.Commit(ctx); e != nil {
		return nil, e
	}
	return s, nil
}
