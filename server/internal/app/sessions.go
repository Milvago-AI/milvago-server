package app

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
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
	e = tx.QueryRow(ctx, `SELECT s.user_id,u.email,u.display_name,s.organization_id,s.csrf_token,s.mfa,s.encrypted_tokens,s.identity_expires_at,u.subject,u.identity_type,s.oidc_nonce FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now() FOR UPDATE OF s`, s.TokenHash).Scan(&s.UserID, &s.Email, &s.DisplayName, &s.OrganizationID, &s.CSRF, &s.MFA, &encrypted, &identityExpiry, &s.Subject, &s.IdentityType, &nonce)
	if e != nil {
		return nil, apiError{401, "unauthenticated", "Sign in to continue."}
	}
	if r.Method != "GET" && (r.Header.Get("Origin") != a.config.AppURL || !equal(r.Header.Get("X-CSRF-Token"), s.CSRF)) {
		return nil, apiError{403, "csrf_failed", "The request origin or CSRF token is invalid."}
	}
	if identityExpiry.Before(time.Now().Add(30*time.Second)) && r.URL.Path != "/auth/logout" {
		invalid := func() (*Session, error) {
			_, e := tx.Exec(ctx, `DELETE FROM sessions WHERE token_hash=$1`, s.TokenHash)
			if e != nil {
				return nil, e
			}
			if e = tx.Commit(ctx); e != nil {
				return nil, e
			}
			return nil, apiError{401, "session_expired", "The identity session expired. Sign in again."}
		}
		var stored sessionTokens
		if len(encrypted) < a.config.SessionCipher.NonceSize() {
			return invalid()
		}
		prefix := encrypted[:a.config.SessionCipher.NonceSize()]
		plain, e := a.config.SessionCipher.Open(nil, prefix, encrypted[a.config.SessionCipher.NonceSize():], s.TokenHash)
		if e != nil || json.Unmarshal(plain, &stored) != nil || stored.RefreshToken == "" {
			return invalid()
		}
		token := stored.Token
		token.Expiry = time.Now().Add(-time.Minute)
		oidcCtx := oidc.ClientContext(ctx, a.oidcClient)
		fresh, e := a.oauth.TokenSource(oidcCtx, &token).Token()
		if e != nil {
			var response *oauth2.RetrieveError
			if errors.As(e, &response) && response.ErrorCode == "invalid_grant" {
				return invalid()
			}
			return nil, apiError{503, "identity_unavailable", "Could not refresh your identity session. Try again."}
		}
		raw, ok := fresh.Extra("id_token").(string)
		if !ok {
			return invalid()
		}
		identity, e := a.verifier.Verify(oidcCtx, raw)
		if e != nil || identity.Subject != s.Subject || (identity.Nonce != "" && !equal(identity.Nonce, nonce)) {
			return invalid()
		}
		var claims struct {
			Email    string   `json:"email"`
			Name     string   `json:"name"`
			Verified bool     `json:"email_verified"`
			ACR      string   `json:"acr"`
			AMR      []string `json:"amr"`
		}
		if identity.Claims(&claims) != nil || !claims.Verified || claims.Email == "" {
			return invalid()
		}
		s.MFA = claims.ACR == "2"
		for _, amr := range claims.AMR {
			if amr == "mfa" || amr == "otp" {
				s.MFA = true
			}
		}
		serialized, e := json.Marshal(sessionTokens{Token: *fresh, IDToken: raw})
		if e != nil {
			return nil, e
		}
		nextNonce := make([]byte, a.config.SessionCipher.NonceSize())
		if _, e = rand.Read(nextNonce); e != nil {
			return nil, e
		}
		sealed := a.config.SessionCipher.Seal(nextNonce, nextNonce, serialized, s.TokenHash)
		if _, e = tx.Exec(ctx, `UPDATE sessions SET encrypted_tokens=$1,identity_expires_at=$2,mfa=$3 WHERE token_hash=$4`, sealed, identity.Expiry, s.MFA, s.TokenHash); e != nil {
			return nil, e
		}
		// The name is cleaned; an e-mail carrying such characters is not taken (the
		// sign-in refuses it, see callback), so the stored one stays.
		claims.Name = identityText(claims.Name)
		if identityText(claims.Email) != claims.Email {
			claims.Email = s.Email
		}
		if _, e = tx.Exec(ctx, `UPDATE users SET email=$1,display_name=$2 WHERE id=$3`, claims.Email, claims.Name, s.UserID); e != nil {
			return nil, e
		}
		s.Email = claims.Email
		s.DisplayName = claims.Name
	}
	if e = tx.Commit(ctx); e != nil {
		return nil, e
	}
	return s, nil
}
