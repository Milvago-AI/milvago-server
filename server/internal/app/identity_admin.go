package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const keycloakUsersPath = "/users/"

// identityAdmin is a short-lived client for the Keycloak admin REST API,
// authenticated with the management service account. Requests go through
// the internal identity address when one is configured.
type identityAdmin struct {
	// reset drops the cached service-account token when the provider refuses it
	// (restart, key rotation), so the next call asks for a fresh one.
	reset  func()
	client *http.Client
	token  string
	base   string // scheme://host/admin/realms/{realm}
}

// identityUser is the subset of Keycloak's UserRepresentation the server uses.
type identityUser struct {
	ID             string `json:"id"`
	Username       string `json:"username"`
	Email          string `json:"email"`
	FirstName      string `json:"firstName"`
	LastName       string `json:"lastName"`
	FederationLink string `json:"federationLink"`
	// Enabled is a pointer on purpose. A plain bool would read as "disabled" when
	// the field is simply absent from a response, and revokeWithdrawnIdentities
	// revokes credentials on that verdict -- an irreversible action. Absent means
	// unknown, and unknown must change nothing.
	Enabled *bool `json:"enabled"`
}

// hasOTP reads the current Keycloak credential list. A missing or unreadable list
// cannot prove that a password-only login is safe.
func (admin *identityAdmin) hasOTP(ctx context.Context, subject string) (bool, error) {
	status, _, raw, err := admin.call(ctx, "GET", keycloakUsersPath+url.PathEscape(subject)+"/credentials", nil)
	if err != nil {
		return false, err
	}
	if status != http.StatusOK {
		return false, apiError{503, "identity_admin_unavailable", "Could not verify the account MFA configuration."}
	}
	var credentials []struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &credentials); err != nil {
		return false, err
	}
	if credentials == nil {
		return false, apiError{503, "identity_admin_unavailable", "Could not verify the account MFA configuration."}
	}
	for _, credential := range credentials {
		if credential.Type == "otp" {
			return true, nil
		}
	}
	return false, nil
}

// withdrawn reports whether the identity provider has stopped honouring this
// account: deleted (no user at all) or explicitly disabled. A nil receiver is the
// deleted case; a nil Enabled is an unknown, which is not a withdrawal.
func (u *identityUser) withdrawn() bool {
	if u == nil {
		return true
	}
	return u.Enabled != nil && !*u.Enabled
}

func (u identityUser) displayName() string {
	return identityText(strings.TrimSpace(strings.TrimSpace(u.FirstName) + " " + strings.TrimSpace(u.LastName)))
}

func (a *App) identityAdmin(ctx context.Context) (*identityAdmin, error) {
	if a.config.AdminClientID == "" || a.config.AdminClientSecret == "" {
		return nil, apiError{503, "identity_admin_unavailable", "Identity administration is not configured."}
	}
	issuer, e := url.Parse(a.config.Issuer)
	if e != nil {
		return nil, e
	}
	parts := strings.Split(strings.Trim(issuer.Path, "/"), "/")
	if len(parts) != 2 || parts[0] != "realms" {
		return nil, apiError{503, "identity_admin_unavailable", "Keycloak realm URL is required for identity administration."}
	}
	baseOrigin := issuer.Scheme + "://" + issuer.Host
	client := a.oidcClient
	tokenURL := a.oauth.Endpoint.TokenURL
	if a.config.InternalOIDC != "" {
		baseOrigin = a.config.InternalOIDC
		client = &http.Client{Timeout: 15 * time.Second}
		tokenURL = baseOrigin + issuer.Path + "/protocol/openid-connect/token"
	}
	base := baseOrigin + "/admin/realms/" + url.PathEscape(parts[1])
	// The service-account token is reused until shortly before it expires: one grant
	// per call let any member drive three identity-provider requests per profile read
	// (audit of 2026-09-24). Keyed on what it was granted for, so a changed
	// configuration never reuses another account's token.
	cacheKey := a.config.AdminClientID + "\x00" + a.config.AdminClientSecret + "\x00" + tokenURL
	a.adminToken.Lock()
	if a.adminToken.key == cacheKey && time.Now().Before(a.adminToken.until) {
		cached := a.adminToken.value
		a.adminToken.Unlock()
		return &identityAdmin{reset: a.forgetAdminToken, client: client, token: cached, base: base}, nil
	}
	a.adminToken.Unlock()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {a.config.AdminClientID}, "client_secret": {a.config.AdminClientSecret}}
	request, e := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(form.Encode()))
	if e != nil {
		return nil, e
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, e := client.Do(request)
	if e != nil {
		return nil, apiError{502, "identity_unavailable", "Could not contact identity administration."}
	}
	defer response.Body.Close()
	var token struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if response.StatusCode != 200 || json.NewDecoder(io.LimitReader(response.Body, 64*1024)).Decode(&token) != nil || token.AccessToken == "" {
		return nil, apiError{502, "identity_unavailable", "Identity administration rejected the service account."}
	}
	// Half the lifetime, at most five minutes: a role taken from the service account
	// stops being usable soon, and a token is never presented near its expiry.
	if life := min(time.Duration(token.ExpiresIn)*time.Second/2, 5*time.Minute); life > 0 {
		a.adminToken.Lock()
		a.adminToken.key, a.adminToken.value, a.adminToken.until = cacheKey, token.AccessToken, time.Now().Add(life)
		a.adminToken.Unlock()
	}
	return &identityAdmin{reset: a.forgetAdminToken, client: client, token: token.AccessToken, base: base}, nil
}

func (a *App) forgetAdminToken() {
	a.adminToken.Lock()
	a.adminToken.value, a.adminToken.until = "", time.Time{}
	a.adminToken.Unlock()
}

// call performs one admin request. path is relative to the realm admin root
// (for example "/users?email=..."). A transport failure is reported as a 502
// apiError; HTTP status codes are returned to the caller for interpretation.
func (c *identityAdmin) call(ctx context.Context, method, path string, body any) (int, http.Header, []byte, error) {
	var raw []byte
	if body != nil {
		var e error
		if raw, e = json.Marshal(body); e != nil {
			return 0, nil, nil, e
		}
	}
	request, e := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(raw))
	if e != nil {
		return 0, nil, nil, e
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, e := c.client.Do(request)
	if e != nil {
		return 0, nil, nil, apiError{502, "identity_unavailable", "Could not contact identity administration."}
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized && c.reset != nil {
		c.reset()
	}
	out, e := io.ReadAll(io.LimitReader(response.Body, 128*1024))
	if e != nil {
		return 0, nil, nil, apiError{502, "identity_unavailable", "Invalid identity administration response."}
	}
	return response.StatusCode, response.Header, out, nil
}

// user fetches one Keycloak account by ID; (nil, nil) when it does not exist.
func (c *identityAdmin) user(ctx context.Context, subject string) (*identityUser, error) {
	status, _, raw, e := c.call(ctx, "GET", keycloakUsersPath+url.PathEscape(subject), nil)
	if e != nil {
		return nil, e
	}
	if status == 404 {
		return nil, nil
	}
	var u identityUser
	if status != 200 || json.Unmarshal(raw, &u) != nil || u.ID == "" {
		return nil, apiError{502, "identity_unavailable", "Could not read the identity account."}
	}
	return &u, nil
}

// answering reports whether the administration API is actually usable for this
// realm and service account.
//
// It exists because a 404 on a single user is ambiguous: the account may be gone,
// or the request may have reached the wrong realm, or the service account may
// have lost its rights. All three answer 404 on /users/{id}, and a caller that
// treats a 404 as "deleted" would conclude that *every* account has been deleted
// the moment the configuration is wrong. A caller acting irreversibly on that
// verdict -- revokeWithdrawnIdentities does -- must corroborate it here first,
// because the collection endpoint answers 200 for a realm that exists and fails
// for one that does not.
func (c *identityAdmin) answering(ctx context.Context) bool {
	status, _, _, e := c.call(ctx, "GET", "/users?max=1", nil)
	return e == nil && status == 200
}

// identityType classifies an account: "ldap" when provided by a user-storage
// federation, "sso" when linked to a brokered identity provider, else "local".
func (c *identityAdmin) identityType(ctx context.Context, u *identityUser) (string, error) {
	if u.FederationLink != "" {
		return "ldap", nil
	}
	status, _, raw, e := c.call(ctx, "GET", keycloakUsersPath+url.PathEscape(u.ID)+"/federated-identity", nil)
	if e != nil {
		return "", e
	}
	var links []json.RawMessage
	if status != 200 || json.Unmarshal(raw, &links) != nil {
		return "", apiError{502, "identity_unavailable", "Could not read the account's identity links."}
	}
	if len(links) > 0 {
		return "sso", nil
	}
	return "local", nil
}
