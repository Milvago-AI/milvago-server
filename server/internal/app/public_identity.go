package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type identityRuntime struct {
	origin    string
	issuer    string
	oauth     oauth2.Config
	verifier  *oidc.IDTokenVerifier
	provider  *oidc.Provider
	client    *http.Client
	logoutURL string
}

// publicIdentityOrigin uses the confirmed instance URL for browser redirects and
// cookies. The environment remains the bootstrap fallback until setup is complete.
func (a *App) publicIdentityOrigin(ctx context.Context) (string, error) {
	if a.db == nil {
		if a.config.PublicURL != "" {
			return a.config.PublicURL, nil
		}
		return a.config.AppURL, nil
	}
	var stored string
	var confirmed bool
	if err := a.db.QueryRow(ctx, "SELECT public_url, public_url_confirmed FROM app_config WHERE singleton").Scan(&stored, &confirmed); err != nil {
		return "", err
	}
	if confirmed && stored != "" {
		if !validOrigin(stored) {
			return "", errors.New("stored public URL is invalid")
		}
		return stored, nil
	}
	if a.config.PublicURL != "" {
		return a.config.PublicURL, nil
	}
	return a.config.AppURL, nil
}

func (a *App) publicIdentityIssuer(origin string) string {
	// A separate identity hostname stays independent of the agent URL.
	prefix := a.config.AppURL + "/realms/"
	if strings.HasPrefix(a.config.Issuer, prefix) {
		return origin + strings.TrimPrefix(a.config.Issuer, a.config.AppURL)
	}
	if current := a.publicOIDC.Load(); current != nil {
		return current.issuer
	}
	return a.config.Issuer
}

func (a *App) currentOIDC(ctx context.Context) (*identityRuntime, error) {
	origin, err := a.publicIdentityOrigin(ctx)
	if err != nil {
		return nil, err
	}
	issuer := a.publicIdentityIssuer(origin)
	if state := a.publicOIDC.Load(); state != nil && state.origin == origin && state.issuer == issuer {
		return state, nil
	}
	a.publicOIDCMu.Lock()
	defer a.publicOIDCMu.Unlock()
	if state := a.publicOIDC.Load(); state != nil && state.origin == origin && state.issuer == issuer {
		return state, nil
	}
	client := &http.Client{Timeout: 15 * time.Second}
	if a.config.InternalOIDC != "" {
		public, _ := url.Parse(issuer)
		internal, parseErr := url.Parse(a.config.InternalOIDC)
		if parseErr != nil || internal.Host == "" || !webURL(internal) || internal.User != nil || internal.Path != "" || internal.RawQuery != "" || internal.Fragment != "" {
			return nil, errors.New("invalid OIDC_INTERNAL_URL")
		}
		client.Transport = oidcTransport{public, internal, http.DefaultTransport}
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, client), issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}
	var discovery struct {
		Logout string `json:"end_session_endpoint"`
	}
	if err = provider.Claims(&discovery); err != nil {
		return nil, err
	}
	state := &identityRuntime{
		origin: origin, issuer: issuer, client: client, provider: provider, logoutURL: discovery.Logout,
		oauth: oauth2.Config{
			ClientID: a.config.ClientID, ClientSecret: a.config.ClientSecret,
			Endpoint: provider.Endpoint(), RedirectURL: origin + "/auth/callback",
			Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
		},
		verifier: provider.VerifierContext(oidc.ClientContext(context.Background(), client), &oidc.Config{
			ClientID: a.config.ClientID, SupportedSigningAlgs: []string{oidc.RS256},
		}),
	}
	a.publicOIDC.Store(state)
	return state, nil
}

func (a *App) browserOrigin() string {
	if state := a.publicOIDC.Load(); state != nil {
		return state.origin
	}
	return a.config.AppURL
}

func (a *App) browserSecure() bool {
	return strings.HasPrefix(a.browserOrigin(), "https://")
}
