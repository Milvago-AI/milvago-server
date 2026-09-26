package app

import (
	"context"
	"testing"

	"golang.org/x/oauth2"
)

func TestPublicIdentityConfiguration(t *testing.T) {
	provider := identityProvider(t)
	app := &App{
		config: Config{
			AppURL:            provider.server.URL,
			Issuer:            provider.server.URL + "/realms/test",
			ClientID:          "test-console",
			AdminClientID:     "test-management",
			AdminClientSecret: "test-secret",
		},
		oidcClient: provider.server.Client(),
		oauth:      oauth2.Config{Endpoint: oauth2.Endpoint{TokenURL: provider.server.URL + "/token"}},
	}
	for range 2 {
		if err := app.syncPublicIdentity(context.Background(), "https://console.example.test"); err != nil {
			t.Fatal(err)
		}
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if got := provider.realmAttributes["frontendUrl"]; got != "https://console.example.test" {
		t.Fatalf("realm frontend URL = %q", got)
	}
	client := provider.clients["console"]
	if len(client.RedirectURIs) != 1 || client.RedirectURIs[0] != "https://console.example.test/auth/callback" {
		t.Fatalf("client redirect URIs = %v", client.RedirectURIs)
	}
	if len(client.WebOrigins) != 1 || client.WebOrigins[0] != "https://console.example.test" {
		t.Fatalf("client web origins = %v", client.WebOrigins)
	}
	if got := client.Attributes["post.logout.redirect.uris"]; got != "https://console.example.test/*" {
		t.Fatalf("post logout URI = %q", got)
	}
}

func TestConfirmedPublicOriginChangesOIDCClient(t *testing.T) {
	f := newSetupWizardFixture(t)
	before, err := f.a.currentOIDC(context.Background())
	if err != nil { t.Fatal(err) }
	if before.origin != f.origin { t.Fatalf("initial origin = %q", before.origin) }
	const public = "https://console.example.test"
	if _, err := f.admin.Exec(context.Background(), "UPDATE app_config SET public_url=$1, public_url_confirmed=true", public); err != nil { t.Fatal(err) }
	after, err := f.a.currentOIDC(context.Background())
	if err != nil { t.Fatal(err) }
	if after == before || after.origin != public || after.oauth.RedirectURL != public+"/auth/callback" {
		t.Fatalf("OIDC client did not move to confirmed origin: %q", after.oauth.RedirectURL)
	}
	if !f.a.browserSecure() || f.a.cookieName("session") != "__Host-"+cookieName("session") {
		t.Fatal("HTTPS cookies were not enabled after the public origin changed")
	}
}

func TestPublicSettingsUpdateReconfiguresLogin(t *testing.T) {
	f := newSecurityFixture(t)
	f.loginOwner(t)
	const public = "https://console.example.test"
	var days int
	if err := f.admin.QueryRow(context.Background(), "SELECT retention_days FROM settings WHERE organization_id=$1", f.session.Organization.ID).Scan(&days); err != nil { t.Fatal(err) }
	w := f.call("PUT", "/api/settings", map[string]any{
		"name": "Test organization", "event_retention_days": days, "public_url": public,
	}, f.sessionCookie, f.session.CSRF, f.config.AppURL, "")
	requireHTTP(t, w, 200)
	f.p.mu.Lock()
	client := f.p.clients["console"]
	redirect := ""
	if len(client.RedirectURIs) == 1 { redirect = client.RedirectURIs[0] }
	f.p.mu.Unlock()
	if redirect != public+"/auth/callback" { t.Fatalf("Keycloak redirect = %q", redirect) }
	state, err := f.a.currentOIDC(context.Background())
	if err != nil { t.Fatal(err) }
	if state.origin != public || state.oauth.RedirectURL != redirect || !f.a.browserSecure() {
		t.Fatalf("login origin did not change: %q", state.origin)
	}
}
