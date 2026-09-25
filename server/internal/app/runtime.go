package app

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	RoleAll         = "all"
	RoleAPI         = "api"
	RoleExports     = "exports"
	RoleMaintenance = "maintenance"
	RoleMigrate     = "migrate"

	runtimeSchemaVersion = 2026091903
)

func (c Config) ProcessRole() string {
	if c.Role == "" {
		return RoleAll
	}
	return c.Role
}

func (c Config) ServesAPI() bool {
	return c.ProcessRole() == RoleAll || c.ProcessRole() == RoleAPI
}

func (c Config) RunsMigrations() bool {
	return c.ProcessRole() == RoleAll || c.ProcessRole() == RoleMigrate
}

func validateProcessRole(role string) error {
	switch role {
	case "", RoleAll, RoleAPI, RoleMaintenance, RoleMigrate:
		return nil
	case RoleExports:
		if Edition != "commercial" {
			return errors.New("MILVAGO_ROLE=exports requires the Enterprise edition")
		}
		return nil
	default:
		return errors.New("MILVAGO_ROLE must be all, api, exports, maintenance or migrate")
	}
}

// Bootstrap performs instance initialization once per deployment Job. Runtime API
// replicas must never initialize durable deployment credentials or mutate Keycloak.
func Bootstrap(ctx context.Context, c Config, p *pgxpool.Pool, logger *slog.Logger) error {
	a := &App{config: c, db: p, log: logger}
	if e := a.initBackgroundIdentity(); e != nil {
		return e
	}
	return a.initializeInstance(ctx)
}

func (a *App) initializeInstance(ctx context.Context) error {
	if e := a.ensureDeploymentKeys(ctx); e != nil {
		return e
	}
	// The existing best-effort MCP policy remains unchanged: API-key access still
	// works if identity administration is unavailable.
	a.ensureMCPIdentity(ctx)
	a.warnTenantDirectories(ctx)
	return nil
}

// Background identity administration uses Keycloak's fixed token endpoint. It
// needs no console client, discovery request, session cipher or token verifier.
func (a *App) initBackgroundIdentity() error {
	if a.config.Issuer == "" {
		return nil
	}
	public, e := url.Parse(a.config.Issuer)
	if e != nil || public.Host == "" || !secureURL(public) {
		return errors.New("invalid background OIDC issuer")
	}
	client := &http.Client{Timeout: 15 * time.Second}
	if a.config.InternalOIDC != "" {
		internal, e := url.Parse(a.config.InternalOIDC)
		if e != nil || internal.Host == "" || (internal.Scheme != "http" && internal.Scheme != "https") || internal.User != nil || internal.Path != "" || internal.RawQuery != "" || internal.Fragment != "" {
			return errors.New("invalid OIDC_INTERNAL_URL")
		}
		client.Transport = oidcTransport{public, internal, http.DefaultTransport}
	}
	a.oidcClient = client
	a.oauth.Endpoint.TokenURL = a.config.Issuer + "/protocol/openid-connect/token"
	return nil
}
