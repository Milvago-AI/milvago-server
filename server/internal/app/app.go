package app

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"
)

const logoutPath = "/auth/logout"

type App struct {
	config   Config
	db       *pgxpool.Pool
	log      *slog.Logger
	mux      *http.ServeMux
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	// mcpVerifier validates the access tokens presented to the MCP endpoint: another
	// audience -- the endpoint itself as an OAuth resource -- on the same keys and the
	// same rotation as the console's verifier. Built once at boot, and only in
	// Enterprise: in Community nothing sets it and the endpoint does not exist.
	mcpVerifier  *oidc.IDTokenVerifier
	oidcClient   *http.Client
	logoutURL    string
	publicOIDC   atomic.Pointer[identityRuntime]
	publicOIDCMu sync.Mutex
	// realmOIDC holds the browser OIDC runtime of each organization realm other than the
	// root one, which stays in publicOIDC (Enterprise: one Keycloak realm per organization).
	realmOIDC     sync.Map
	metrics       *appMetrics
	metricsOnce   sync.Once
	exportMetrics exportMetricSnapshot
	exportHTTP    exportHTTPClient
	ingestRate    ingestLimiter
	publicRate    ingestLimiter
	publicTotals  ingestLimiter
	// root caches the root organization once setup has named it (Enterprise exports).
	root atomic.Pointer[string]
	// mcpClients caches, per OAuth client, whether its tokens may open /mcp
	// (Enterprise). Keyed by verified authorized parties only, so bounded by the realm.
	mcpClients sync.Map
	// mcpMapperPolicy records when the realm was last seen refusing mappers on
	// self-registered clients; until it is, only the connector opens /mcp (Enterprise).
	mcpMapperPolicy struct {
		sync.Mutex
		at time.Time
	}
	// adminToken caches one service-account token per realm, keyed on what it was
	// granted for.
	adminToken struct {
		sync.Mutex
		tokens map[string]cachedAdminToken
	}
	quotaReservations quotaReservations
	eventSlotsOnce    sync.Once
	eventSlots        chan struct{}
	// routes records every console route as it is registered, so a test can prove
	// that each one is covered by the identity-projection audit. A route that is
	// added later and not listed there fails that test instead of silently
	// escaping the review.
	routes []registeredRoute
	// Digest memoization for the release artifacts served to devices and the
	// Firefox update document: keyed on (path, size, mtime), so a poll costs a
	// stat instead of a full read and hash of a 128–256 Mio file.
	releaseCacheMu sync.Mutex
	releaseCache   map[string]releaseCacheEntry
	extFirefoxMu   sync.Mutex
	extFirefox     extFirefoxCacheEntry
	// Derived-AEAD memoization for the sealed regime. shadowCipher ran a full
	// HKDF-SHA256 plus an AES key schedule and GCM setup on every open and every
	// seal, and several callers do that once per row. Keyed on exactly what the
	// derivation consumes: the organization and the content key version.
	//
	// Safe to keep for the life of the process because a.config is immutable once
	// built: rotation adds a version and restarting the server is step one of the
	// documented procedure. If ContentKeys ever becomes reloadable at runtime, this
	// map has to be invalidated with it.
	shadowCipherMu sync.Mutex
	shadowCiphers  map[shadowCipherKey]cipher.AEAD
	// license memoizes the signature check of the stored licence (license.go).
	license licenseMemo
}

type registeredRoute struct {
	Pattern, Permission string
	Mode                credentialMode
}

// Ingestion budget per device, per minute, keyed by route. An approved device is
// authenticated, not trusted: without a ceiling it can fill the organization's
// storage as fast as the network allows. The budgets are far above what an agent
// does legitimately (one synchronization per minute, plus a bounded number of
// browser-triggered deliveries), so a device that reaches one is misbehaving.
// Routes absent from this table are not bounded here.
var deviceBudget = map[string]int{
	"/v1/policy":         60,
	"/v2/policy":         60,
	"/v3/policy":         60,
	"/v2/identity/start": 12,
	"/v3/enforcement":    60,
	"/v1/events":         60,
	"/v2/events":         60,
	// One completion follows one submission, so it shares the ingestion budget.
	"/v2/events/complete": 60,
	"/v2/heartbeat":       20,
	"/v1/inventory":       20,
	// A deployment key is readable by anyone who can read the installer it is
	// embedded in (installed on Linux it is 0640 root:milvago-agent since
	// 2026-09-24, no longer world-readable). Approval policy is the real bound, but under
	// automatic approval there was none at all: this makes bulk enrolment slow and
	// visible instead of instantaneous. Keyed by the key, not by a device.
	"/v2/install": 30,
	// Update polling is one manifest per minute per agent (endpoint main.rs), the
	// anchor rides with it, a status report follows an actual download, and the
	// catalogues refresh at most once a minute (endpoint detection.rs cooldown).
	// These budgets sit far above that cadence: reaching one is a misbehaving
	// device, and before they existed a fleet could drive a full artifact re-hash
	// per request. The artifact path carries a digest; deviceTx normalizes it to
	// this key before lookup.
	"/v2/update":            12,
	"/v2/update/artifact":   6,
	"/v2/update/anchor":     6,
	"/v2/update/status":     20,
	"/v3/catalog":           30,
	"/v3/detection-catalog": 30,
	"/v2/identity":          6,
}

// Fixed one-minute window. The whole map is dropped when the window turns, so
// its cardinality has a hard cap even when callers supply arbitrary credentials.
const maxRateKeys = 16384

type ingestLimiter struct {
	mu     sync.Mutex
	window time.Time
	counts map[string]int
}

func (l *ingestLimiter) allow(key string, budget int, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if minute := now.Truncate(time.Minute); !minute.Equal(l.window) {
		l.window = minute
		l.counts = make(map[string]int, len(l.counts))
	}
	if _, present := l.counts[key]; !present && len(l.counts) >= maxRateKeys {
		// Full: admit without counting. Every caller consults the shared PostgreSQL
		// budget next, which stays authoritative. Refusing here let 16384 source
		// addresses, or a fleet of a few thousand devices, lock out every key not yet
		// seen this minute (audit of 2026-09-24).
		return true
	}
	if budget <= 0 || l.counts[key] >= budget {
		return false
	}
	l.counts[key]++
	return true
}

type Session struct {
	TokenHash                                              []byte
	UserID, Email, DisplayName, OrganizationID, Role, CSRF string
	// Subject is the identity provider account ID; IdentityType is the last
	// known account source ('local', 'sso' or 'ldap') derived from Keycloak.
	Subject, IdentityType string
	// Realm is the stored Keycloak realm of the account ("" for the root one).
	Realm       string
	MFA         bool
	Permissions []string
	// APIKeyID is empty for a browser session and holds the key's identity when
	// the request authenticated with a bearer API key. The zero value is the
	// unprivileged reading: nothing has to be set for a session to stay safe.
	//
	// keyPermissions is the ceiling chosen when the key was created. It is
	// unexported on purpose -- handlers must read Permissions, which is already
	// the intersection with the creator's live rights; the raw ceiling is never
	// authority on its own. keyContent is the same for prompt content.
	APIKeyID       string
	keyPermissions []string
	keyContent     bool
	// tokenAuth marks a session authenticated by an OAuth access token on the MCP
	// endpoint. tokenContent is the same explicit grant as keyContent: the scope the
	// person consented to, not a property of their role. A key carries a flag chosen
	// at creation, a token carries a scope chosen at consent, and prompt text needs
	// one or the other on top of the role (product decision, 2026-09-17). Both are
	// unexported for the same reason as keyContent.
	tokenAuth    bool
	tokenContent bool
}

// pinned reports whether the credential is bound to the one organization it was
// resolved in. A browser session can switch organization and can read the tree it
// has rights over; a machine credential cannot -- an API key is pinned to the
// organization it was created in, and an access token to the one it landed on. The
// distinction governs both authorization (permissionsFor refuses another
// organization outright) and confidentiality (the reachable tree is not listed).
func (s *Session) pinned() bool { return s.APIKeyID != "" || s.tokenAuth }

// contentUnlocked reports whether this credential carries the second, explicit
// grant that prompt text requires on top of the role: the flag chosen when a key
// was created, the scope consented to when a token was issued. A browser session
// has no second lock to carry -- there the human's own role and the privacy policy
// are the whole answer.
func (s *Session) contentUnlocked() bool {
	if s.APIKeyID != "" {
		return s.keyContent
	}
	if s.tokenAuth {
		return s.tokenContent
	}
	return true
}

type apiHandler func(http.ResponseWriter, *http.Request, pgx.Tx, *Session) error
type apiError struct {
	status        int
	code, message string
}

func (e apiError) Error() string { return e.message }
func bad(message string) error   { return apiError{400, "invalid_request", message} }
func forbidden() error           { return apiError{403, "forbidden", "This operation is not permitted."} }
func (a *App) fail(w http.ResponseWriter, e error) {
	var ae apiError
	if errors.As(e, &ae) {
		reply(w, ae.status, map[string]string{"error": ae.code, "message": ae.message})
		return
	}
	a.log.Error("request failed", "error", e)
	reply(w, 500, map[string]string{"error": "internal_error", "message": "The operation could not be completed."})
}

// contain logs a panic recovered from background work and reports whether there
// was one; call it as a.contain(recover(), task) from a deferred function.
// Background goroutines have no net/http safety net: one malformed row or remote
// reply would otherwise stop the process and every other job with it. Only the
// task and the stack are logged -- a panic value can carry a destination URL or a
// credential, which never enter logs.
func (a *App) contain(v any, task string) bool {
	if v == nil {
		return false
	}
	a.log.Error("background task panicked", "task", task, "stack", string(debug.Stack()))
	return true
}
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return apiError{415, "unsupported_media_type", "Use application/json."}
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return bad("Invalid or oversized JSON body.")
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return bad("Exactly one JSON document is required.")
	}
	return nil
}
func randomToken() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func hash(v string) []byte   { h := sha256.Sum256([]byte(v)); return h[:] }
func equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func New(ctx context.Context, c Config, p *pgxpool.Pool, logger *slog.Logger) (*App, error) {
	if e := validateProcessRole(c.Role); e != nil {
		return nil, e
	}
	a := &App{config: c, db: p, log: logger, mux: http.NewServeMux()}
	if !c.ServesAPI() {
		if c.ProcessRole() == RoleMaintenance {
			if e := a.initBackgroundIdentity(); e != nil {
				return nil, e
			}
		}
		a.registerMetrics()
		return a, nil
	}
	if e := a.initOIDC(ctx); e != nil {
		return nil, e
	}
	a.registerMetrics()
	a.mux.HandleFunc("GET /auth/login", a.login)
	a.mux.HandleFunc("GET /auth/callback", a.callback)
	// logout destroys a cookie session, and profile is the human's identity
	// provider account: it needs s.Subject and calls Keycloak on every read, so a
	// key polling it would hammer the identity provider. Neither is a machine
	// operation. GET /api/session stays key-reachable as the discovery route
	// ("who am I, what may this key do").
	a.sessionOnly("POST "+logoutPath, "", a.logout)
	a.mux.HandleFunc("GET /api/bootstrap", a.bootstrap)
	a.registerSetupRoutes()
	a.registerLicenseRoutes()
	a.console("GET /api/session", "", a.session)
	a.sessionOnly("GET /api/profile", "", a.profile)
	a.sessionOnly("PUT /api/profile", "", a.putProfile)
	a.console("GET /api/overview", permOverviewRead, a.overview)
	a.console("GET /api/events", permEventsRead, a.events)
	a.console("GET /api/devices", permDevicesRead, a.devices)
	a.console("POST /api/enrollments", permDevicesManage, a.enrollment)
	a.console("POST /api/devices/{id}/approve", permDevicesManage, a.approve)
	a.console("POST /api/devices/{id}/revoke", permDevicesManage, a.revoke)
	// Deleting a device cascades through its whole history: session-only, fresh
	// second factor (see deleteDevice).
	a.sessionOnly("DELETE /api/devices/{id}", permDevicesManage, a.deleteDevice)
	a.console("GET /api/members", permMembersRead, a.members)
	a.console("GET /api/roles", permMembersRead, a.roles)
	a.console("POST /api/roles", permRolesManage, a.licensed(a.createRole))
	a.console("PUT /api/roles/{name}", permRolesManage, a.licensed(a.updateRole))
	a.console("DELETE /api/roles/{name}", permRolesManage, a.licensed(a.deleteRole))
	a.console("GET /api/roles/{name}/members", permRolesManage, a.roleMembers)
	// Without a licence, Community keeps its single owner account (license.go).
	a.console("POST /api/members/invitations", permMembersManage, a.licensed(a.invite))
	a.console("PUT /api/members/{id}/role", permMembersManage, a.licensed(a.changeMemberRole))
	a.console("PUT /api/members/{id}/language", permMembersManage, a.changeMemberLanguage)
	a.console("DELETE /api/members/{id}", permMembersManage, a.removeMember)
	a.console("GET /api/audit", permAuditRead, a.audits)
	a.console("GET /api/settings", "", a.settings)
	a.console("PUT /api/settings", permSettingsManage, a.putSettings)
	a.mux.HandleFunc("POST /v1/enroll", a.enroll)
	a.mux.HandleFunc("GET /v1/policy", a.devicePolicy)
	a.mux.HandleFunc("POST /v1/events", a.deviceFirst(a.ingest))
	a.registerAPIKeyRoutes()
	a.registerEditionRoutes()
	a.registerShadowRoutes()
	a.registerDeviceGroupRoutes()
	a.registerInstallerRoutes()
	a.registerDirectoryRoutes()
	a.registerSSORoutes()
	a.registerPrivacyRoutes()
	a.registerDetectionRoutes()
	a.registerPublisherRoutes()
	a.mux.HandleFunc("GET /ext/update.xml", a.extUpdate)
	a.mux.HandleFunc("GET /ext/milvago.crx", a.extCRX)
	a.mux.HandleFunc("GET /ext/updates.json", a.extFirefoxUpdate)
	a.mux.HandleFunc("GET /ext/milvago.xpi", a.extXPI)
	a.mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		reply(w, 404, map[string]string{"error": "not_found", "message": "API route is unavailable in this edition."})
	})
	a.mux.HandleFunc("/v1/", func(w http.ResponseWriter, r *http.Request) {
		reply(w, 404, map[string]string{"error": "not_found", "message": "Endpoint route not found."})
	})
	a.mux.HandleFunc("/", a.static)
	if c.ProcessRole() == RoleAll {
		if e := a.initializeInstance(ctx); e != nil {
			return nil, e
		}
	}
	return a, nil
}
func (a *App) Handler() http.Handler {
	a.registerMetrics()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		// Nothing here is meant to be embedded by another site, and the console uses
		// no device API: say so rather than leave both to browser defaults.
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if a.browserSecure() {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/auth/") || strings.HasPrefix(r.URL.Path, "/v1/") || strings.HasPrefix(r.URL.Path, "/v2/") || strings.HasPrefix(r.URL.Path, "/v3/") || r.URL.Path == mcpPath || isProbePath(r.URL.Path) || isMetricsPath(r.URL.Path) {
			w.Header().Set("Cache-Control", "no-store")
		}
		if a.config.DemoReadOnly && demoRefuses(r.Method, r.URL.Path) {
			reply(w, 403, map[string]string{"error": "demo_read_only", "message": "This demonstration instance is read-only."})
			return
		}
		// Enterprise never runs without a licence: before routing, like the
		// demonstration rule, so that no route can be registered around it; on the
		// route the mux will choose, so that no spelling of a path can differ from it.
		if Edition == "commercial" && a.config.ServesAPI() && a.licenseGatedRequest(r) {
			locked, e := a.licenseLocked(r.Context())
			if e != nil {
				a.log.Warn("licence status unavailable", "error", e)
				reply(w, 503, map[string]string{"error": "license_unavailable", "message": "The licence could not be checked; try again."})
				return
			}
			if locked {
				reply(w, 402, map[string]string{"error": "license_required", "message": "A valid licence is required."})
				return
			}
		}
		a.metrics.serve(a.mux, w, r)
	})
}

// demoRefuses reports whether a demonstration instance turns this request away.
// It runs before routing, so the refusal does not depend on any route having been
// registered with the right permission -- including a route added after this rule
// was written, which is the whole reason the check is not a list of paths.
//
// Device ingestion (/v1, /v2, /v3) is out of scope: it is how the demonstration
// data arrives, and it is authenticated by a device credential no visitor holds.
// Signing out stays possible: refusing it would leave a visitor's session open on
// a shared screen, which is the opposite of what the instance is protecting.
func demoRefuses(method, path string) bool {
	if method == "GET" || method == "HEAD" {
		return false
	}
	// Two exceptions, and both write only to the viewer's own session row.
	//
	// Signing out: refusing it would leave a visitor's session open on a shared
	// screen, the opposite of what the instance is protecting.
	//
	// Changing organization: on a multi-organization instance this is how a visitor
	// moves between them, and it is a mutation only in the narrowest sense -- it
	// re-points their own session and grants nothing, since effective_access is
	// resolved again on every request afterwards. Refusing it locked whoever signed in
	// inside whichever organization the sign-in happened to pick, with no way out.
	if method == "POST" && (path == logoutPath || path == "/api/session/organization") {
		return false
	}
	// The MCP endpoint, when the instance serves one. Its POST is an envelope, not a
	// mutation: the tool catalog admits GET console routes only, each carrying the
	// exact permission of its registration line, and mcp_commercial_test.go pins every
	// pair. Refusing it would close the endpoint on a demonstration that deliberately
	// publishes a read-only key (product decision, 2026-09-17) — and refusing it here,
	// before routing, would do so whatever the key was allowed to read.
	if method == "POST" && path == "/mcp" {
		return false
	}
	return strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/auth/") || path == mcpPath
}

func hasPermission(permissions []string, required string) bool {
	for _, p := range permissions {
		if p == required {
			return true
		}
	}
	return false
}

// intersect keeps only what both sets hold. It is how an API key narrows its
// creator's live rights: the key can subtract, never add.
func intersect(granted, ceiling []string) []string {
	kept := []string{}
	for _, p := range granted {
		if hasPermission(ceiling, p) {
			kept = append(kept, p)
		}
	}
	return kept
}

// allHeld reports whether every requested permission is present in held.
func allHeld(held, requested []string) bool {
	for _, p := range requested {
		if !hasPermission(held, p) {
			return false
		}
	}
	return true
}

// permissionsFor resolves the caller's effective permissions in org, already
// narrowed by the API key's own ceiling when the caller is a key.
//
// It also enforces the key's organization pinning. The hierarchy re-checks that
// let a parent act on a descendant resolve effective_access() against the target
// organization, which for a key would reach an organization its creator never
// scoped it to -- so a key is refused any organization but its own, even when its
// creator holds rights over the target.
func (a *App) permissionsFor(ctx context.Context, tx pgx.Tx, s *Session, org string) ([]string, error) {
	if s.pinned() && org != s.OrganizationID {
		return nil, forbidden()
	}
	var perms []string
	if tx.QueryRow(ctx, `SELECT permissions FROM effective_access($1,$2)`, s.UserID, org).Scan(&perms) != nil {
		return nil, forbidden()
	}
	if s.APIKeyID != "" {
		perms = intersect(perms, s.keyPermissions)
	}
	// Acting on another organization by its identifier answers to that organization's
	// MFA requirement, as switching into it does: a parent signed in without a second
	// factor could otherwise delete, rename or re-key a child that requires one
	// (audit of 2026-09-24). A pinned credential never gets here for another org.
	if org != s.OrganizationID && !s.MFA {
		required, e := organizationRequiresMFA(ctx, tx, org)
		if e != nil {
			return nil, e
		}
		if required {
			return nil, apiError{403, "mfa_required", "The target organization requires multi-factor authentication."}
		}
	}
	return perms, nil
}

// organizationRequiresMFA reads another organization's MFA setting under its own
// tenant context and puts the caller's context back. A missing settings row is
// misconfiguration, never permission (see switchOrganization).
func organizationRequiresMFA(ctx context.Context, tx pgx.Tx, org string) (required bool, err error) {
	var current string
	if err = tx.QueryRow(ctx, `SELECT coalesce(current_setting('milvago.organization_id',true),'')`).Scan(&current); err != nil {
		return
	}
	if _, err = tx.Exec(ctx, sqlSetOrganizationContext, org); err != nil {
		return
	}
	defer func() {
		if _, restore := tx.Exec(ctx, sqlSetOrganizationContext, current); err == nil {
			err = restore
		}
	}()
	err = tx.QueryRow(ctx, `SELECT coalesce((SELECT require_mfa FROM settings WHERE organization_id=$1), true)`, org).Scan(&required)
	return
}

// mcpPath is the single MCP endpoint. It is declared here, in the shared file,
// because Handler() has to keep its responses out of every cache in both
// editions -- the endpoint itself exists only in Enterprise.
const mcpPath = "/mcp"

// credentialMode is which credential a route accepts. There is no permissive
// default: every registrar names one, so the choice is visible in review on the
// registration line itself.
type credentialMode int

const (
	accessBoth credentialMode = iota
	accessSession
	accessKey
)

// console registers a route reachable both by a browser session and by a bearer
// API key.
func (a *App) console(pattern, permission string, h apiHandler) {
	a.register(pattern, permission, h, accessBoth)
}

// sessionOnly registers a route a browser session may reach and an API key may
// not. It is an explicit registrar rather than a denylist of paths on purpose: a
// denylist is fail-open, so a route added later would silently become reachable
// by every key, whereas here the author of a new route has to choose, and a wrong
// choice is visible in review on the registration line itself.
func (a *App) sessionOnly(pattern, permission string, h apiHandler) {
	a.register(pattern, permission, h, accessSession)
}

func (a *App) register(pattern, permission string, h apiHandler, mode credentialMode) {
	a.routes = append(a.routes, registeredRoute{pattern, permission, mode})
	a.mux.HandleFunc(pattern, a.handler(permission, h, mode))
}

// handler builds the authentication and authorization chain for one route. It is
// separate from register so a caller that must run a check before any database
// access -- the MCP endpoint validates Origin first -- can wrap the chain
// instead of reimplementing it.
// routeCredential chooses one credential before any database access. An explicit
// bearer header cannot fall back to an ambient browser cookie.
func (a *App) routeCredential(w http.ResponseWriter, r *http.Request, mode credentialMode) (pgx.Tx, *Session, error) {
	if r.Header.Get("Authorization") != "" {
		if mode == accessSession {
			return nil, nil, apiError{403, "session_required", "This operation requires an interactive console session."}
		}
		return a.bearerTx(r, mode)
	}
	if mode == accessKey {
		w.Header().Set("WWW-Authenticate", a.bearerChallenge(r))
		return nil, nil, apiKeyUnauthorized()
	}
	if _, err := a.currentOIDC(r.Context()); err != nil {
		return nil, nil, err
	}
	c, e := r.Cookie(a.cookieName("session"))
	if e != nil {
		return nil, nil, apiError{401, "unauthenticated", "Sign in to continue."}
	}
	// SameSite=Lax attaches cookies on some cross-site GET navigations.
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return nil, nil, apiError{403, "csrf_failed", "The request origin or CSRF token is invalid."}
	}
	return a.cookieRouteTx(r, c.Value)
}

func (a *App) cookieRouteTx(r *http.Request, opaque string) (pgx.Tx, *Session, error) {
	s, e := a.loadSession(r, opaque)
	if e != nil {
		return nil, nil, e
	}
	// Signing out always succeeds even when the ordinary request budget is spent.
	budget := "person " + s.UserID
	if a.config.DemoReadOnly {
		budget = "session " + hex.EncodeToString(s.TokenHash)
	}
	if r.URL.Path != logoutPath {
		if e = a.checkIngestRate(r.Context(), budget, apiKeyBudget); e != nil {
			return nil, nil, e
		}
	}
	// Permission for a large catalogue body is checked before reserving memory.
	if r.URL.Path == "/api/detection/catalog/import" {
		var may bool
		if e = a.db.QueryRow(r.Context(), "SELECT coalesce((SELECT $3=ANY(permissions) FROM effective_access($1,$2)),false)", s.UserID, s.OrganizationID, permPolicyManage).Scan(&may); e != nil {
			return nil, nil, e
		}
		if !may {
			return nil, nil, forbidden()
		}
	}
	if e = a.readBody(r, budget); e != nil {
		return nil, nil, e
	}
	tx, e := tenantTx(r.Context(), a.db, s.OrganizationID)
	return tx, s, e
}

func (a *App) authorizeConsoleRequest(r *http.Request, tx pgx.Tx, s *Session, permission string) (*http.Request, error) {
	// Authority is resolved only after the privacy and permission barrier.
	r, e := a.privacyRequest(r, tx, s)
	if e != nil {
		return r, e
	}
	if tx.QueryRow(r.Context(), "SELECT role,permissions FROM effective_access($1,$2)", s.UserID, s.OrganizationID).Scan(&s.Role, &s.Permissions) != nil {
		return r, forbidden()
	}
	// A key's current authority is the intersection with its declared ceiling.
	if s.APIKeyID != "" {
		s.Permissions = intersect(s.Permissions, s.keyPermissions)
	}
	if permission != "" && !hasPermission(s.Permissions, permission) {
		return r, forbidden()
	}
	var requireMFA bool
	if e = tx.QueryRow(r.Context(), "SELECT require_mfa FROM settings WHERE organization_id=$1", s.OrganizationID).Scan(&requireMFA); e != nil {
		return r, e
	}
	// A bearer key cannot supply MFA evidence; its creation required a session.
	if requireMFA && s.APIKeyID == "" && !s.MFA && r.URL.Path != logoutPath {
		return r, apiError{403, "mfa_required", "Sign in with multi-factor authentication."}
	}
	return r, nil
}

func (a *App) handler(permission string, h apiHandler, mode credentialMode) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// A body reservation remains held until the request has ended.
		hold := &bodyHold{}
		defer hold.release()
		r = r.WithContext(context.WithValue(context.WithValue(r.Context(), routePermissionKey{}, permission), bodyHoldKey{}, hold))
		tx, s, e := a.routeCredential(w, r, mode)
		if e != nil {
			a.fail(w, e)
			return
		}
		defer tx.Rollback(r.Context())
		r, e = a.authorizeConsoleRequest(r, tx, s, permission)
		if e != nil {
			a.fail(w, e)
			return
		}

		// Handlers write only after successful commit for mutations. The response is
		// held until the transaction has ended, so the barrier is released before the
		// client reads it: a slow reader otherwise kept its organizations' barriers --
		// the root's for every request -- for as long as the write timeout (audit of
		// 2026-09-24). A response that outgrows the buffer streams; a read's
		// transaction is ended first, so it never streams under the barrier.
		held := &heldWriter{ResponseWriter: w}
		// A panic skips finish: its reservation is returned, its partial body dropped.
		defer func() {
			if !held.through {
				heldBytes.Add(-held.reserved)
			}
		}()
		// Reads: GET and HEAD, and MCP, which serves read tools only and commits their
		// audit inside the handler.
		if r.Method == "GET" || r.Method == "HEAD" || r.URL.Path == mcpPath {
			held.end = func() { tx.Rollback(r.Context()) }
		}
		if e := h(held, r, tx, s); e != nil {
			a.fail(held, e)
		}
		tx.Rollback(r.Context())
		held.finish()
	}
}

// readBody reads a change's body once its sender is authenticated and before its
// transaction opens (audit of 2026-09-24): read inside it, a client trickling the body
// held a pool connection and its organizations' barriers -- the root's among them --
// for the whole read timeout; read before authentication, anyone could make the server
// buffer it. It takes one byte past the route's ceiling at most (128 KiB, 1.5 MiB for
// the catalogue import), so the route still refuses the excess with its own error.
// Every body is reserved against readTotal before it is read: read outside the
// transaction, bodies are no longer bounded by the database pool, and an authenticated
// client could otherwise trickle hundreds of them at once.
// principal is the budget key of the sender: at most bodiesPerPrincipal of its bodies
// are in flight, so one person cannot fill readTotal by trickling (audit of 2026-09-24).
func (a *App) readBody(r *http.Request, principal string) error {
	if r.Method == "GET" || r.Method == "HEAD" || r.Body == nil {
		return nil
	}
	// Signing out reads nothing, and its budget is never refused.
	if r.URL.Path == logoutPath {
		r.Body = http.NoBody
		return nil
	}
	limit := int64(128 << 10)
	if r.URL.Path == "/api/detection/catalog/import" {
		limit = 1536 << 10
	}
	// The public demonstration writes nothing and shares one account between every
	// visitor, each with a session: its bodies are small ones (organization switch).
	if a.config.DemoReadOnly {
		limit = 8 << 10
	}
	if !bodiesInFlight.acquire(principal, bodiesPerPrincipal) {
		return rateLimited()
	}
	hold, scoped := r.Context().Value(bodyHoldKey{}).(*bodyHold)
	if !scoped {
		defer bodiesInFlight.release(principal)
	}
	if readBytes.Add(limit+1) > readTotal {
		readBytes.Add(-(limit + 1))
		if scoped {
			bodiesInFlight.release(principal)
		}
		return apiError{503, "busy", "The server is busy. Retry shortly."}
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, limit+1))
	readBytes.Add(int64(len(raw)) - (limit + 1))
	if e != nil || !scoped {
		// Unreadable, or no request scope to return it at: returned now.
		readBytes.Add(-int64(len(raw)))
		if scoped {
			bodiesInFlight.release(principal)
		}
		if e != nil {
			return bad("The request body could not be read.")
		}
	} else {
		hold.reserved += int64(len(raw))
		hold.principals = append(hold.principals, principal)
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	return nil
}

const bodiesPerPrincipal = 4

var bodiesInFlight = &orgSlots{held: map[string]int{}}

const readTotal = 64 << 20

var readBytes atomic.Int64

type bodyHoldKey struct{}

// bodyHold carries the reservation of the body readBody read for one request.
type bodyHold struct {
	reserved   int64
	principals []string
}

func (h *bodyHold) release() {
	readBytes.Add(-h.reserved)
	h.reserved = 0
	for _, p := range h.principals {
		bodiesInFlight.release(p)
	}
	h.principals = nil
}

// heldLimit bounds one held response; heldTotal all of them at once. The database
// pool no longer bounds how many responses are waiting on their clients, so the
// buffers are: past either ceiling a response writes through.
const (
	heldLimit = 8 << 20
	heldTotal = 128 << 20
)

var heldBytes atomic.Int64

// heldWriter buffers a response until finish, or until it outgrows its ceilings or is
// flushed, after which it writes through.
type heldWriter struct {
	http.ResponseWriter
	end      func()
	body     bytes.Buffer
	reserved int64
	status   int
	through  bool
}

func (h *heldWriter) WriteHeader(status int) {
	if h.through {
		h.ResponseWriter.WriteHeader(status)
	} else if h.status == 0 {
		h.status = status
	}
}

func (h *heldWriter) Write(p []byte) (int, error) {
	if !h.through {
		n := int64(len(p))
		if int64(h.body.Len())+n > heldLimit || heldBytes.Add(n) > heldTotal {
			if int64(h.body.Len())+n <= heldLimit {
				heldBytes.Add(-n)
			}
			h.release()
		} else {
			h.reserved += n
		}
	}
	if h.through {
		return h.ResponseWriter.Write(p)
	}
	return h.body.Write(p)
}

func (h *heldWriter) Flush() {
	h.release()
	if f, ok := h.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (h *heldWriter) Unwrap() http.ResponseWriter { return h.ResponseWriter }

func (h *heldWriter) release() {
	if h.through {
		return
	}
	if h.end != nil {
		h.end()
	}
	h.through = true
	if h.status != 0 {
		h.ResponseWriter.WriteHeader(h.status)
	}
	if h.body.Len() > 0 {
		_, _ = h.ResponseWriter.Write(h.body.Bytes())
	}
	h.body = bytes.Buffer{}
	heldBytes.Add(-h.reserved)
	h.reserved = 0
}

func (h *heldWriter) finish() { h.release() }
func (a *App) static(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "HEAD" {
		http.NotFound(w, r)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/")
	if name != "" && (strings.Contains(name, "\\") || !fs.ValidPath(name) || !filepath.IsLocal(filepath.FromSlash(name))) {
		http.NotFound(w, r)
		return
	}
	root, err := os.OpenRoot(a.config.StaticDir)
	if err != nil {
		http.Error(w, "Static files unavailable", http.StatusInternalServerError)
		return
	}
	defer root.Close()
	if name != "" {
		file, openErr := root.Open(name)
		if openErr == nil {
			info, statErr := file.Stat()
			if statErr == nil && !info.IsDir() {
				defer file.Close()
				http.ServeContent(w, r, name, info.ModTime(), file)
				return
			}
			_ = file.Close()
		}
	}
	// The application shell names the current hashed bundle, so it must never be
	// served from a browser's heuristic cache: without an explicit directive a
	// stale index.html keeps loading a retired bundle after a redeployment.
	w.Header().Set("Cache-Control", "no-store")
	index, err := root.Open("index.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer index.Close()
	info, err := index.Stat()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	http.ServeContent(w, r, "index.html", info.ModTime(), index)
}
