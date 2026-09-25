package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jackc/pgx/v5"
)

// Instance licences (product decisions of 2026-09-24).
//
// A licence is a JWT signed with Ed25519 by the vendor's licensing service
// (licensing/). It is bound to one instance -- publisher_client_state.instance_id --
// and is either free ("community", requested through the vendor's webhook,
// perpetual) or "enterprise" (issued by the vendor, with an expiry and a device
// quota, 0 meaning unlimited).
//
// Community runs without one, restricted: five devices, the single owner account,
// no role management, no directory, no SSO. Enterprise never runs without one: past
// expiry it keeps working ten days, then every console and device route answers 402
// except what is needed to enter a new licence.
//
// The public key is compiled in and never configurable: an operator able to set it
// could sign licences of their own.

const (
	licenseIssuer        = "milvago.ai"
	licenseGrace         = 10 * 24 * time.Hour
	licenseMaxLength     = 4096
	communityDeviceLimit = 5
	// Serializes enrollments instance-wide while the device quota is counted.
	deviceQuotaLockKey = 7069206
)

// Package variables, not constants, so that tests substitute their own key, webhook
// and licence; nothing outside tests assigns them.
var (
	// Public half of the licence signing key (Ed25519).
	licensePublicKey  = mustLicenseKey("cMlHShs1ohApYn2dtasMG3jfU2MmAaOj3C7JdWk2TX8=")
	licenseRequestURL = "https://dodo.milvago.ai/webhook/giveanopensourcelicence"
	// licenseTestGrant, when set, stands for a valid licence of every instance. Only
	// TestMain sets it, so that suites written before licences keep testing what they
	// test; the licence tests clear it.
	licenseTestGrant *licenseClaims
)

func mustLicenseKey(encoded string) ed25519.PublicKey {
	raw, e := base64.StdEncoding.DecodeString(encoded)
	if e != nil || len(raw) != ed25519.PublicKeySize {
		// Placeholder or corrupted: no licence verifies, which is the safe failure.
		return nil
	}
	return ed25519.PublicKey(raw)
}

type licenseClaims struct {
	jwt.Claims
	Kind       string `json:"kind"`
	Instance   string `json:"instance"`
	MaxDevices *int   `json:"max_devices,omitempty"`
}

var (
	errLicenseInvalid    = apiError{400, "license_invalid", "This licence is not valid for this instance."}
	errLicenseCommunity  = apiError{400, "license_community_on_enterprise", "A free licence does not activate the Enterprise edition."}
	errLicenseMissing    = apiError{400, "license_required", "This edition requires a licence."}
	errLicenseRestricted = apiError{403, "license_restricted", "This feature requires a licence."}
)

// verifyLicense accepts only an EdDSA signature by the compiled-in key, for this
// instance, of a kind this edition admits. Expiry is not judged here: an expired
// licence is still this instance's licence, and its state says what it allows.
func verifyLicense(raw, instance string) (*licenseClaims, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > licenseMaxLength || len(licensePublicKey) != ed25519.PublicKeySize || instance == "" {
		return nil, errLicenseInvalid
	}
	token, e := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.EdDSA})
	if e != nil {
		return nil, errLicenseInvalid
	}
	var c licenseClaims
	if e = token.Claims(licensePublicKey, &c); e != nil {
		return nil, errLicenseInvalid
	}
	if c.Issuer != licenseIssuer || !equal(c.Instance, instance) || c.ID == "" {
		return nil, errLicenseInvalid
	}
	switch c.Kind {
	case "community":
	case "enterprise":
		if c.Expiry == nil || c.MaxDevices == nil || *c.MaxDevices < 0 {
			return nil, errLicenseInvalid
		}
	default:
		return nil, errLicenseInvalid
	}
	if Edition == "commercial" && c.Kind != "enterprise" {
		return nil, errLicenseCommunity
	}
	return &c, nil
}

// licenseStatus is what the stored licence allows now. It is recomputed on every
// call from a fresh read, so a licence entered on one replica applies to all of them
// at once; only the signature check is memoized.
type licenseStatus struct {
	State      string     `json:"state"` // none, valid, grace or expired
	Kind       string     `json:"kind,omitempty"`
	MaxDevices int        `json:"max_devices"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	GraceUntil *time.Time `json:"grace_until,omitempty"`
	Instance   string     `json:"instance_id"`
	Restricted bool       `json:"restricted"`
	Locked     bool       `json:"locked"`
}

func statusOf(c *licenseClaims, instance string, now time.Time) licenseStatus {
	s := licenseStatus{State: "none", Instance: instance}
	if c != nil {
		s.State, s.Kind = "valid", c.Kind
		if c.MaxDevices != nil {
			s.MaxDevices = *c.MaxDevices
		}
		if c.Expiry != nil {
			expires, grace := c.Expiry.Time().UTC(), c.Expiry.Time().UTC().Add(licenseGrace)
			s.ExpiresAt, s.GraceUntil = &expires, &grace
			switch {
			case !now.After(expires):
			case !now.After(grace):
				s.State = "grace"
			default:
				s.State = "expired"
			}
		}
	}
	usable := s.State == "valid" || s.State == "grace"
	s.Restricted = Edition == "community" && !usable
	s.Locked = Edition == "commercial" && !usable
	return s
}

// deviceLimit is the number of devices the instance may hold, 0 meaning unlimited.
func (s licenseStatus) deviceLimit() int {
	if s.Restricted {
		return communityDeviceLimit
	}
	if s.Kind == "enterprise" {
		return s.MaxDevices
	}
	return 0
}

type licenseMemo struct {
	mu            sync.Mutex
	raw, instance string
	claims        *licenseClaims
	// loaded is when the stored licence was last read; the 402 gate reuses that read
	// for licenseGateTTL rather than adding a query to every device request.
	loaded     time.Time
	refreshing bool
}

// ponytail: another replica sees a newly entered licence up to this late at the gate;
// handlers that read the licence themselves are never late.
const licenseGateTTL = 30 * time.Second

// licenseStatus reads the stored licence now. Handlers use it; the gate uses
// licenseLocked.
func (a *App) licenseStatus(ctx context.Context) (licenseStatus, error) {
	var raw, instance string
	if e := a.db.QueryRow(ctx, `SELECT c.license,p.instance_id FROM app_config c CROSS JOIN publisher_client_state p`).Scan(&raw, &instance); e != nil {
		return licenseStatus{}, e
	}
	if licenseTestGrant != nil {
		return statusOf(licenseTestGrant, instance, time.Now()), nil
	}
	m := &a.license
	m.mu.Lock()
	defer m.mu.Unlock()
	if raw != m.raw || instance != m.instance || m.loaded.IsZero() {
		// A stored licence that no longer verifies (another key, another instance
		// after a database copy) counts as none.
		m.raw, m.instance, m.claims = raw, instance, nil
		if raw != "" {
			m.claims, _ = verifyLicense(raw, instance)
		}
	}
	m.loaded, m.refreshing = time.Now(), false
	return statusOf(m.claims, instance, time.Now()), nil
}

// licenseLocked answers the gate from the last read while it is recent, and
// while another request is refreshing it, so that a slow or saturated database
// delays one request per interval instead of every one. With nothing read yet
// and the database unavailable, it fails closed.
func (a *App) licenseLocked(ctx context.Context) (bool, error) {
	if licenseTestGrant != nil {
		return false, nil
	}
	m := &a.license
	m.mu.Lock()
	known := !m.loaded.IsZero()
	if known && (time.Since(m.loaded) < licenseGateTTL || m.refreshing) {
		s := statusOf(m.claims, m.instance, time.Now())
		m.mu.Unlock()
		return s.Locked, nil
	}
	m.refreshing = true
	m.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	s, e := a.licenseStatus(ctx)
	if e == nil {
		return s.Locked, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshing = false
	if known {
		return statusOf(m.claims, m.instance, time.Now()).Locked, nil
	}
	return true, e
}

// forgetLicense makes the gate read the licence again at the next request.
func (a *App) forgetLicense() {
	a.license.mu.Lock()
	a.license.loaded = time.Time{}
	a.license.mu.Unlock()
}

// licenseGated reports whether a locked Enterprise instance refuses a request that
// the mux routes to pattern: every console and device route, except those that let
// an owner sign in and enter a licence. It judges the route the mux chose, never the
// path: the mux unescapes each segment (%61pi is api, ..%2F stays inside a wildcard)
// where path.Clean of the decoded path resolves it, and the two disagreed
// (/api/roles/..%2F..%2F..%2Fx/members reached a gated handler, 2026-09-24).
func licenseGated(pattern string) bool {
	switch pattern {
	case "GET /api/session", "POST /api/session/organization", "PUT /api/license", "GET /api/bootstrap", "GET /api/setup":
		return false
	}
	p := pattern[strings.IndexByte(pattern, ' ')+1:]
	if strings.HasPrefix(p, "/api/setup/") {
		return false
	}
	// /auth/device binds a device's user: a device route, unlike sign-in.
	for _, prefix := range []string{"/api", "/v1", "/v2", "/v3", "/ext", mcpPath, "/auth/device"} {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}

func (a *App) licenseGatedRequest(r *http.Request) bool {
	_, pattern := a.mux.Handler(r)
	return licenseGated(pattern)
}

// licensed wraps a route that a restricted Community instance does not offer.
func (a *App) licensed(h apiHandler) apiHandler {
	return func(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
		l, e := a.licenseStatus(r.Context())
		if e != nil {
			return e
		}
		if l.Restricted {
			return errLicenseRestricted
		}
		return h(w, r, tx, s)
	}
}

// checkDeviceQuota refuses a new device once the licence's quota is reached. It
// counts every organization's devices, revoked ones excepted, under an instance-wide
// lock so that concurrent enrollments cannot both take the last place. tx is the
// tenant transaction of org, whose context it restores.
func (a *App) checkDeviceQuota(ctx context.Context, tx pgx.Tx, org string) error {
	l, e := a.licenseStatus(ctx)
	if e != nil {
		return e
	}
	limit := l.deviceLimit()
	if limit == 0 {
		return nil
	}
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, deviceQuotaLockKey); e != nil {
		return e
	}
	rows, e := tx.Query(ctx, `SELECT id FROM organizations`)
	if e != nil {
		return e
	}
	orgs, e := pgx.CollectRows(rows, pgx.RowTo[string])
	if e != nil {
		return e
	}
	total := 0
	for _, o := range orgs {
		var n int
		if _, e = tx.Exec(ctx, sqlSetOrganizationContext, o); e != nil {
			return e
		}
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM devices WHERE status<>'revoked'`).Scan(&n); e != nil {
			return e
		}
		total += n
	}
	if _, e = tx.Exec(ctx, sqlSetOrganizationContext, org); e != nil {
		return e
	}
	if total >= limit {
		return apiError{409, "device_limit_reached", "The licence's device limit has been reached."}
	}
	return nil
}

func (a *App) registerLicenseRoutes() {
	a.sessionOnly("PUT /api/license", permSettingsManage, a.putLicense)
	a.sessionOnly("POST /api/license/request", permSettingsManage, a.requestLicense)
	a.mux.HandleFunc("POST /api/setup/license-request", a.setupLicenseRequest)
}

// putLicense is an instance-level change, like the public URL: the root
// organization's owner, in an interactive session.
func (a *App) putLicense(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if !isInstanceOwner(r.Context(), tx, s) {
		return forbidden()
	}
	var body struct {
		License string `json:"license"`
	}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	var instance string
	if e := tx.QueryRow(r.Context(), `SELECT instance_id FROM publisher_client_state`).Scan(&instance); e != nil {
		return e
	}
	c, e := verifyLicense(body.License, instance)
	if e != nil {
		return e
	}
	if _, e = tx.Exec(r.Context(), `UPDATE app_config SET license=$1`, strings.TrimSpace(body.License)); e != nil {
		return e
	}
	if e = audit(r.Context(), tx, s.OrganizationID, s.UserID, "license.updated", c.ID); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	a.forgetLicense()
	reply(w, 200, statusOf(c, instance, time.Now()))
	return nil
}

func (a *App) requestLicense(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if !isInstanceOwner(r.Context(), tx, s) {
		return forbidden()
	}
	if e := a.checkPublicRequest(r, "license-request", 3, 30); e != nil {
		return e
	}
	return a.forwardLicenseRequest(w, r)
}

func (a *App) setupLicenseRequest(w http.ResponseWriter, r *http.Request) {
	if !a.setupGuard(w, r, "setup-license") {
		return
	}
	if e := a.forwardLicenseRequest(w, r); e != nil {
		a.fail(w, e)
	}
}

// forwardLicenseRequest asks the vendor's webhook to e-mail a free licence for this
// instance. The destination is fixed: nothing in the request chooses where it goes.
func (a *App) forwardLicenseRequest(w http.ResponseWriter, r *http.Request) error {
	if Edition != "community" {
		return errSetupClosed
	}
	var body struct {
		Email string `json:"email"`
	}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	email, ok := plainAddress(body.Email)
	if !ok {
		return bad("Enter a valid e-mail address.")
	}
	var instance string
	if e := a.db.QueryRow(r.Context(), `SELECT instance_id FROM publisher_client_state`).Scan(&instance); e != nil {
		return e
	}
	payload, _ := json.Marshal(map[string]string{"email": email, "instance": instance})
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	request, e := http.NewRequestWithContext(ctx, "POST", licenseRequestURL, bytes.NewReader(payload))
	if e != nil {
		return e
	}
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, e := client.Do(request)
	if e != nil {
		return apiError{502, "license_request_failed", "The licence request could not be sent."}
	}
	response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return apiError{502, "license_request_failed", "The licence request could not be sent."}
	}
	reply(w, 202, map[string]bool{"requested": true})
	return nil
}

// setupLicense checks the licence chosen in the wizard: required in Enterprise,
// optional in Community.
func setupLicense(ctx context.Context, tx pgx.Tx, raw string) error {
	if strings.TrimSpace(raw) == "" {
		if Edition == "commercial" && licenseTestGrant == nil {
			return errLicenseMissing
		}
		return nil
	}
	var instance string
	if e := tx.QueryRow(ctx, `SELECT instance_id FROM publisher_client_state`).Scan(&instance); e != nil {
		return e
	}
	if _, e := verifyLicense(raw, instance); e != nil {
		return e
	}
	_, e := tx.Exec(ctx, `UPDATE app_config SET license=$1`, strings.TrimSpace(raw))
	return e
}
