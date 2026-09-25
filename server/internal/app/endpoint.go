package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
)

const (
	msgDeviceCredentialRequired = "An approved device credential is required."
)

func (a *App) enroll(w http.ResponseWriter, r *http.Request) {
	if e := a.enrollRequest(w, r); e != nil {
		a.fail(w, e)
	}
}
func (a *App) enrollRequest(w http.ResponseWriter, r *http.Request) error {
	if err := a.checkPublicRequest(r, "install", 300, 1200); err != nil {
		return err
	}
	var body struct {
		Token          string          `json:"token"`
		Hostname       string          `json:"hostname"`
		Platform       string          `json:"platform"`
		Version        string          `json:"version"`
		Kind           string          `json:"kind"`
		Capabilities   []string        `json:"capabilities"`
		MachineDomains []machineDomain `json:"machine_domains"`
	}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	if len(body.Token) != 43 || !validMetadata(body.Hostname, 120) || !validMetadata(body.Platform, 40) || !validMetadata(body.Version, 40) {
		return bad("Invalid enrollment metadata.")
	}
	if body.Kind == "" {
		body.Kind = "browser"
	}
	if (body.Kind != "browser" && body.Kind != "native") || (Edition == "community" && body.Kind != "browser") || len(body.Capabilities) > 50 {
		return bad("Invalid endpoint composition or capabilities.")
	}
	if !validMachineDomains(body.MachineDomains) {
		return bad("Invalid machine domains.")
	}
	if body.Capabilities == nil {
		body.Capabilities = []string{}
	}
	for _, c := range body.Capabilities {
		if !categoryPattern.MatchString(c) {
			return bad("Invalid capability identifier.")
		}
	}
	var org string
	if e := a.db.QueryRow(r.Context(), `SELECT organization_id FROM enrollment_identity($1)`, hash(body.Token)).Scan(&org); e != nil {
		return apiError{401, "invalid_enrollment", "Enrollment token is invalid, expired or consumed."}
	}
	tx, e := tenantTx(r.Context(), a.db, org)
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	var enrollmentID string
	e = tx.QueryRow(r.Context(), `UPDATE enrollments SET consumed_at=now() WHERE token_hash=$1 AND consumed_at IS NULL AND expires_at>now() RETURNING id`, hash(body.Token)).Scan(&enrollmentID)
	if e == pgx.ErrNoRows {
		return apiError{401, "invalid_enrollment", "Enrollment token is invalid, expired or consumed."}
	}
	if e != nil {
		return e
	}
	if e = a.checkDeviceQuota(r.Context(), tx, org); e != nil {
		return e
	}
	credential := randomToken()
	var id string
	status, e := a.approvalStatus(r, tx, org, body.MachineDomains)
	if e != nil {
		return e
	}
	caps, _ := json.Marshal(body.Capabilities)
	domains := machineDomainsJSON(body.MachineDomains)
	e = tx.QueryRow(r.Context(), `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,kind,capabilities,status,machine_domains) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`, org, hash(credential), body.Hostname, body.Platform, body.Version, body.Kind, caps, status, domains).Scan(&id)
	if e == nil {
		e = a.storeDeviceName(r.Context(), tx, org, id, body.Hostname)
	}
	if e != nil {
		return e
	}
	if e = audit(r.Context(), tx, org, "device:"+id, "device.enroll", enrollmentID); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 201, map[string]string{"device_id": id, "credential": credential})
	return nil
}
func validMetadata(s string, max int) bool {
	if len(s) < 1 || len(s) > max || strings.TrimSpace(s) != s {
		return false
	}
	// Control and format characters (C1, bidi overrides, U+2028) are refused as well:
	// a device could otherwise take a hostname that renders as another machine's.
	for _, c := range s {
		if unicode.IsControl(c) || unicode.Is(unicode.Bidi_Control, c) || c == '\u2028' || c == '\u2029' {
			return false
		}
	}
	return true
}

// deviceIdentified is a device credential already checked for this request.
type deviceIdentified struct {
	org, id, route string
	digest         []byte
}

type deviceIdentityKey struct{}

// deviceFirst identifies the device before the handler decodes its body: decoded
// first, an anonymous 128 KiB body of empty events allocated some two hundred times
// its size, on every device route that takes one (audit of 2026-09-24).
func (a *App) deviceFirst(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d, e := a.identifyDevice(r)
		if e != nil {
			a.fail(w, e)
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), deviceIdentityKey{}, d)))
	}
}

// identifyDevice checks the credential's shape, the public budget, the device and its
// per-route budget, with no transaction held.
func (a *App) identifyDevice(r *http.Request) (deviceIdentified, error) {
	if d, ok := r.Context().Value(deviceIdentityKey{}).(deviceIdentified); ok {
		return d, nil
	}
	var d deviceIdentified
	bearer := r.Header.Get("Authorization")
	if !strings.HasPrefix(bearer, "Bearer ") || len(bearer) != 50 {
		return d, apiError{401, "device_unauthorized", msgDeviceCredentialRequired}
	}
	if err := a.checkPublicRequest(r, "device-auth", 6000, 60000); err != nil {
		return d, err
	}
	d.digest = hash(strings.TrimPrefix(bearer, "Bearer "))
	// A live pgx pool can keep retrying connections during a database outage.
	// Bound admission independently of the collector HTTP timeout.
	lookup, cancelLookup := context.WithTimeout(r.Context(), 2*time.Second)
	identityError := a.db.QueryRow(lookup, `SELECT organization_id,device_id FROM device_identity($1)`, d.digest).Scan(&d.org, &d.id)
	cancelLookup()
	if e := identityError; e != nil {
		// Database outages must not revoke the agent's cached authorization.
		if !errors.Is(e, pgx.ErrNoRows) {
			if a.log != nil {
				a.log.Warn("device identity lookup unavailable")
			}
			return d, apiError{503, "device_identity_unavailable", "Device authorization is temporarily unavailable."}
		}
		return d, apiError{401, "device_unauthorized", msgDeviceCredentialRequired}
	}
	// Checked once the device is identified, so the budget cannot be escaped by
	// presenting a different credential, and before the transaction and the row
	// lock, which are what a flood would actually cost.
	route := r.URL.Path
	if route == "/v1/events" {
		route = "/v2/events"
	}
	if route == "/v1/policy" || route == "/v2/policy" {
		route = "/v3/policy"
	}
	// The artifact path carries the release digest, so the budget map could never
	// match it as-is; every digest shares the one artifact budget.
	if strings.HasPrefix(route, "/v2/update/artifact/") {
		route = "/v2/update/artifact"
	}
	if budget, bounded := deviceBudget[route]; bounded {
		if err := a.checkIngestRate(r.Context(), d.id+" "+route, budget); err != nil {
			return d, err
		}
	}
	d.route = route
	return d, nil
}

func (a *App) deviceTx(r *http.Request) (pgx.Tx, string, string, error) {
	d, e := a.identifyDevice(r)
	if e != nil {
		return nil, "", "", e
	}
	org, id, digest, route := d.org, d.id, d.digest, d.route
	var tx pgx.Tx
	if route == "/v2/events" {
		tx, e = a.eventTransaction(r.Context(), org)
	} else {
		tx, e = tenantTx(r.Context(), a.db, org)
	}
	if e != nil {
		return nil, "", "", e
	}
	// Lock status through request commit: a concurrent revocation cannot race ingestion.
	// Match the console writers' lock order BEFORE holding the device row. The
	// entire event batch uses one coherent privacy and collection configuration.
	// Every other device route takes the policy barrier before the row too: inventory,
	// enforcement and the v1 events read the policy under it after locking the row,
	// which deadlocked with a group move or deletion (audit of 2026-09-24).
	// Event batches read the privacy policy of the device's organization chain first.
	if route == "/v2/events" {
		if e = sharedBarrier(r.Context(), tx, org, true); e != nil {
			tx.Rollback(r.Context())
			return nil, "", "", e
		}
	}
	if _, e = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock_shared(7069202)`); e != nil {
		tx.Rollback(r.Context())
		return nil, "", "", e
	}
	var status string
	e = tx.QueryRow(r.Context(), `SELECT status FROM devices WHERE id=$1 AND credential_hash=$2 FOR UPDATE`, id, digest).Scan(&status)
	if e != nil || status != "approved" {
		tx.Rollback(r.Context())
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return nil, "", "", e
		}
		return nil, "", "", apiError{401, "device_unauthorized", msgDeviceCredentialRequired}
	}
	return tx, org, id, nil
}

type policyPayload struct {
	Version    int       `json:"version"`
	Revision   int64     `json:"revision"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Rules      []Rule    `json:"rules"`
	Collection struct {
		PromptContent bool `json:"prompt_content"`
	} `json:"collection"`
}

func (a *App) devicePolicy(w http.ResponseWriter, r *http.Request) {
	if e := a.devicePolicyRequest(w, r); e != nil {
		a.fail(w, e)
	}
}
func (a *App) devicePolicyRequest(w http.ResponseWriter, r *http.Request) error {
	tx, org, id, e := a.deviceTx(r)
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	payload := policyPayload{Version: 1, IssuedAt: time.Now().UTC()}
	payload.ExpiresAt = payload.IssuedAt.Add(15 * time.Minute)
	cfg, e := a.effectiveShadow(r.Context(), tx, org, id)
	if e != nil {
		return e
	}
	// The v1 browser policy is derived from the Shadow AI services, the single
	// source of truth. The frozen legacy policies.revision is added as a floor so
	// the revision never decreases for agents that already stored a v1 revision.
	var legacy int64
	if e = tx.QueryRow(r.Context(), `SELECT revision FROM policies WHERE organization_id=$1`, org).Scan(&legacy); e != nil {
		return e
	}
	payload.Revision = cfg.Revision + legacy
	payload.Rules = rulesFromServices(cfg.Config.Services)
	for _, restriction := range cfg.Config.ModelAccess {
		if restriction.Channel == "browser" && restriction.Mode != "off" {
			return apiError{409, "upgrade_required", "Update this endpoint to enforce the configured model restrictions."}
		}
	}
	raw, e := json.Marshal(payload)
	if e != nil {
		return e
	}
	signature := ed25519.Sign(a.policyKey(org), raw)
	if _, e = tx.Exec(r.Context(), `UPDATE devices SET last_seen=now() WHERE id=$1`, id); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]string{"payload": base64.StdEncoding.EncodeToString(raw), "signature": base64.StdEncoding.EncodeToString(signature)})
	return nil
}

// rulesFromServices flattens Shadow AI services into v1 domain rules: observe
// stays observe; block and redirect both block, since v1 agents cannot redirect.
func rulesFromServices(services []ServiceConfig) []Rule {
	rules := []Rule{}
	for _, service := range services {
		action := "block"
		if service.Mode == "observe" {
			action = "observe"
		}
		for i, domain := range service.Domains {
			rules = append(rules, Rule{ID: service.ID + "-" + strconv.Itoa(i), Domain: domain, Action: action, Enabled: service.Enabled})
		}
	}
	return rules
}

type InputEvent struct {
	ID         string    `json:"id"`
	OccurredAt time.Time `json:"occurred_at"`
	Provider   string    `json:"provider"`
	Action     string    `json:"action"`
	Source     string    `json:"source"`
	Characters int       `json:"characters"`
	Labels     []string  `json:"labels"`
}

var categoryPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

func validateEvent(v InputEvent, now time.Time) error {
	if !uuidPattern.MatchString(v.ID) || v.OccurredAt.IsZero() || v.OccurredAt.After(now.Add(5*time.Minute)) || v.OccurredAt.Before(now.AddDate(-1, 0, 0)) {
		return bad("Event identity or timestamp is invalid.")
	}
	if !categoryPattern.MatchString(v.Provider) || (v.Action != "observed" && v.Action != "blocked") || v.Source != "browser" || v.Characters < 0 || v.Characters > 10000000 || v.Labels == nil || len(v.Labels) > 16 {
		return bad("Only bounded browser usage metadata is accepted.")
	}
	for _, label := range v.Labels {
		if !categoryPattern.MatchString(label) {
			return bad("Labels must be short category identifiers.")
		}
	}
	return nil
}
func (a *App) ingest(w http.ResponseWriter, r *http.Request) {
	if e := a.ingestRequest(w, r); e != nil {
		a.fail(w, e)
	}
}
func (a *App) ingestRequest(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Events []InputEvent `json:"events"`
	}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	if len(body.Events) < 1 || len(body.Events) > 100 {
		return bad("Submit between 1 and 100 events.")
	}
	now := time.Now()
	for _, v := range body.Events {
		if e := validateEvent(v, now); e != nil {
			return e
		}
	}
	tx, org, id, e := a.deviceTx(r)
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	accepted := make([]string, 0, len(body.Events))
	if _, e = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock_shared(7069202)`); e != nil {
		return e
	}
	cfg, e := a.effectiveShadow(r.Context(), tx, org, id)
	if e != nil {
		return e
	}
	if !cfg.Config.Collection.Enabled {
		return apiError{403, "collection_disabled", "Collection is disabled for this installation."}
	}
	for _, v := range body.Events {
		labels, _ := json.Marshal(v.Labels)
		if _, e = tx.Exec(r.Context(), `INSERT INTO events(organization_id,device_id,id,occurred_at,provider,action,source,characters,labels) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(organization_id,device_id,id) DO NOTHING`, org, id, v.ID, v.OccurredAt.UTC(), v.Provider, v.Action, v.Source, v.Characters, labels); e != nil {
			return e
		}
		accepted = append(accepted, v.ID)
	}
	if _, e = tx.Exec(r.Context(), `UPDATE devices SET last_seen=now() WHERE id=$1`, id); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]any{"accepted_ids": accepted})
	return nil
}

// approvalStatus resolves the status a newly enrolled device starts in, from the
// organization's configured approval policy. Every path that creates a device shares
// it: an MSI installation is no more trusted than a token enrollment, and a manual
// approval setting that a mass deployment silently bypassed would be worse than no
// setting at all.
func (a *App) approvalStatus(r *http.Request, tx pgx.Tx, org string, domains []machineDomain) (string, error) {
	cfg, e := a.readShadow(r.Context(), tx, org, 0)
	if e != nil {
		return "", e
	}
	switch cfg.Config.Enrollment.Approval {
	case "automatic":
		return "approved", nil
	case "network":
		// The rule matches the socket peer. Behind a reverse proxy, Ingress or Gateway
		// that peer is the proxy, often inside the very range an administrator names,
		// which approved every enrollment from the internet (audit of 2026-09-24). A
		// request carrying forwarding headers therefore never approves by network: it
		// waits for manual approval. A caller adding the header only makes it stricter.
		if r.Header.Get("Forwarded") != "" || r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("X-Real-IP") != "" {
			return "pending", nil
		}
		ipRaw, _, _ := net.SplitHostPort(r.RemoteAddr)
		ip := net.ParseIP(ipRaw)
		for _, raw := range cfg.Config.Enrollment.CIDRs {
			if _, network, e := net.ParseCIDR(raw); e == nil && network.Contains(ip) {
				return "approved", nil
			}
		}
		// A rule's network always applies; its domain, when set, narrows it. The domain is
		// declared by the machine, so it can never approve on its own.
		for _, rule := range cfg.Config.Enrollment.Rules {
			_, network, e := net.ParseCIDR(rule.CIDR)
			if e != nil || !network.Contains(ip) {
				continue
			}
			if rule.Domain == "" || slices.ContainsFunc(domains, func(d machineDomain) bool { return strings.EqualFold(d.Name, rule.Domain) }) {
				return "approved", nil
			}
		}
	}
	return "pending", nil
}

// machineDomain is what an enrolling agent declares about the directory its machine is
// joined to. Informational and matched by approval rules; the server cannot verify it.
type machineDomain struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// A DNS name (Active Directory or Linux realm, any case) or an Entra tenant ID.
var machineDomainPattern = regexp.MustCompile(`^(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func validMachineDomains(domains []machineDomain) bool {
	if len(domains) > 4 {
		return false
	}
	for _, d := range domains {
		if (d.Kind != "ad" && d.Kind != "entra" && d.Kind != "realm") || len(d.Name) > 253 || !machineDomainPattern.MatchString(d.Name) {
			return false
		}
	}
	return true
}

func machineDomainsJSON(domains []machineDomain) []byte {
	if domains == nil {
		domains = []machineDomain{}
	}
	raw, _ := json.Marshal(domains)
	return raw
}
