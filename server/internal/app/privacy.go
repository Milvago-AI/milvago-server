package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	// Posed on every path that walks the organization chain: a path that skips it
	// reads under whichever organization the transaction was left on, which is what
	// RLS is there to prevent.
	sqlSetOrganizationContext = "SELECT set_config('milvago.organization_id',$1,true)"
	// Locking read, used where the alias key may have to be created.
	// identityAliasKey deliberately reads the same row WITHOUT this lock, so its
	// query is not this constant: ingestion would serialize every batch of every
	// device behind the single privacy_settings row.
	sqlAliasKeyForUpdate     = "SELECT alias_key FROM privacy_settings WHERE organization_id=$1 FOR UPDATE"
	sqlDeleteIdentityReveals = "DELETE FROM identity_reveals WHERE organization_id=$1"

	msgPrivacyContextMissing = "privacy context missing"

	msgFreshMFARequired       = "Authenticate again with multi-factor authentication."
	msgReasonLengthRequired   = "A reason of 8 to 1000 characters is required."
	msgInvalidSubject         = "Invalid subject."
	purposeIdentityKey        = "identity-key"
	purposeIdentityNamePrefix = "identity-name:"
)

type IdentityPrivacyConfig struct {
	Pseudonymous     bool     `json:"pseudonymous"`
	AggregateOnly    bool     `json:"aggregate_only"`
	K                int      `json:"k_anonymity"`
	IdentityDays     int      `json:"identity_link_days"`
	LockDescendants  bool     `json:"lock_descendants"`
	Justification    string   `json:"retention_justification"`
	TeamClaim        string   `json:"team_claim"`
	DiscoveryEnabled bool     `json:"discovery_enabled"`
	IgnoredDomains   []string `json:"ignored_domains"`
	ShareHealth      bool     `json:"share_health"`
	ShareFleet       bool     `json:"share_fleet"`
	AutoCatalog      bool     `json:"auto_catalog"`
	// Detector-health thresholds: how many devices must have visited a provider in
	// the window before a verdict is given, below which share of network prompts the
	// DOM capture counts as degraded, and the window itself in hours.
	HealthMinDevices  int `json:"health_min_devices"`
	HealthDOMRatio    int `json:"health_dom_ratio_percent"`
	HealthWindowHours int `json:"health_window_hours"`
}
type PrivacyView struct {
	Config   IdentityPrivacyConfig `json:"config"`
	Revision int64                 `json:"revision"`
	LockedBy string                `json:"locked_by,omitempty"`
}

func defaultPrivacy() IdentityPrivacyConfig {
	return IdentityPrivacyConfig{Pseudonymous: true, K: 5, IdentityDays: 90, IgnoredDomains: []string{}, HealthMinDevices: 3, HealthDOMRatio: 20, HealthWindowHours: 24}
}

type privacyContextKey struct{}
type privacyRequest struct {
	app     *App
	session *Session
	view    PrivacyView
}

func (a *App) readPrivacy(ctx context.Context, tx pgx.Tx, org string) (out PrivacyView, err error) {
	out.Config = defaultPrivacy()
	current := org
	defer func() {
		_, e := tx.Exec(ctx, sqlSetOrganizationContext, org)
		if err == nil {
			err = e
		}
	}()
	for depth := 0; current != "" && depth < 20; depth++ {
		if _, err = tx.Exec(ctx, sqlSetOrganizationContext, current); err != nil {
			return
		}
		var raw []byte
		var rev int64
		err = tx.QueryRow(ctx, "SELECT configuration,revision FROM privacy_settings WHERE organization_id=$1", current).Scan(&raw, &rev)
		if errors.Is(err, pgx.ErrNoRows) {
			err = nil
			raw = []byte("{}")
			rev = 1
		}
		if err != nil {
			return
		}
		cfg := defaultPrivacy()
		if err = json.Unmarshal(raw, &cfg); err != nil {
			return
		}
		out.Revision += rev
		if current == org {
			out.Config = cfg
		} else if cfg.LockDescendants {
			// Parent control only imposes protective privacy settings. It never grants
			// consent to external telemetry on behalf of another organization.
			out.Config.Pseudonymous = cfg.Pseudonymous
			out.Config.AggregateOnly = cfg.AggregateOnly
			out.Config.K = cfg.K
			out.Config.IdentityDays = cfg.IdentityDays
			out.LockedBy = current
		}
		if Edition != "commercial" {
			current = ""
			break
		}
		var parent *string
		if err = tx.QueryRow(ctx, "SELECT parent_id FROM organizations WHERE id=$1", current).Scan(&parent); err != nil {
			return
		}
		current = ""
		if parent != nil {
			current = *parent
		}
	}
	if current != "" {
		err = bad("Organization ancestry exceeds supported depth.")
	}
	return
}
func privacyFor(r *http.Request) *privacyRequest {
	p, _ := r.Context().Value(privacyContextKey{}).(*privacyRequest)
	return p
}

// routePermissionKey carries the permission of the matched console route, so the
// exclusive barrier below can refuse a caller who will be refused anyway.
type routePermissionKey struct{}

// exclusiveBarrier lists the mutations that take the barrier exclusively. Adding a
// member (invitation, directory import) is not one of them: it spends seconds at the
// identity provider, and holding the exclusive form meanwhile stalled every tenant
// (audit of 2026-09-24). Those two serialize per account instead (lockAccount).
func exclusiveBarrier(r *http.Request) bool {
	if r.Method == "GET" || r.Method == "HEAD" {
		return false
	}
	switch r.URL.Path {
	case "/api/privacy":
		return r.Method == "PUT"
	case "/api/privacy/alias-key/rotate":
		return r.Method == "POST"
	case "/api/members/invitations", "/api/members/directory":
		return false
	}
	return strings.HasPrefix(r.URL.Path, "/api/roles") || strings.HasPrefix(r.URL.Path, "/api/members") || strings.HasPrefix(r.URL.Path, "/api/organizations")
}

// The privacy and permission barrier is one advisory lock per organization (user
// decision, 2026-09-24). A request takes the shared form of every organization from
// the root down to its own, because its authority and its privacy policy are read
// along that chain; a change takes the shared form of its target's ancestors and the
// exclusive form of the target. A change is thus ordered against exactly the requests
// it can alter -- those of the target's subtree -- and never against a sibling
// tenant's: with one global lock, a tenant administrator could stall every tenant.
// Everyone acquires root first, so the locks cannot deadlock among themselves.
const barrierKeySQL = `hashtextextended('milvago-barrier:'||$1::text,0)`

// barrierChain lists org and its ancestors, root first.
func barrierChain(ctx context.Context, tx pgx.Tx, org string) ([]string, error) {
	rows, e := tx.Query(ctx, `WITH RECURSIVE up(id,n) AS (SELECT $1::uuid,0 UNION ALL SELECT o.parent_id,up.n+1 FROM organizations o JOIN up ON o.id=up.id WHERE o.parent_id IS NOT NULL AND up.n<20) SELECT id::text FROM up ORDER BY n DESC`, org)
	if e != nil {
		return nil, e
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// sharedBarrier takes the shared form for org and its ancestors (or its ancestors
// only), root first.
func sharedBarrier(ctx context.Context, tx pgx.Tx, org string, includeOrg bool) error {
	chain, e := barrierChain(ctx, tx, org)
	if e != nil {
		return e
	}
	if !includeOrg && len(chain) > 0 {
		chain = chain[:len(chain)-1]
	}
	for _, id := range chain {
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(`+barrierKeySQL+`)`, id); e != nil {
			return e
		}
	}
	return nil
}

// barrierTarget is the organization a change alters: the one named in the path of an
// organization route, else the caller's.
func barrierTarget(r *http.Request, s *Session) string {
	if strings.HasPrefix(r.URL.Path, "/api/organizations/") {
		if id := r.PathValue("id"); uuidPattern.MatchString(id) {
			return strings.ToLower(id)
		}
	}
	return s.OrganizationID
}

func (a *App) privacyLock(r *http.Request, tx pgx.Tx, s *Session) error {
	ctx := r.Context()
	if !exclusiveBarrier(r) {
		// A read holding the shared form while it writes to a slow reader kept every
		// administrative change of its chain waiting for as long as the write timeout.
		// Past thirty idle seconds inside its transaction -- beyond the directory
		// search's twenty, the longest external wait of a read -- the database ends it.
		// A change may wait on the identity provider several times in a row before it
		// writes (four 15 s calls for an invitation or a directory): ninety seconds.
		// (handler also holds the response until the transaction has ended.)
		idle := `SET LOCAL idle_in_transaction_session_timeout='90s'`
		if r.Method == "GET" || r.Method == "HEAD" || r.URL.Path == mcpPath {
			idle = `SET LOCAL idle_in_transaction_session_timeout='30s'`
		}
		if _, e := tx.Exec(ctx, idle); e != nil {
			return e
		}
		return sharedBarrier(ctx, tx, s.OrganizationID, true)
	}
	// The exclusive form makes every new request of the target's subtree queue behind
	// it while it waits. It was taken before authorization, so any member with no
	// permission, or any key, could freeze requests with a stream of DELETE
	// /api/members/<uuid> (audit of 2026-09-24). The route's own check runs first,
	// without the lock -- handler repeats it under the lock; waits are budgeted per
	// person, keys included, and bounded.
	// Checked on the organization the change targets, which is the key it will wait on:
	// checked on the caller's own, an administrator of one tenant queued on the root's.
	target := barrierTarget(r, s)
	person, allowed, e := routePermissionHeld(r, tx, s, target)
	if e != nil {
		return e
	}
	if !allowed {
		return forbidden()
	}
	if e := sharedBarrier(ctx, tx, target, false); e != nil {
		return e
	}
	// Free when the target is free: only a wait -- the part that stalls the others --
	// spends the budget, so a burst of changes on a quiet organization is never refused.
	var granted bool
	if e := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(`+barrierKeySQL+`)`, target).Scan(&granted); e != nil || granted {
		return e
	}
	if e := a.checkIngestRate(ctx, "barrier person "+person, 20); e != nil {
		return e
	}
	if _, e := tx.Exec(ctx, `SET LOCAL lock_timeout='3s'`); e != nil {
		return e
	}
	if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(`+barrierKeySQL+`)`, target); e != nil {
		var pe *pgconn.PgError
		if errors.As(e, &pe) && pe.Code == "55P03" {
			return apiError{503, "busy", "Another administrative change is in progress. Retry shortly."}
		}
		return e
	}
	_, e = tx.Exec(ctx, `SET LOCAL lock_timeout TO DEFAULT`)
	return e
}

// lockAccount serializes the additions of one account to an organization, taken
// before the tree checks so two tenants cannot both pass outsideTree for it.
func lockAccount(r *http.Request, tx pgx.Tx, subject string) error {
	_, e := tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtextextended('milvago-account:'||$1,0))`, subject)
	return e
}

// routePermissionHeld is handler's permission check, answered before the barrier,
// with the person it is answered for (a key's creator).
func routePermissionHeld(r *http.Request, tx pgx.Tx, s *Session, org string) (string, bool, error) {
	permission, _ := r.Context().Value(routePermissionKey{}).(string)
	user, ctx := s.UserID, r.Context()
	var keyPermissions []string
	if s.pinned() && org != s.OrganizationID {
		return user, false, nil
	}
	// As permissionsFor: another organization's second-factor requirement applies.
	if org != s.OrganizationID && !s.MFA {
		if required, e := organizationRequiresMFA(ctx, tx, org); e != nil || required {
			return user, false, e
		}
	}
	if s.APIKeyID != "" {
		if e := tx.QueryRow(ctx, `SELECT user_id,permissions FROM api_keys WHERE id=$1 AND revoked_at IS NULL AND expires_at>clock_timestamp()`, s.APIKeyID).Scan(&user, &keyPermissions); errors.Is(e, pgx.ErrNoRows) {
			return "", false, nil
		} else if e != nil {
			return "", false, e
		}
	}
	var permissions []string
	if e := tx.QueryRow(ctx, `SELECT permissions FROM effective_access($1,$2)`, user, org).Scan(&permissions); errors.Is(e, pgx.ErrNoRows) {
		return user, false, nil
	} else if e != nil {
		return "", false, e
	}
	if s.APIKeyID != "" {
		permissions = intersect(permissions, keyPermissions)
	}
	return user, permission == "" || hasPermission(permissions, permission), nil
}
func (a *App) privacyRequest(r *http.Request, tx pgx.Tx, s *Session) (*http.Request, error) {
	if e := a.privacyLock(r, tx, s); e != nil {
		return r, e
	}
	p, e := a.readPrivacy(r.Context(), tx, s.OrganizationID)
	if e != nil {
		return r, e
	}
	return r.WithContext(context.WithValue(r.Context(), privacyContextKey{}, &privacyRequest{app: a, session: s, view: p})), nil
}
func requireIndividual(r *http.Request) error {
	if p := privacyFor(r); p != nil && p.view.Config.AggregateOnly {
		return apiError{403, "aggregate_only", "Individual usage is disabled by the effective privacy policy."}
	}
	return nil
}
func (a *App) requireFreshMFA(r *http.Request, tx pgx.Tx, s *Session) error {
	// Never a credential acting without a person at the keyboard: a key, or an access
	// token whose session row carries the token's auth_time as a verification time.
	if s.APIKeyID != "" || s.tokenAuth || !s.MFA || len(s.TokenHash) == 0 {
		return apiError{403, "fresh_mfa_required", msgFreshMFARequired}
	}
	var fresh bool
	if e := tx.QueryRow(r.Context(), `SELECT coalesce(mfa AND mfa_verified_at>clock_timestamp()-interval '5 minutes' AND mfa_verified_at<=clock_timestamp()+interval '30 seconds',false) FROM sessions WHERE token_hash=$1 AND organization_id=$2 AND user_id=$3 AND expires_at>clock_timestamp() FOR SHARE`, s.TokenHash, s.OrganizationID, s.UserID).Scan(&fresh); e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return apiError{403, "fresh_mfa_required", msgFreshMFARequired}
		}
		return e
	}
	if !fresh {
		return apiError{403, "fresh_mfa_required", msgFreshMFARequired}
	}
	return nil
}
func (a *App) getPrivacy(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	p, e := a.readPrivacy(r.Context(), tx, s.OrganizationID)
	if e != nil {
		return e
	}
	reply(w, 200, p)
	return nil
}
func (a *App) putPrivacy(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	var b struct {
		Revision int64                 `json:"revision"`
		Config   IdentityPrivacyConfig `json:"config"`
		Reason   string                `json:"reason"`
	}
	b.Config = defaultPrivacy()
	if e := decode(w, r, &b); e != nil {
		return e
	}
	if e := a.requireFreshMFA(r, tx, s); e != nil {
		return e
	}
	if len(strings.TrimSpace(b.Reason)) < 8 || len(b.Reason) > 1000 {
		return bad(msgReasonLengthRequired)
	}
	c := b.Config
	if e := validatePrivacyConfig(c); e != nil {
		return e
	}
	if _, e := tx.Exec(r.Context(), `INSERT INTO privacy_settings(organization_id) VALUES($1) ON CONFLICT DO NOTHING`, s.OrganizationID); e != nil {
		return e
	}
	if _, e := tx.Exec(r.Context(), `SELECT organization_id FROM privacy_settings WHERE organization_id=$1 FOR UPDATE`, s.OrganizationID); e != nil {
		return e
	}
	old, e := a.readPrivacy(r.Context(), tx, s.OrganizationID)
	if e != nil {
		return e
	}
	if old.Revision != b.Revision {
		return apiError{409, "revision_conflict", "Privacy settings changed. Reload before saving."}
	}
	if old.LockedBy != "" && (c.Pseudonymous != old.Config.Pseudonymous || c.AggregateOnly != old.Config.AggregateOnly || c.K != old.Config.K || c.IdentityDays != old.Config.IdentityDays) {
		return apiError{403, "configuration_enforced", "An ancestor enforces these privacy settings."}
	}
	var days int
	if e = tx.QueryRow(r.Context(), "SELECT retention_days FROM settings WHERE organization_id=$1", s.OrganizationID).Scan(&days); e != nil {
		return e
	}
	if days > 180 && len(strings.TrimSpace(c.Justification)) < 8 {
		return bad("Retention exceeding 180 days requires justification.")
	}
	raw, _ := json.Marshal(c)
	tag, e := tx.Exec(r.Context(), `UPDATE privacy_settings SET configuration=$2,revision=revision+1,updated_at=now() WHERE organization_id=$1`, s.OrganizationID, raw)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return errors.New("privacy settings were not updated")
	}
	if _, e = tx.Exec(r.Context(), sqlDeleteIdentityReveals, s.OrganizationID); e != nil {
		return e
	}
	action := "privacy.updated"
	if old.Config.Pseudonymous && !c.Pseudonymous {
		action = "privacy.pseudonymous.disabled"
	}
	if !old.Config.Pseudonymous && c.Pseudonymous {
		action = "privacy.pseudonymous.enabled"
	}
	if e = privacyAudit(r, tx, s, action, s.OrganizationID, map[string]any{"reason": b.Reason, "previous_revision": old.Revision}); e != nil {
		return e
	}
	next, e := a.readPrivacy(r.Context(), tx, s.OrganizationID)
	if e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, next)
	return nil
}

// validatePrivacyConfig is shared by PUT /api/privacy and the setup wizard.
func validatePrivacyConfig(c IdentityPrivacyConfig) error {
	if c.K < 1 || c.K > 100 || c.IdentityDays < 7 || c.IdentityDays > 365 || len(c.Justification) > 2000 || len(c.TeamClaim) > 100 || len(c.IgnoredDomains) > 100 {
		return bad("Invalid privacy settings.")
	}
	if c.HealthMinDevices < 1 || c.HealthMinDevices > 1000 || c.HealthDOMRatio < 1 || c.HealthDOMRatio > 100 || c.HealthWindowHours < 1 || c.HealthWindowHours > 168 {
		return bad("Invalid detector health thresholds.")
	}
	if Edition != "commercial" && c.LockDescendants {
		return forbidden()
	}
	for _, d := range c.IgnoredDomains {
		if !domainPattern.MatchString(d) || len(d) > 253 {
			return bad("Invalid ignored domain.")
		}
	}
	return nil
}

func privacyAudit(r *http.Request, tx pgx.Tx, s *Session, action, target string, details any) error {
	raw, e := json.Marshal(details)
	if e != nil {
		return e
	}
	var id string
	e = tx.QueryRow(r.Context(), `INSERT INTO audit(organization_id,actor,action,target,details,api_key_id,oauth_client) VALUES($1,$2,$3,$4,$5,nullif(current_setting('milvago.api_key_id',true),'')::uuid,nullif(current_setting('milvago.oauth_client',true),'')) RETURNING id`, s.OrganizationID, s.UserID, action, target, raw).Scan(&id)
	if e != nil {
		return e
	}
	if strings.HasPrefix(action, "identity.") || strings.HasPrefix(action, "privacy.") {
		return enqueuePrivacyAudit(r.Context(), tx, s.OrganizationID, id)
	}
	return nil
}
func (a *App) identityKey(ctx context.Context, tx pgx.Tx, org string) ([]byte, error) {
	if _, e := tx.Exec(ctx, `INSERT INTO privacy_settings(organization_id) VALUES($1) ON CONFLICT DO NOTHING`, org); e != nil {
		return nil, e
	}
	var encoded string
	if e := tx.QueryRow(ctx, sqlAliasKeyForUpdate, org).Scan(&encoded); e != nil {
		return nil, e
	}
	if encoded == "" {
		plain := []byte(randomToken())
		var e error
		encoded, e = a.sealShadow(org, purposeIdentityKey, plain)
		if e != nil {
			return nil, e
		}
		if _, e = tx.Exec(ctx, "UPDATE privacy_settings SET alias_key=$2 WHERE organization_id=$1", org, encoded); e != nil {
			return nil, e
		}
		return plain, nil
	}
	return a.openShadow(org, purposeIdentityKey, encoded)
}
func identityDigest(key []byte, kind, value string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(kind))
	h.Write([]byte{0})
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
}

// identityAliasKey reads the organization's alias key without the row lock
// identityKey takes to create it. Ingestion runs for every batch of every
// device: a FOR UPDATE on the single privacy_settings row of an organization
// would serialize all of them behind one another.
func (a *App) identityAliasKey(ctx context.Context, tx pgx.Tx, org string) ([]byte, error) {
	var encoded string
	e := tx.QueryRow(ctx, "SELECT alias_key FROM privacy_settings WHERE organization_id=$1", org).Scan(&encoded)
	if errors.Is(e, pgx.ErrNoRows) || (e == nil && encoded == "") {
		return a.identityKey(ctx, tx, org)
	}
	if e != nil {
		return nil, e
	}
	return a.openShadow(org, purposeIdentityKey, encoded)
}

// osAccountKey digests an OS account under the organization's alias key, the same
// primitive the OIDC subject alias uses. Case and surrounding spaces are folded:
// one machine reports one spelling, several machines of one person need not.
// Rotating the alias key deliberately breaks the link with earlier records, here
// as for subject aliases: a person then appears as two accounts on the map until
// the older records expire.
func osAccountKey(key []byte, account string) string {
	return identityDigest(key, "os-user", strings.ToLower(strings.TrimSpace(account)))
}

// machineName is independent of personal identity. Empty means unavailable.
func (a *App) machineName(r *http.Request, org, id, cipher string) (string, error) {
	if privacyFor(r) == nil {
		return "", errors.New(msgPrivacyContextMissing)
	}
	if r.URL.Query().Get("identity") == "aliases" {
		return deviceAlias(id), nil
	}
	return a.openIdentity(org, "device-name:"+id, cipher)
}
func deviceAlias(id string) string {
	return "Device " + strings.ToUpper(strings.ReplaceAll(id, "-", ""))[:16]
}
func (a *App) sealIdentity(org, purpose, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	return a.sealShadow(org, purpose, []byte(value))
}
func (a *App) openIdentity(org, purpose, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	plain, e := a.openShadow(org, purpose, value)
	return string(plain), e
}
func revealed(r *http.Request, tx pgx.Tx, subject string) (bool, error) {
	p := privacyFor(r)
	if p == nil {
		return false, errors.New(msgPrivacyContextMissing)
	}
	if r.URL.Query().Get("identity") == "aliases" {
		return false, nil
	}
	s := p.session
	// loadSession commits before the tenant handler. Lock and recheck the live
	// session so completed logout or organization changes cannot reuse a grant.
	if s.APIKeyID == "" {
		var currentMFA bool
		e := tx.QueryRow(r.Context(), `SELECT mfa FROM sessions WHERE token_hash=$1 AND organization_id=$2 AND user_id=$3 AND expires_at>clock_timestamp() FOR SHARE`, s.TokenHash, s.OrganizationID, s.UserID).Scan(&currentMFA)
		if errors.Is(e, pgx.ErrNoRows) {
			return false, nil
		}
		if e != nil {
			return false, e
		}
		if p.view.Config.Pseudonymous && !currentMFA {
			return false, nil
		}
	}
	if !p.view.Config.Pseudonymous {
		return true, nil
	}
	if s.APIKeyID != "" || !s.MFA || !hasPermission(s.Permissions, permIdentityReveal) || !uuidPattern.MatchString(subject) {
		return false, nil
	}
	var yes bool
	e := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM identity_reveals WHERE session_hash=$1 AND organization_id=$2 AND collaborator_id=$3 AND actor_id=$4 AND privacy_revision=$5 AND expires_at>clock_timestamp())`, s.TokenHash, s.OrganizationID, subject, s.UserID, p.view.Revision).Scan(&yes)
	return yes, e
}
func protectShadow(r *http.Request, tx pgx.Tx, v *ShadowEventView) error {
	p := privacyFor(r)
	if p == nil {
		return errors.New(msgPrivacyContextMissing)
	}
	// The sealed name travelled with the row: every read path already joins `devices d`
	// (shadowProjection selects d.hostname_ciphertext), so there is no per-row lookup
	// here and nothing to memoize. `revealed`, below, deliberately re-reads the live
	// session under FOR SHARE on every call -- that recheck is what makes a logout or
	// an organization change take effect mid-request -- and must stay uncached.
	var e error
	v.Hostname, e = p.app.machineName(r, p.session.OrganizationID, v.DeviceID, v.HostnameCiphertext)
	if e != nil {
		return e
	}
	// Recorded before any withholding: whether someone is behind the record is not
	// itself the identity, and the reader needs it to tell "nobody" from "not shown".
	v.UserKnown = v.User != ""
	yes, e := revealed(r, tx, v.ActorID)
	if e != nil {
		return e
	}
	if !yes {
		v.User = ""
		v.Files = nil
		v.Prompt = nil
		v.Response = nil
		return nil
	}
	if p.view.Config.Pseudonymous {
		e = tx.QueryRow(r.Context(), `SELECT max(expires_at) FROM identity_reveals WHERE session_hash=$1 AND organization_id=$2 AND collaborator_id=$3 AND actor_id=$4 AND privacy_revision=$5 AND expires_at>clock_timestamp()`, p.session.TokenHash, p.session.OrganizationID, v.ActorID, p.session.UserID, p.view.Revision).Scan(&v.IdentityExpiresAt)
		if e != nil {
			return e
		}
		if v.IdentityExpiresAt == nil {
			v.User = ""
			v.Files = nil
			v.Prompt = nil
			v.Response = nil
			return nil
		}
	}
	if uuidPattern.MatchString(v.ActorID) {
		var encrypted string
		if e = tx.QueryRow(r.Context(), "SELECT display_name FROM collaborators WHERE id=$1", v.ActorID).Scan(&encrypted); e != nil {
			return e
		}
		v.ActorName, e = p.app.openIdentity(p.session.OrganizationID, purposeIdentityNamePrefix+v.ActorID, encrypted)
		if e != nil {
			return e
		}
	}

	v.User, e = p.app.openIdentity(p.session.OrganizationID, "event-user:"+v.DeviceID+":"+v.ID, v.User)
	return e
}
func auditSubjectView(r *http.Request, tx pgx.Tx, subject, view string, count int) error {
	s, recorded, e := recordSubjectView(r, tx, subject, view)
	if e != nil || !recorded {
		return e
	}
	return privacyAudit(r, tx, s, "subject.view", subject, map[string]any{"view": view, "rows": count})
}

// recordSubjectView notes that the reader viewed a subject, at most once per five
// minutes, and says whether this view is to be audited.
func recordSubjectView(r *http.Request, tx pgx.Tx, subject, view string) (*Session, bool, error) {
	p := privacyFor(r)
	if p == nil {
		return nil, false, errors.New(msgPrivacyContextMissing)
	}
	s := p.session
	// An OS-account bucket is a subject of a view like a collaborator is: a filter
	// on one is auditable, and refusing the value here would turn the map's own
	// drill-down into a bad request.
	if subject != "" && subject != "unknown" && !uuidPattern.MatchString(subject) && !osActorPattern.MatchString(subject) {
		return nil, false, bad(msgInvalidSubject)
	}
	tag, e := tx.Exec(r.Context(), `INSERT INTO subject_views(organization_id,actor_id,subject,view,last_at) VALUES($1,$2,$3,$4,clock_timestamp()) ON CONFLICT(organization_id,actor_id,subject,view) DO UPDATE SET last_at=excluded.last_at WHERE subject_views.last_at<clock_timestamp()-interval '5 minutes'`, s.OrganizationID, s.UserID, subject, view)
	if e != nil {
		return nil, false, e
	}
	return s, tag.RowsAffected() != 0, nil
}
func (a *App) revealIdentity(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if e := requireIndividual(r); e != nil {
		return e
	}

	id := r.PathValue("id")
	if !uuidPattern.MatchString(id) {
		return bad(msgInvalidSubject)
	}
	var b struct {
		Reason string `json:"reason"`
	}
	if e := decode(w, r, &b); e != nil {
		return e
	}
	if e := a.requireFreshMFA(r, tx, s); e != nil {
		return e
	}
	if len(strings.TrimSpace(b.Reason)) < 8 || len(b.Reason) > 1000 {
		return bad(msgReasonLengthRequired)
	}
	var name, email, alias string
	if e := tx.QueryRow(r.Context(), "SELECT display_name,email,alias FROM collaborators WHERE id=$1 FOR SHARE", id).Scan(&name, &email, &alias); errors.Is(e, pgx.ErrNoRows) {
		return apiError{404, "not_found", "Subject not found."}
	} else if e != nil {
		return e
	}
	p := privacyFor(r)
	if p == nil {
		return errors.New(msgPrivacyContextMissing)
	}
	var expires time.Time
	if e := tx.QueryRow(r.Context(), `INSERT INTO identity_reveals(organization_id,session_hash,actor_id,collaborator_id,privacy_revision,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '15 minutes') RETURNING expires_at`, s.OrganizationID, s.TokenHash, s.UserID, id, p.view.Revision).Scan(&expires); e != nil {
		return e
	}
	if e := privacyAudit(r, tx, s, permIdentityReveal, id, map[string]any{"reason": b.Reason, "expires_at": expires}); e != nil {
		return e
	}
	var e error
	name, e = a.openIdentity(s.OrganizationID, purposeIdentityNamePrefix+id, name)
	if e != nil {
		return e
	}
	email, e = a.openIdentity(s.OrganizationID, "identity-email:"+id, email)
	if e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]any{"subject_id": id, "alias": alias, "display_name": name, "email": email, "expires_at": expires})
	return nil
}
func (a *App) eraseIdentity(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if e := a.requireFreshMFA(r, tx, s); e != nil {
		return e
	}
	id := r.PathValue("id")
	if !uuidPattern.MatchString(id) {
		return bad(msgInvalidSubject)
	}
	var present bool
	if e := tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM collaborators WHERE id=$1)", id).Scan(&present); e != nil {
		return e
	}
	if !present {
		return apiError{404, "not_found", "Subject not found."}
	}
	tag, e := tx.Exec(r.Context(), "DELETE FROM shadow_events WHERE collaborator_id=$1", id)
	if e != nil {
		return e
	}
	if _, e = tx.Exec(r.Context(), "DELETE FROM device_collaborators WHERE collaborator_id=$1", id); e != nil {
		return e
	}
	// subject_views.subject is a plain text column, not a foreign key: nothing
	// cascades it, so it must be cleared explicitly or a viewer's consultation
	// history keeps linking to the erased subject.
	if _, e = tx.Exec(r.Context(), "DELETE FROM subject_views WHERE subject=$1", id); e != nil {
		return e
	}
	deleted, e := tx.Exec(r.Context(), "DELETE FROM collaborators WHERE id=$1", id)
	if e != nil {
		return e
	}
	if deleted.RowsAffected() != 1 {
		return errors.New("subject was not erased")
	}
	if e = privacyAudit(r, tx, s, permIdentityErase, id, map[string]any{"events": tag.RowsAffected()}); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]any{"erased": true, "events": tag.RowsAffected()})
	return nil
}

// rotateAliasKey replaces the organization's alias key and re-derives every
// subject's digest and alias from its sealed identifier. Stable subject IDs and
// exported data can still permit correlation; rotation does not guarantee
// anonymisation.
// Published reports carry no alias, so they are unaffected. It sits in the same
// destructive family as erasure, hence the same permission.
func (a *App) rotateAliasKey(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {

	var b struct {
		Reason string `json:"reason"`
	}
	if e := decode(w, r, &b); e != nil {
		return e
	}
	if e := a.requireFreshMFA(r, tx, s); e != nil {
		return e
	}
	if len(strings.TrimSpace(b.Reason)) < 8 || len(b.Reason) > 1000 {
		return bad(msgReasonLengthRequired)
	}
	org := s.OrganizationID
	if _, e := tx.Exec(r.Context(), `INSERT INTO privacy_settings(organization_id) VALUES($1) ON CONFLICT DO NOTHING`, org); e != nil {
		return e
	}
	if _, e := tx.Exec(r.Context(), sqlAliasKeyForUpdate, org); e != nil {
		return e
	}
	plain := []byte(randomToken())
	sealed, e := a.sealShadow(org, purposeIdentityKey, plain)
	if e != nil {
		return e
	}
	rows, e := tx.Query(r.Context(), "SELECT id,subject_ciphertext FROM collaborators ORDER BY id")
	if e != nil {
		return e
	}
	type sealedSubject struct{ id, cipher string }
	subjects := []sealedSubject{}
	for rows.Next() {
		var v sealedSubject
		if e = rows.Scan(&v.id, &v.cipher); e != nil {
			rows.Close()
			return e
		}
		subjects = append(subjects, v)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return e
	}
	for _, v := range subjects {
		subject, e := a.openIdentity(org, "identity-subject:"+v.id, v.cipher)
		if e != nil {
			return e
		}
		if subject == "" {
			return errors.New("a subject cannot be re-aliased without its sealed identifier")
		}
		digest := identityDigest(plain, "oidc", subject)
		tag, e := tx.Exec(r.Context(), "UPDATE collaborators SET subject=$2,alias=$3 WHERE id=$1", v.id, digest, "Subject "+strings.ToUpper(digest[:24]))
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return errors.New("subject alias was not rotated")
		}
	}
	tag, e := tx.Exec(r.Context(), "UPDATE privacy_settings SET alias_key=$2,revision=revision+1,updated_at=now() WHERE organization_id=$1", org, sealed)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return errors.New("alias key was not rotated")
	}
	if _, e = tx.Exec(r.Context(), sqlDeleteIdentityReveals, org); e != nil {
		return e
	}
	if e = privacyAudit(r, tx, s, "privacy.alias_key.rotated", org, map[string]any{"reason": b.Reason, "subjects": len(subjects)}); e != nil {
		return e
	}
	next, e := a.readPrivacy(r.Context(), tx, org)
	if e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]any{"subjects": len(subjects), "revision": next.Revision})
	return nil
}
func auditSubjectFilters(r *http.Request, tx pgx.Tx, view string, count int) error {
	ids := r.URL.Query()["actor_id"]
	if len(ids) <= 1 {
		return auditSubjectView(r, tx, strings.Join(ids, ""), view, count)
	}
	// Several subjects in one request are one audit line naming them all. One line
	// each let a reader write twenty lines per request with made-up subjects and push
	// a real read out of the journal's latest entries (audit of 2026-09-24).
	var s *Session
	subjects := []string{}
	for _, id := range ids {
		reader, recorded, e := recordSubjectView(r, tx, id, view)
		if e != nil {
			return e
		}
		if recorded {
			s, subjects = reader, append(subjects, id)
		}
	}
	if len(subjects) == 0 {
		return nil
	}
	return privacyAudit(r, tx, s, "subject.view", strings.Join(subjects, " "), map[string]any{"view": view, "rows": count, "subjects": len(subjects)})
}
func (a *App) storeDeviceName(ctx context.Context, tx pgx.Tx, org, id, name string) error {
	sealed, e := a.sealIdentity(org, "device-name:"+id, name)
	if e != nil {
		return e
	}
	tag, e := tx.Exec(ctx, "UPDATE devices SET hostname=$1,hostname_ciphertext=$2 WHERE id=$3", deviceAlias(id), sealed, id)
	if e == nil && tag.RowsAffected() != 1 {
		return errors.New("device name was not stored")
	}
	return e
}
func (a *App) associateIdentity(ctx context.Context, tx pgx.Tx, org, subject, email, name string) (string, error) {
	key, e := a.identityKey(ctx, tx, org)
	if e != nil {
		return "", e
	}
	digest := identityDigest(key, "oidc", subject)
	alias := "Subject " + strings.ToUpper(digest[:24])
	var id string
	e = tx.QueryRow(ctx, `INSERT INTO collaborators(organization_id,subject,email,display_name,alias) VALUES($1,$2,'','',$3) ON CONFLICT(organization_id,subject) DO UPDATE SET last_associated_at=now() RETURNING id`, org, digest, alias).Scan(&id)
	if e != nil {
		return "", e
	}
	encryptedName, e := a.sealIdentity(org, purposeIdentityNamePrefix+id, name)
	if e != nil {
		return "", e
	}
	encryptedEmail, e := a.sealIdentity(org, "identity-email:"+id, email)
	if e != nil {
		return "", e
	}
	encryptedSubject, e := a.sealIdentity(org, "identity-subject:"+id, subject)
	if e != nil {
		return "", e
	}
	_, e = tx.Exec(ctx, "UPDATE collaborators SET display_name=$2,email=$3,subject_ciphertext=$4 WHERE id=$1", id, encryptedName, encryptedEmail, encryptedSubject)
	return id, e
}

// Plaintext columns only; see privateDevices for why the two sealed ones are absent.
//
// The NULL arm of the exclusion is load-bearing, not defensive noise. The Go filter it
// replaces compared an untyped JSON value, so an ungrouped device -- whose group_id is
// nil and therefore never equal -- was KEPT. A plain `d.group_id::text<>$5` drops it
// through three-valued logic, which would silently empty the "devices you can add to
// this group" dialog: exactly the screen this filter exists for. The inclusion arm
// ($4) must drop NULLs, which `=` already does, matching the Go behaviour it replaces.
const devicesPredicate = `($2='' OR d.platform=$2) AND ($3='' OR d.status=$3)
  AND ($4='' OR d.group_id::text=$4)
  AND ($5='' OR d.group_id IS NULL OR d.group_id::text<>$5)`

// `fleet`, `pending` and `platforms` read every machine; only `matched` honours the
// device_id scope and the filters. The console opens a device by naming it in the URL,
// and `fleet` is what lets it tell "this device is gone" from "this fleet is empty":
// that fact has its own column, so the platform facet is free to mean "filter options"
// and may one day be scoped without bringing the first-run screen back on a full fleet.
// Revoked machines count, on purpose: they are still rows of this listing (the status
// filter offers them), so a fleet whose every machine was revoked is a fleet with rows to
// show and a history to keep, not a first installation to walk through again; and
// `platforms` lists what those rows can be filtered by, revoked ones included.
const devicesFacets = `SELECT count(*),
  count(*) FILTER (WHERE d.status='pending'),
  coalesce(array_agg(DISTINCT d.platform),'{}'),
  count(*) FILTER (WHERE ($1='' OR d.id::text=$1) AND ` + devicesPredicate + `)
  FROM devices d`

const devicesRows = `SELECT jsonb_build_object('id',d.id,'hostname',d.hostname,'platform',d.platform,'version',d.version,'status',d.status,'last_seen',d.last_seen,'os_user',d.os_user,'browsers',d.browsers,'update_status',d.update_status,'update_reported_at',d.update_reported_at,'hostname_ciphertext',d.hostname_ciphertext,'collector_health',d.collector_health,'group_id',d.group_id,'group_name',g.name,'machine_domains',d.machine_domains) FROM devices d LEFT JOIN device_groups g ON g.organization_id=d.organization_id AND g.id=d.group_id WHERE ($1='' OR d.id::text=$1) AND ` + devicesPredicate + ` ORDER BY d.id`

type privateDeviceFilter struct {
	limit, offset                      int
	deviceID, groupID, excludeGroupID  string
	query, userQuery, platform, status string
}

func parsePrivateDeviceFilter(r *http.Request) (privateDeviceFilter, error) {
	limit, offset, e := collectionPage(r)
	if e != nil {
		return privateDeviceFilter{}, e
	}
	deviceID := r.URL.Query().Get("device_id")
	if deviceID != "" && !uuidPattern.MatchString(deviceID) {
		return privateDeviceFilter{}, bad("Invalid device ID.")
	}
	groupID := r.URL.Query().Get("group_id")
	excludeGroupID := r.URL.Query().Get("exclude_group_id")
	if (groupID != "" && !uuidPattern.MatchString(groupID)) || (excludeGroupID != "" && !uuidPattern.MatchString(excludeGroupID)) || (groupID != "" && excludeGroupID != "") {
		return privateDeviceFilter{}, bad("Invalid device group filter.")
	}
	// uuidPattern accepts either case; the predicates below compare `::text`, which
	// PostgreSQL renders lowercase. Without this an uppercase identity passed
	// validation and silently matched nothing -- an exclusion that excluded no one.
	deviceID, groupID, excludeGroupID = strings.ToLower(deviceID), strings.ToLower(groupID), strings.ToLower(excludeGroupID)
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("query")))
	userQuery := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("user")))
	platform := strings.TrimSpace(r.URL.Query().Get("platform"))
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	if len(query) > 200 || len(userQuery) > 200 || len(platform) > 100 || (status != "" && !slices.Contains([]string{"pending", "approved", "revoked"}, status)) {
		return privateDeviceFilter{}, bad("Invalid device filter.")
	}
	return privateDeviceFilter{limit, offset, deviceID, groupID, excludeGroupID, query, userQuery, platform, status}, nil
}

func (a *App) presentPrivateDevice(r *http.Request, s *Session, row map[string]any, show bool) error {
	id := row["id"].(string)
	originalOSUser := row["os_user"].(string)
	row["hostname"] = deviceAlias(id)
	row["os_user"] = ""
	hostname, e := a.machineName(r, s.OrganizationID, id, row["hostname_ciphertext"].(string))
	if e != nil {
		return e
	}
	row["hostname"] = hostname
	// Machine administration remains available; OS identity stays protected.
	if show {
		// The current OS user is independent from a verified subject association.
		osUser, e := a.openIdentity(s.OrganizationID, "device-user:"+id, originalOSUser)
		if e != nil {
			return e
		}
		row["os_user"] = osUser
	}
	delete(row, "hostname_ciphertext")
	return nil
}

func (a *App) privateDevices(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	f, e := parsePrivateDeviceFilter(r)
	if e != nil {
		return e
	}
	limit, offset, deviceID, groupID, excludeGroupID := f.limit, f.offset, f.deviceID, f.groupID, f.excludeGroupID
	query, userQuery, platform, status := f.query, f.userQuery, f.platform, f.status
	show := false
	if p := privacyFor(r); p != nil && !p.view.Config.AggregateOnly {
		show, e = revealed(r, tx, "")
		if e != nil {
			return e
		}
	}
	// The facets answer for the whole fleet: `fleet`, `pending` and `platforms` describe
	// every machine, never the filtered page nor the one device a device_id names -- a
	// device_id that names nothing (deleted, or another organization's) must still
	// read as "no match" on a populated fleet, not as "no fleet". `matched` is the
	// filtered count, computed here so
	// it stays exact even when offset runs past the last match -- which a
	// `count(*) OVER ()` on the paged query could not do, and which the console's
	// bounded pager and the groups dialog both rely on. No decryption on this path.
	var fleet, pending, matched int
	var platforms []string
	if e = tx.QueryRow(r.Context(), devicesFacets, deviceID, platform, status, groupID, excludeGroupID).Scan(&fleet, &pending, &platforms, &matched); e != nil {
		return e
	}
	if platforms == nil {
		platforms = []string{}
	}
	slices.Sort(platforms)
	// hostname and os_user are sealed with a per-device purpose in the AAD, so `query`
	// and `user` have no SQL form at all: deciding them means opening every envelope.
	// Everything else is a plaintext column and is settled by the database. When no text
	// search is active -- which is every request from the overview badge, the groups
	// dialogs and the MCP tool -- the page is cut in SQL and only the rows actually
	// returned are ever decrypted. Do not "simplify" this into one path.
	scan := query != "" || userQuery != ""
	statement, args, total := devicesRows, []any{deviceID, platform, status, groupID, excludeGroupID}, matched
	if !scan {
		statement, args = statement+" LIMIT $6 OFFSET $7", append(args, limit, offset)
	} else {
		total = 0
	}
	rows, e := tx.Query(r.Context(), statement, args...)
	if e != nil {
		return e
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var raw []byte
		if e = rows.Scan(&raw); e != nil {
			return e
		}
		var row map[string]any
		if e = json.Unmarshal(raw, &row); e != nil {
			return e
		}
		if e = a.presentPrivateDevice(r, s, row, show); e != nil {
			return e
		}
		// Only the two sealed filters are left to decide here, and only when one is
		// active: the database already applied the others and, on that path, the page.
		if scan {
			if (query != "" && !strings.Contains(strings.ToLower(row["hostname"].(string)), query)) ||
				(userQuery != "" && !strings.Contains(strings.ToLower(row["os_user"].(string)), userQuery)) {
				continue
			}
			total++
			if total <= offset || len(items) >= limit {
				continue
			}
		}
		items = append(items, row)
	}
	if e = rows.Err(); e != nil {
		return e
	}
	reply(w, 200, map[string]any{"items": items, "total": total, "fleet": fleet, "pending": pending, "limit": limit, "offset": offset, "platforms": platforms})
	return nil
}
func (a *App) registerPrivacyRoutes() {
	a.console("GET /api/privacy", "", a.getPrivacy)
	a.sessionOnly("PUT /api/privacy", permSettingsManage, a.putPrivacy)
	a.sessionOnly("POST /api/subjects/{id}/reveal", permIdentityReveal, a.revealIdentity)
	// Erasure has no console screen and that is deliberate, not an oversight: it is an
	// irreversible act performed on request, reached with a session credential and a
	// fresh second factor, not a button someone can find while browsing. An audit of
	// 2026-09-21 flagged the route as unreferenced by the console and proposed removing
	// it; keeping it is a decision. What it guarantees is proven by
	// privacy_hardening_test.go, which links a subject across ten tables, erases it, and
	// asserts no table still names it while the append-only audit keeps the identifier
	// and never a plaintext identity.
	a.sessionOnly("DELETE /api/subjects/{id}", permIdentityErase, a.eraseIdentity)
	a.sessionOnly("POST /api/privacy/alias-key/rotate", permIdentityErase, a.rotateAliasKey)
	a.console("GET /api/shadow/aggregate", permReportsAggregate, a.aggregateReports)
}

// namesMachines reports whether this reader may see real machine names on a view that
// is not the device listing itself: they must be allowed to read the devices, and the
// effective policy must not be aggregate-only. Otherwise a machine is its alias.
func namesMachines(r *http.Request, s *Session) bool {
	return hasPermission(s.Permissions, permDevicesRead) && requireIndividual(r) == nil
}

// machineLabel is machineName for such views: the alias unless namesMachines.
func (a *App) machineLabel(r *http.Request, s *Session, id, cipher string) (string, error) {
	if !namesMachines(r, s) {
		return deviceAlias(id), nil
	}
	return a.machineName(r, s.OrganizationID, id, cipher)
}
