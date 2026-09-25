package app

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// API keys are the machine-facing half of the console API: the same /api routes,
// the same handlers, the same response shapes, reached with a bearer key instead
// of a session cookie.
//
// Three invariants hold the design together, and none of them may be relaxed:
//
//  1. A key never carries authority of its own. Its stored permissions are a
//     ceiling; the floor is effective_access() for its creator, re-derived on
//     every request. The applied set is the intersection of the two, so demoting
//     the creator or removing their membership shrinks or kills the key with no
//     extra bookkeeping and no revocation sweep.
//  2. A key is pinned to the organization that was active when it was created. It
//     cannot switch, and it cannot act on a sibling or a descendant even when its
//     creator could.
//  3. A key cannot manage keys. A stolen key must not be able to mint a wider or
//     longer-lived successor, nor resurrect itself after revocation. That is
//     enforced by registering the management routes with sessionOnly.

// apiKeyPrefix marks the credential's kind. It makes a key impossible to confuse
// with a device credential (deviceTx accepts only a bare 43-character token) and
// makes a leaked key recognizable to a secret scanner.
const apiKeyPrefix = "mvk_"

// A key is 32 random bytes in base64url (43 characters) behind that prefix.
const apiKeyLength = len(apiKeyPrefix) + 43

// apiKeyBudget bounds one key to a generous but finite number of requests per
// minute. An authenticated integration is not a trusted one: without a ceiling a
// single leaked key can exhaust the connection pool for the whole instance.
const apiKeyBudget = 600

// apiKeyLimit is how many live keys one user may hold in one organization, so an
// abandoned integration gets noticed rather than accumulated.
const apiKeyLimit = 5

// apiKeyLifetimes is an allowlist, deliberately not a numeric range: a range
// invites rounding at the boundary, a fixed set cannot be interpreted.
var apiKeyLifetimes = map[int]bool{30: true, 90: true, 365: true}

// registerAPIKeyRoutes mounts the self-service management surface.
//
// Every route is sessionOnly, and that is the single most important denial in the
// feature: without it a stolen key could mint a fresh, wider or longer-lived
// successor, which would make the mandatory bounded expiry decorative, or
// revoke the keys of the human it impersonates.
//
// No permission gates them. A key can never exceed
// intersection(key.permissions, effective_access(creator, org)), so creating one
// grants its owner nothing they do not already hold at every future instant -- it
// re-presents their own authority, which is the /api/profile self-service model.
// Adding a catalog permission would instead force an entry in permissionCatalog,
// two edits to the built-in sets, a matching edit to the duplicated seed list in
// db.go, and would silently strip the capability from every existing custom role.
func (a *App) registerAPIKeyRoutes() {
	a.sessionOnly("GET /api/profile/api-keys", "", a.apiKeys)
	a.sessionOnly("POST /api/profile/api-keys", "", a.createAPIKey)
	a.sessionOnly("DELETE /api/profile/api-keys/{id}", "", a.revokeAPIKey)
}

// One message for every rejection -- unknown, revoked, expired, malformed. A
// caller learns that the key does not work, never why, so the endpoint is not an
// oracle for probing which of a stolen set is still live.
func apiKeyUnauthorized() error {
	return apiError{401, "api_key_unauthorized", "A valid API key is required."}
}

// apiKeyTx authenticates a bearer key and opens its tenant-scoped transaction.
// It mirrors deviceTx: parse, hash, resolve across tenants through a SECURITY
// DEFINER function, spend the rate budget, then re-check under a row lock inside
// the transaction so a concurrent revocation cannot lose the race.
func (a *App) apiKeyTx(r *http.Request) (pgx.Tx, *Session, error) {
	ctx := r.Context()
	secret, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || len(secret) != apiKeyLength || !strings.HasPrefix(secret, apiKeyPrefix) {
		return nil, nil, apiKeyUnauthorized()
	}
	digest := hash(secret)
	// Two columns only: the organization, which cannot be known before a tenant
	// context exists, and the row identity. The owner and the permissions are read
	// back below, under row-level security.
	var org, keyID string
	if a.db.QueryRow(ctx, `SELECT organization_id,key_id FROM api_key_identity($1)`, digest).Scan(&org, &keyID) != nil {
		return nil, nil, apiKeyUnauthorized()
	}
	// Spent once the key is identified, so the budget cannot be escaped by
	// presenting a different credential, and before the transaction and the row
	// lock, which are what a flood would actually cost.
	if err := a.checkIngestRate(ctx, "apikey "+keyID, apiKeyBudget); err != nil {
		return nil, nil, err
	}
	// Recorded in its own short transaction, and strictly BEFORE the request
	// transaction takes the row lock below. Both halves of that are load-bearing:
	// see touchAPIKey.
	a.touchAPIKey(ctx, org, keyID)
	// The key is known and within its budget: its body is read now, before the
	// transaction and the barrier (see readBody), counted against the person behind
	// the key -- per key, a member rotating keys held as many bodies as they liked --
	// and never for a key already revoked or expired.
	if r.Method != "GET" && r.Method != "HEAD" {
		owner, e := a.apiKeyOwner(ctx, org, keyID)
		if e != nil {
			return nil, nil, e
		}
		if e := a.readBody(r, "person "+owner); e != nil {
			return nil, nil, e
		}
	}
	tx, e := tenantTx(ctx, a.db, org)
	if e != nil {
		return nil, nil, e
	}
	fail := func(e error) (pgx.Tx, *Session, error) {
		tx.Rollback(ctx)
		return nil, nil, e
	}
	s := &Session{OrganizationID: org, APIKeyID: keyID}
	// Lock order is privacy/authority, then credential row.
	if e := a.privacyLock(r, tx, s); e != nil {
		return fail(e)
	}
	// Re-read under row-level security and under a row lock held to commit. The
	// identity lookup above necessarily runs before any tenant context exists;
	// this is where the key's current state actually governs the request.
	//
	// FOR SHARE, not FOR UPDATE: revocation needs the exclusive lock, so it still
	// waits for requests already in flight and cannot be raced, while two
	// concurrent requests using the same key no longer serialize. That matters
	// here and not for devices, because this surface includes responses that
	// stream for a long time (GET /api/installer/{platform} sends a signed MSI,
	// GET /api/shadow/export sends a full export) and one such download would
	// otherwise block every other call made with the same key for its duration.
	//
	// Invariant this depends on: no statement inside the request transaction may
	// write this row. Upgrading a share lock held concurrently by two requests
	// deadlocks, which is exactly why the usage timestamp is written above,
	// outside and before this transaction.
	if e = tx.QueryRow(ctx, `SELECT user_id,permissions,content_access FROM api_keys WHERE id=$1 AND secret_hash=$2 AND revoked_at IS NULL AND expires_at>clock_timestamp() FOR SHARE`, keyID, digest).Scan(&s.UserID, &s.keyPermissions, &s.keyContent); e != nil {
		return fail(apiKeyUnauthorized())
	}
	// Read by audit(), so every existing call site attributes its row to the key
	// without a single call site being modified. Transaction-local, so a pooled
	// connection can never carry it into a cookie-authenticated request.
	if _, e = tx.Exec(ctx, `SELECT set_config('milvago.api_key_id',$1,true),set_config('milvago.api_key_org',$2,true)`, keyID, org); e != nil {
		return fail(e)
	}
	// The identity fields existing handlers already read -- session() reports the
	// email and display name. users carries no row-level security, which is why
	// the cross-tenant lookup above can stay at two columns.
	if e = tx.QueryRow(ctx, `SELECT email,display_name,subject,identity_type FROM users WHERE id=$1`, s.UserID).Scan(&s.Email, &s.DisplayName, &s.Subject, &s.IdentityType); e != nil {
		return fail(apiKeyUnauthorized())
	}
	return tx, s, nil
}

// touchAPIKey records that a key was used, in a transaction of its own.
//
// It cannot be folded into the request transaction: handlers commit only for
// mutations and every read path ends in the deferred Rollback, so a write
// attached to that transaction would be discarded on exactly the traffic an API
// key generates most -- the timestamp would stay null forever for a read-only
// integration.
//
// It must also run before the request transaction takes its FOR SHARE lock.
// Issued afterwards from this second connection it would deadlock with itself:
// the request holds the share lock and waits for this statement, while this
// statement asks for the exclusive lock and waits for the request. Running first
// leaves this transaction holding one lock and holding nothing while it waits, so
// it cannot be part of a wait cycle.
//
// Throttled because the value answers "is this key still in use?", not "when
// exactly". Best effort: losing a usage timestamp must never fail a request.
// apiKeyOwner is the person behind a live key, read in a transaction of its own.
func (a *App) apiKeyOwner(ctx context.Context, org, id string) (string, error) {
	tx, e := tenantTx(ctx, a.db, org)
	if e != nil {
		return "", e
	}
	defer tx.Rollback(ctx)
	var user string
	if e = tx.QueryRow(ctx, `SELECT user_id FROM api_keys WHERE id=$1 AND revoked_at IS NULL AND expires_at>clock_timestamp()`, id).Scan(&user); e != nil {
		return "", apiKeyUnauthorized()
	}
	return user, tx.Commit(ctx)
}

func (a *App) touchAPIKey(ctx context.Context, org, id string) {
	tx, e := tenantTx(ctx, a.db, org)
	if e != nil {
		return
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `UPDATE api_keys SET last_used_at=now() WHERE id=$1 AND revoked_at IS NULL AND expires_at>now() AND (last_used_at IS NULL OR last_used_at<now()-interval '5 minutes')`, id); e != nil {
		return
	}
	_ = tx.Commit(ctx)
}

// keyHolder is one account that still holds a live key in one organization.
type keyHolder struct{ org, user, subject string }

// revokeWithdrawnIdentities revokes the API keys of accounts the identity
// provider no longer honours -- deleted outright, or disabled.
//
// It exists because a key is the one credential nothing else re-checks. A cookie
// session dies on its own: refreshing it against the provider fails once the
// account is gone, and loadSession deletes the row. A key carries no refresh
// token and never consults the provider, so without this sweep, disabling an
// account in the directory leaves its machine credentials working until they
// expire -- up to a year.
//
// Two deliberate choices, both about the cost of being wrong:
//
//   - **Fail open on any provider error.** Revocation is irreversible and this
//     runs fleet-wide, so a Keycloak outage must not destroy every key in the
//     deployment. An unreachable or unconfigured provider changes nothing, and
//     the keys stay bounded by their own expiry and by the permission
//     intersection. The same reasoning makes identityUser.Enabled a pointer: an
//     absent field is unknown, not disabled.
//   - **Off the request path.** Checking per request would put an external HTTP
//     call in front of every API call and couple the API's availability to the
//     provider's. The exposure window is therefore one maintenance cycle, which
//     is the honest trade and is documented for the offboarding procedure.
func (a *App) revokeWithdrawnIdentities(ctx context.Context) {
	admin, e := a.identityAdmin(ctx)
	if e != nil {
		return
	}
	rows, e := a.db.Query(ctx, `SELECT id FROM organizations`)
	if e != nil {
		return
	}
	orgs := []string{}
	for rows.Next() {
		var org string
		if e = rows.Scan(&org); e != nil {
			break
		}
		orgs = append(orgs, org)
	}
	rows.Close()
	if e != nil || rows.Err() != nil {
		return
	}
	// Collected before any provider call, so no transaction is held open across
	// network I/O. users carries no row-level security, so the join is sound once
	// the tenant is set for api_keys.
	holders := []keyHolder{}
	for _, org := range orgs {
		tx, e := tenantTx(ctx, a.db, org)
		if e != nil {
			continue
		}
		found, e := tx.Query(ctx, `SELECT DISTINCT k.user_id,u.subject FROM api_keys k JOIN users u ON u.id=k.user_id WHERE k.revoked_at IS NULL AND k.expires_at>now()`)
		if e == nil {
			for found.Next() {
				h := keyHolder{org: org}
				if e = found.Scan(&h.user, &h.subject); e != nil {
					break
				}
				holders = append(holders, h)
			}
			found.Close()
		}
		tx.Rollback(ctx)
	}
	// One verdict per account for the whole sweep: the same person can hold keys
	// in several organizations, and the provider is asked once.
	verdicts := map[string]bool{}
	probed, answering := false, false
	for _, h := range holders {
		if _, known := verdicts[h.subject]; known {
			continue
		}
		u, e := admin.user(h.subject)
		if e != nil {
			// Unreachable or refused: no verdict, so this account is left alone.
			continue
		}
		// A 404 is ambiguous. The account may be gone, or the request may have
		// reached the wrong realm, or the service account may have lost its
		// rights -- all three answer 404 on a single user, and acting on the
		// first reading would revoke every key in the deployment the moment the
		// configuration is wrong. So corroborate once, against the collection
		// endpoint, and abandon the sweep rather than guess.
		if u == nil {
			if !probed {
				probed, answering = true, admin.answering()
			}
			if !answering {
				a.log.Error("identity administration answered 404 for a key holder but is not listing users; withdrawn-identity sweep abandoned")
				return
			}
		}
		verdicts[h.subject] = u.withdrawn()
	}
	for _, h := range holders {
		if !verdicts[h.subject] {
			continue
		}
		tx, e := tenantTx(ctx, a.db, h.org)
		if e != nil {
			continue
		}
		tag, e := tx.Exec(ctx, `UPDATE api_keys SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, h.user)
		if e != nil || tag.RowsAffected() == 0 {
			tx.Rollback(ctx)
			continue
		}
		// Attributed to the account whose keys these were; api_key_id stays null
		// because no key performed this -- maintenance did.
		if e = audit(ctx, tx, h.org, h.user, "api_key.identity_withdrawn", h.user); e != nil {
			tx.Rollback(ctx)
			continue
		}
		if e = tx.Commit(ctx); e != nil {
			continue
		}
		a.log.Info("revoked API keys for a withdrawn identity", "organization", h.org, "keys", tag.RowsAffected())
	}
}

type apiKeyView struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Permissions   []string   `json:"permissions"`
	ContentAccess bool       `json:"content_access"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	LastUsedAt    *time.Time `json:"last_used_at"`
}

// The projection is shared by the list and the creation reply so the two can
// never drift. It deliberately has no column for the secret: the plaintext exists
// only in the creation response, in memory.
const apiKeyProjection = `id,name,permissions,content_access,created_at,expires_at,last_used_at`

// mayGrant answers whether this caller may hand out the given permissions.
//
// The per-request intersection bounds what a key can do itself, and nothing more.
// It leaves lateral amplification open: a key holding members.manage, created by
// an owner, could promote an accomplice to owner; a key holding roles.manage
// could define a custom role carrying permissions the key itself was never given.
// Either turns a narrow key back into full authority through a second account.
//
// The rule that closes it: a key can never hand out a permission it does not
// itself hold. The same ceiling applies to interactive sessions: a second
// account must never amplify the current principal's authority.
func (s *Session) mayGrant(permissions []string) bool {
	return allHeld(s.Permissions, permissions)
}

// mayGrantRole is mayGrant for a role name: it resolves what the role actually
// carries in the current organization and applies the same rule, so a key cannot
// hand someone a role that is broader than the key itself.
func mayGrantRole(ctx context.Context, tx pgx.Tx, s *Session, role string) (bool, error) {
	var permissions []string
	if e := tx.QueryRow(ctx, `SELECT permissions FROM roles WHERE name=$1 FOR SHARE`, role).Scan(&permissions); e != nil {
		return false, e
	}
	return allHeld(s.Permissions, permissions), nil
}

// notGranted is the shared refusal for both the creation-time subset check and
// the non-amplification rule.
func notGranted() error {
	return apiError{403, "permission_not_held", "This cannot grant a permission you do not hold."}
}

func scanAPIKey(row pgx.Row) (apiKeyView, error) {
	var v apiKeyView
	e := row.Scan(&v.ID, &v.Name, &v.Permissions, &v.ContentAccess, &v.CreatedAt, &v.ExpiresAt, &v.LastUsedAt)
	return v, e
}

// contentAccessAvailable reports whether the caller may read prompt content in
// this organization, which is what decides if they may grant it to a key.
//
// The answer is their ROLE, but the role they hold IN THIS ORGANIZATION — deliberately
// not effective_access, which walks up to an ancestor. Every other permission is
// inherited by a parent over its descendants; prompt content is the documented
// exception, and it predates this function: the column this replaced was read on the
// organization at hand, and an owner of a parent, having no membership row in the
// child, was answered no. Resolving it through effective_access reopened exactly that
// path — verified on 2026-09-15 against a real hierarchy, where a parent owner with no
// membership in the child was granted the child's text.
//
// It used to be a per-person column, `memberships.content_access`, which no role could
// grant: an owner had to be given the flag by someone, and an owner alone in an
// organization therefore never obtained it (product decision, 2026-09-15).
//
// Deliberately not `hasPermission(s.Permissions, …)`: for a bearer key, s.Permissions
// is already the intersection of the key ceiling and its creator's rights, so reading
// it here would additionally demand `content.read` inside the key ceiling and lock out
// every key minted with content access before this change. The rule stays what it was:
// the creator's own right, re-read on every request, combined by the callers with the
// key's own `content_access`.
func contentAccessAvailable(ctx context.Context, tx pgx.Tx, org, user string) (bool, error) {
	var allowed bool
	e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM memberships m JOIN roles r ON r.organization_id=m.organization_id AND r.name=m.role
		WHERE m.organization_id=$2 AND m.user_id=$1 AND 'content.read'=ANY(r.permissions))`, user, org).Scan(&allowed)
	if e == pgx.ErrNoRows {
		return false, nil
	}
	return allowed, e
}

func (a *App) apiKeys(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	rows, e := tx.Query(r.Context(), `SELECT `+apiKeyProjection+` FROM api_keys WHERE user_id=$1 AND revoked_at IS NULL AND expires_at>now() ORDER BY created_at DESC,id DESC`, s.UserID)
	if e != nil {
		return e
	}
	defer rows.Close()
	items := []apiKeyView{}
	for rows.Next() {
		v, e := scanAPIKey(rows)
		if e != nil {
			return e
		}
		items = append(items, v)
	}
	if e = rows.Err(); e != nil {
		return e
	}
	content, e := contentAccessAvailable(r.Context(), tx, s.OrganizationID, s.UserID)
	if e != nil {
		return e
	}
	// The published MCP key of a demonstration instance, and only there.
	//
	// A demonstration cannot mint a key — creating one is a write, which the
	// read-only rule refuses — so without this the endpoint it advertises is
	// unusable: the credential exists, hashed, and nobody can read it. Two
	// conditions guard the field, and a customer instance meets neither: the
	// instance must run read-only, and the operator must have put the key in the
	// environment on purpose. The value is a demonstration credential by
	// construction — narrow ceiling, no content, pinned to its organization — and
	// it is meant to be handed out.
	out := map[string]any{"items": items, "content_access_available": content}
	if a.config.DemoReadOnly && a.config.DemoMCPKey != "" {
		out["demo_mcp_key"] = a.config.DemoMCPKey
	}
	reply(w, 200, out)
	return nil
}

func (a *App) createAPIKey(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	var body struct {
		Name          string   `json:"name"`
		ExpiresInDays int      `json:"expires_in_days"`
		Permissions   []string `json:"permissions"`
		ContentAccess bool     `json:"content_access"`
	}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	body.Name = strings.TrimSpace(body.Name)
	if len(body.Name) < 1 || len(body.Name) > 60 || hasControl(body.Name) {
		return bad("The key name must contain 1 to 60 characters without control characters.")
	}
	if !apiKeyLifetimes[body.ExpiresInDays] {
		return bad("Choose an expiry of 30, 90 or 365 days.")
	}
	if len(body.Permissions) == 0 {
		return bad("Choose at least one permission for the key.")
	}
	if !validPermissions(body.Permissions) {
		return bad("Unknown permission.")
	}
	// A key may never exceed its creator. s.Permissions is the caller's live
	// effective set for this organization, already resolved by console(). This
	// check is the creation-time half; the request-time intersection is the half
	// that keeps holding after the creator is demoted.
	if !allHeld(s.Permissions, body.Permissions) {
		return notGranted()
	}
	if body.ContentAccess {
		allowed, e := contentAccessAvailable(r.Context(), tx, s.OrganizationID, s.UserID)
		if e != nil {
			return e
		}
		if !allowed {
			return bad("You cannot grant prompt content access to a key.")
		}
	}
	// Serialize this account's creations before counting, so two parallel requests
	// cannot each read four and both insert a fifth. Same count-then-mutate
	// discipline mutateMember uses, narrowed to the one account.
	if _, e := tx.Exec(r.Context(), `SELECT id FROM users WHERE id=$1 FOR UPDATE`, s.UserID); e != nil {
		return e
	}
	var live int
	if e := tx.QueryRow(r.Context(), `SELECT count(*) FROM api_keys WHERE user_id=$1 AND revoked_at IS NULL AND expires_at>now()`, s.UserID).Scan(&live); e != nil {
		return e
	}
	if live >= apiKeyLimit {
		return apiError{409, "api_key_limit", "Revoke one of your API keys before creating another."}
	}
	secret := apiKeyPrefix + randomToken()
	view, e := scanAPIKey(tx.QueryRow(r.Context(),
		`INSERT INTO api_keys(organization_id,user_id,name,secret_hash,permissions,content_access,expires_at)
		 VALUES($1,$2,$3,$4,$5,$6,now()+make_interval(days => $7)) RETURNING `+apiKeyProjection,
		s.OrganizationID, s.UserID, body.Name, hash(secret), body.Permissions, body.ContentAccess, body.ExpiresInDays))
	if e != nil {
		return e
	}
	if e = audit(r.Context(), tx, s.OrganizationID, s.UserID, "api_key.create", view.ID); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	// The only time the plaintext leaves the server. It is not logged, and no
	// column stores it, so a lost key can only be replaced.
	reply(w, 201, map[string]any{"key": view, "secret": secret})
	return nil
}

func (a *App) revokeAPIKey(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	id := r.PathValue("id")
	if !uuidPattern.MatchString(id) {
		return bad("Invalid key identity.")
	}
	// The user_id predicate is what stops one member revoking another's key;
	// row-level security already stops it across organizations. Revocation is
	// logical, not a delete: the audit trail keeps resolving against the row
	// until maintenance purges it.
	tag, e := tx.Exec(r.Context(), `UPDATE api_keys SET revoked_at=now() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL`, id, s.UserID)
	if e != nil {
		return e
	}
	if tag.RowsAffected() == 0 {
		return apiError{404, "not_found", "API key not found."}
	}
	if e = audit(r.Context(), tx, s.OrganizationID, s.UserID, "api_key.revoke", id); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]bool{"ok": true})
	return nil
}
