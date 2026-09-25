package app

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
var domainPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

type Rule struct {
	ID      string `json:"id"`
	Domain  string `json:"domain"`
	Action  string `json:"action"`
	Enabled bool   `json:"enabled"`
}

func collectionPage(r *http.Request) (int, int, error) {
	limit, offset := 50, 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 200 {
			return 0, 0, bad("Limit must be between 1 and 200.")
		}
		limit = value
	}
	if raw := r.URL.Query().Get("offset"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 0 || value > 1_000_000 {
			return 0, 0, bad("Offset must be between 0 and 1000000.")
		}
		offset = value
	}
	return limit, offset, nil
}

func jsonQuery(w http.ResponseWriter, r *http.Request, tx pgx.Tx, query string, args ...any) error {
	var data json.RawMessage
	if e := tx.QueryRow(r.Context(), query, args...).Scan(&data); e != nil {
		return e
	}
	reply(w, 200, data)
	return nil
}
func (a *App) overview(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if p := privacyFor(r); p != nil && (p.view.Config.AggregateOnly || !hasPermission(s.Permissions, permEventsRead)) {
		return a.aggregateReports(w, r, tx, s)
	}
	// A visit and a submitted request are two distinct facts, so the counters must
	// not merge them: `requests` is prompts only, exactly like the cartography's
	// flows and series, and navigations are reported under their own key. Legacy v1
	// rows predate the kind column and are all prompts.
	// `pending_devices` is the overview's to-do badge: the fleet-wide count of machines
	// awaiting approval, answered here rather than by a second request to the device
	// listing whose one row the badge would only throw away.
	return jsonQuery(w, r, tx, `WITH recent AS (SELECT id,occurred_at,provider,action,'prompt' AS kind FROM events WHERE occurred_at>=now()-interval '24 hours' UNION ALL SELECT id,occurred_at,provider,action,kind FROM shadow_events e WHERE source='browser' AND occurred_at>=now()-interval '24 hours' AND NOT `+attachmentOnly("e")+`), requests AS (SELECT * FROM recent WHERE kind='prompt'), hours AS (SELECT generate_series(date_trunc('hour',now())-interval '23 hours',date_trunc('hour',now()),interval '1 hour') AS hour) SELECT jsonb_build_object('period_hours',24,'events',(SELECT count(*) FROM requests),'navigations',(SELECT count(*) FROM recent WHERE kind='navigation'),'blocked',(SELECT count(*) FROM requests WHERE action='blocked'),'devices',(SELECT count(*) FROM devices),'active_devices',(SELECT count(*) FROM devices WHERE status='approved' AND last_seen>now()-interval '24 hours'),'pending_devices',(SELECT count(*) FROM devices WHERE status='pending'),'providers',COALESCE((SELECT jsonb_agg(x ORDER BY x.events DESC,x.name) FROM (SELECT provider AS name,count(*) AS events,count(*) FILTER(WHERE action='blocked') AS blocked FROM requests GROUP BY provider) x),'[]'::jsonb),'timeline',(SELECT jsonb_agg(x ORDER BY x.hour) FROM (SELECT h.hour,count(e.id) AS events,count(e.id) FILTER(WHERE e.action='blocked') AS blocked FROM hours h LEFT JOIN requests e ON date_trunc('hour',e.occurred_at)=h.hour GROUP BY h.hour) x))`)
}

type Event struct {
	ID         string    `json:"id"`
	OccurredAt time.Time `json:"occurred_at"`
	DeviceID   string    `json:"device_id"`
	Hostname   string    `json:"hostname"`
	Provider   string    `json:"provider"`
	Action     string    `json:"action"`
	Source     string    `json:"source"`
	Characters int       `json:"characters"`
	Labels     []string  `json:"labels"`
}
type eventCursor struct {
	Time   time.Time `json:"t"`
	ID     string    `json:"i"`
	Device string    `json:"d"`
}

type eventsFilter struct {
	Limit                   int
	Query, Provider, Action string
	CursorTime              any
	CursorID, CursorDevice  string
}

func parseEventsFilter(r *http.Request) (eventsFilter, error) {
	filter := eventsFilter{Limit: 50, CursorID: "00000000-0000-4000-8000-000000000000", CursorDevice: "00000000-0000-4000-8000-000000000000"}
	q := r.URL.Query()
	if raw := q.Get("limit"); raw != "" {
		value, e := strconv.Atoi(raw)
		if e != nil || value < 1 || value > 100 {
			return filter, bad("Limit must be between 1 and 100.")
		}
		filter.Limit = value
	}
	filter.Query, filter.Provider, filter.Action = q.Get("query"), q.Get("provider"), q.Get("action")
	if len(filter.Query) > 100 || len(filter.Provider) > 100 || (filter.Action != "" && filter.Action != "observed" && filter.Action != "blocked") {
		return filter, bad("Invalid event filters.")
	}
	if raw := q.Get("cursor"); raw != "" {
		if len(raw) > 400 {
			return filter, bad("Invalid cursor.")
		}
		decoded, e := base64.RawURLEncoding.DecodeString(raw)
		var cursor eventCursor
		if e != nil || json.Unmarshal(decoded, &cursor) != nil || cursor.Time.IsZero() || !uuidPattern.MatchString(cursor.ID) || !uuidPattern.MatchString(cursor.Device) {
			return filter, bad("Invalid cursor.")
		}
		filter.CursorTime, filter.CursorID, filter.CursorDevice = cursor.Time, cursor.ID, cursor.Device
	}
	return filter, nil
}

func (a *App) events(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if e := requireIndividual(r); e != nil {
		return e
	}
	filter, e := parseEventsFilter(r)
	if e != nil {
		return e
	}
	limit, query, provider, action := filter.Limit, filter.Query, filter.Provider, filter.Action
	cursorTime, cursorID, cursorDevice := filter.CursorTime, filter.CursorID, filter.CursorDevice

	rows, e := tx.Query(r.Context(), `SELECT e.id,e.occurred_at,e.device_id,d.hostname_ciphertext,e.provider,e.action,e.source,e.characters,e.labels FROM events e JOIN devices d ON d.id=e.device_id AND d.organization_id=e.organization_id WHERE ($1='' OR e.provider ILIKE '%'||$1||'%' OR d.hostname ILIKE '%'||$1||'%') AND ($2='' OR e.provider=$2) AND ($3='' OR e.action=$3) AND ($4::timestamptz IS NULL OR (e.occurred_at,e.id,e.device_id)<($4::timestamptz,$5::uuid,$6::uuid)) ORDER BY e.occurred_at DESC,e.id DESC,e.device_id DESC LIMIT $7`, query, provider, action, cursorTime, cursorID, cursorDevice, limit+1)
	if e != nil {
		return e
	}
	defer rows.Close()
	items := []Event{}
	for rows.Next() {
		var v Event
		var hostnameCipher string
		if e = rows.Scan(&v.ID, &v.OccurredAt, &v.DeviceID, &hostnameCipher, &v.Provider, &v.Action, &v.Source, &v.Characters, &v.Labels); e != nil {
			return e
		}
		v.Hostname, e = a.machineName(r, s.OrganizationID, v.DeviceID, hostnameCipher)
		if e != nil {
			return e
		}
		items = append(items, v)
	}
	if e = rows.Err(); e != nil {
		return e
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1]
		b, _ := json.Marshal(eventCursor{last.OccurredAt, last.ID, last.DeviceID})
		next = base64.RawURLEncoding.EncodeToString(b)
	}
	if e = auditSubjectView(r, tx, "", "legacy_journal", len(items)); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]any{"items": items, "next_cursor": next})
	return nil
}
func (a *App) devices(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	return a.privateDevices(w, r, tx, s)
}
func (a *App) enrollment(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	var body struct {
		Label string `json:"label"`
	}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	body.Label = strings.TrimSpace(body.Label)
	if len(body.Label) < 1 || len(body.Label) > 120 {
		return bad("Enrollment label must contain 1 to 120 characters.")
	}
	token := randomToken()
	expiry := time.Now().UTC().Add(10 * time.Minute)
	var id string
	if e := tx.QueryRow(r.Context(), `INSERT INTO enrollments(organization_id,token_hash,label,expires_at) VALUES($1,$2,$3,$4) RETURNING id`, s.OrganizationID, hash(token), body.Label, expiry).Scan(&id); e != nil {
		return e
	}
	if e := audit(r.Context(), tx, s.OrganizationID, s.UserID, "enrollment.create", id); e != nil {
		return e
	}
	origin := a.publicOriginIn(r.Context(), tx)
	if e := tx.Commit(r.Context()); e != nil {
		return e
	}
	provision := map[string]any{"token": token, "expires_at": expiry, "server_url": origin, "policy_public_key": base64.StdEncoding.EncodeToString(a.policyKey(s.OrganizationID).Public().(ed25519.PublicKey))}
	if a.updatesAvailable() {
		provision["update_public_key"] = base64.StdEncoding.EncodeToString(a.config.UpdatePublicKey)
	}
	reply(w, 201, provision)
	return nil
}
func (a *App) approve(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	return a.deviceStatus(w, r, tx, s, "approved")
}
func (a *App) revoke(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	return a.deviceStatus(w, r, tx, s, "revoked")
}

// deleteDevice removes a device and, through the cascading device foreign keys,
// everything recorded about it: events, policy override, local observations and
// installation records. Revocation only stops new writes; this erases history,
// so it is a separate, explicitly confirmed action.
func (a *App) deleteDevice(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	id := r.PathValue("id")
	if !uuidPattern.MatchString(id) {
		return bad("Invalid device ID.")
	}
	// The delete cascades through the device's events and the prompt text retained
	// with them: the same irreversible erasure as a purge or a shorter retention, so
	// the same fresh second factor, and content.purge while any text is retained
	// (audit of 2026-09-24).
	if e := a.requireFreshPerson(r, tx, s); e != nil {
		return e
	}
	// The row first: a batch in flight holds it, so the check below sees its text
	// once it commits rather than missing it and the cascade erasing it unchecked.
	if _, e := tx.Exec(r.Context(), `SELECT 1 FROM devices WHERE id=$1 FOR UPDATE`, id); e != nil {
		return e
	}
	var retained bool
	if e := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM shadow_content WHERE device_id=$1)`, id).Scan(&retained); e != nil {
		return e
	}
	if retained && !hasPermission(s.Permissions, permContentPurge) {
		return apiError{403, "content_retained", "This device still has retained prompt text: deleting it requires the right to purge content."}
	}
	// Row-level security limits the statement to the current organization.
	command, e := tx.Exec(r.Context(), `DELETE FROM devices WHERE id=$1`, id)
	if e != nil {
		return e
	}
	if command.RowsAffected() != 1 {
		return apiError{404, "device_not_found", "This device does not exist in this organization."}
	}
	if e = audit(r.Context(), tx, s.OrganizationID, s.UserID, "device.delete", id); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]bool{"ok": true})
	return nil
}
func (a *App) deviceStatus(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session, status string) error {
	id := r.PathValue("id")
	if !uuidPattern.MatchString(id) {
		return bad("Invalid device ID.")
	}
	command, e := tx.Exec(r.Context(), `UPDATE devices SET status=$1 WHERE id=$2 AND status<> 'revoked' AND status<>$1`, status, id)
	if e != nil {
		return e
	}
	if command.RowsAffected() != 1 {
		return apiError{409, "device_state_conflict", "Device is missing, already in this state, or permanently revoked."}
	}
	if e = audit(r.Context(), tx, s.OrganizationID, s.UserID, "device."+status, id); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]string{"id": id, "status": status})
	return nil
}
func (a *App) members(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	limit, offset, err := collectionPage(r)
	if err != nil {
		return err
	}
	// Subtree listing: current organization plus accessible descendants, each row
	// carrying its organization (resolved by the SECURITY DEFINER subtree_members).
	// A pinned credential (key, token) sees its own organization only, as session()
	// and organizations() already narrow it.
	return jsonQuery(w, r, tx, `WITH visible AS MATERIALIZED (SELECT * FROM subtree_members($1,$2) WHERE NOT $5 OR organization_id=$2), page AS (SELECT * FROM visible ORDER BY organization_name,email LIMIT $3 OFFSET $4)
SELECT jsonb_build_object('items',COALESCE((SELECT jsonb_agg(jsonb_build_object('id',member_id,'email',email,'display_name',display_name,'role',role,'organization_id',organization_id,'organization_name',organization_name,'identity_type',identity_type,'language',language) ORDER BY organization_name,email) FROM page),'[]'::jsonb),'total',(SELECT count(*) FROM visible),'limit',$3,'offset',$4,'directory_configured',EXISTS(SELECT 1 FROM ldap_directories WHERE organization_id=$2))`, s.UserID, s.OrganizationID, limit, offset, s.pinned())
}
func (a *App) audits(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	return jsonQuery(w, r, tx, `SELECT jsonb_build_object('items',COALESCE(jsonb_agg(x ORDER BY x.occurred_at DESC,x.id DESC),'[]'::jsonb)) FROM (SELECT id,occurred_at,actor,action,target,details FROM audit ORDER BY occurred_at DESC,id DESC LIMIT 200) x`)
}
func (a *App) settings(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	// $3 mirrors the editable predicate in putSettings: a machine credential never
	// edits an instance-level value, so the response must not claim it can. This
	// route is also an MCP tool, so the claim is read by a model as well as by the
	// console.
	return jsonQuery(w, r, tx, `SELECT jsonb_build_object('name',o.name,'event_retention_days',s.retention_days,'public_url',(SELECT public_url FROM app_config),'public_url_confirmed',(SELECT public_url_confirmed FROM app_config),'public_url_editable',(o.parent_id IS NULL AND $2='owner' AND $3),'default_language',(SELECT default_language FROM app_config),'default_language_editable',(o.parent_id IS NULL AND $2='owner' AND $3)) FROM settings s JOIN organizations o ON o.id=s.organization_id WHERE s.organization_id=$1`, s.OrganizationID, s.Role, !s.pinned())
}

type settingsUpdate struct {
	Name            string  `json:"name"`
	Days            int     `json:"event_retention_days"`
	PublicURL       string  `json:"public_url"`
	DefaultLanguage *string `json:"default_language"`
}

type instanceSettings struct {
	URL       string
	Confirmed bool
	Language  string
	Editable  bool
}

func applyDefaultLanguage(state *instanceSettings, language *string) error {
	if language == nil {
		return nil
	}
	if !slices.Contains(consoleLanguages, *language) {
		return bad("Default language must be one of fr, en, es, pt-BR.")
	}
	if *language != state.Language && !state.Editable {
		return forbidden()
	}
	state.Language = *language
	return nil
}

func updatePublicURL(r *http.Request, tx pgx.Tx, state *instanceSettings, raw string) error {
	desired := strings.TrimRight(strings.TrimSpace(raw), "/")
	if state.Editable {
		if !validOrigin(desired) {
			return bad("Public URL must be an HTTPS origin (HTTP permitted only on explicit loopback).")
		}
		if _, e := tx.Exec(r.Context(), "UPDATE app_config SET public_url=$1,public_url_confirmed=true,default_language=$2", desired, state.Language); e != nil {
			return e
		}
		state.URL, state.Confirmed = desired, true
	} else if desired != "" && desired != state.URL {
		return apiError{403, "forbidden", "Only the root organization owner can change the public URL."}
	}
	return nil
}

func (a *App) updateInstanceSettings(r *http.Request, tx pgx.Tx, s *Session, body settingsUpdate) (instanceSettings, error) {
	var state instanceSettings
	var isRoot bool
	if e := tx.QueryRow(r.Context(), "SELECT parent_id IS NULL FROM organizations WHERE id=$1", s.OrganizationID).Scan(&isRoot); e != nil {
		return state, e
	}
	// A non-interactive credential cannot change instance-wide settings, even
	// when its role would otherwise allow that change.
	state.Editable = isRoot && s.Role == "owner" && !s.pinned()
	if e := tx.QueryRow(r.Context(), "SELECT public_url,public_url_confirmed,default_language FROM app_config").Scan(&state.URL, &state.Confirmed, &state.Language); e != nil {
		return state, e
	}
	if e := applyDefaultLanguage(&state, body.DefaultLanguage); e != nil {
		return state, e
	}
	if e := updatePublicURL(r, tx, &state, body.PublicURL); e != nil {
		return state, e
	}
	return state, nil
}

func (a *App) putSettings(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	var body settingsUpdate
	if e := decode(w, r, &body); e != nil {
		return e
	}
	body.Name = strings.TrimSpace(body.Name)
	if len(body.Name) < 1 || len(body.Name) > 120 || body.Days < 1 || body.Days > 365 {
		return bad("Name must contain 1 to 120 characters and retention must be between 1 and 365 days.")
	}
	// Renaming the organization requires organizations.manage (owner); admins with
	// settings.manage may change retention but not the organization name.
	var currentName string
	if e := tx.QueryRow(r.Context(), `SELECT name FROM organizations WHERE id=$1`, s.OrganizationID).Scan(&currentName); e != nil {
		return e
	}
	if body.Name != currentName && !hasPermission(s.Permissions, permOrganizationsManage) {
		return apiError{403, "forbidden", "Only an owner can rename the organization."}
	}
	instance, e := a.updateInstanceSettings(r, tx, s, body)
	if e != nil {
		return e
	}
	if _, e := tx.Exec(r.Context(), `UPDATE organizations SET name=$1 WHERE id=$2`, body.Name, s.OrganizationID); e != nil {
		return e
	}
	if body.Days > 180 {
		p, e := a.readPrivacy(r.Context(), tx, s.OrganizationID)
		if e != nil {
			return e
		}
		if len(strings.TrimSpace(p.Config.Justification)) < 8 {
			return bad("Retention exceeding 180 days requires justification.")
		}
	}
	// Shortening retention deletes history within the hour, prompts retained with it
	// by cascade: the same irreversible deletion the content purge guards with a fresh
	// second factor, so it gets the same guard here (audit of 2026-09-24).
	var currentDays int
	if e := tx.QueryRow(r.Context(), `SELECT retention_days FROM settings WHERE organization_id=$1 FOR UPDATE`, s.OrganizationID).Scan(&currentDays); e != nil {
		return e
	}
	if body.Days < currentDays {
		if e := a.requireFreshPerson(r, tx, s); e != nil {
			return e
		}
	}
	if _, e := tx.Exec(r.Context(), `UPDATE settings SET retention_days=$1 WHERE organization_id=$2`, body.Days, s.OrganizationID); e != nil {
		return e
	}
	if e := audit(r.Context(), tx, s.OrganizationID, s.UserID, "settings.update", s.OrganizationID); e != nil {
		return e
	}
	if e := tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]any{"name": body.Name, "event_retention_days": body.Days, "public_url": instance.URL, "public_url_confirmed": instance.Confirmed, "public_url_editable": instance.Editable, "default_language": instance.Language, "default_language_editable": instance.Editable})
	return nil
}
