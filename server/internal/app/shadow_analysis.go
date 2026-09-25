package app

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type shadowFilter struct {
	Where    string
	Args     []any
	Criteria map[string]any
	// The period is kept apart from Where because conversation grouping resolves
	// a missing conversation identifier through correlation over the same window
	// but deliberately ignores the other predicates: a kind=prompt filter would
	// otherwise drop the navigation that carries the identifier.
	From time.Time
	To   time.Time
}

// Sensitivity values accepted by the "sensitivity" filter, checked once per filter
// value; hoisted alongside eventKinds/eventActions (shadow_endpoint.go), which the
// "kind" and "action" filters below reuse rather than duplicate.
var sensitivityValues = []string{"normal", "sensitive", "unknown"}

func validateShadowFilterValue(key, value string) error {
	if len(value) > 200 || strings.ContainsAny(value, "\n\r\x00") {
		return bad("Invalid filter value.")
	}
	if key == "actor_id" && value != "unknown" && !uuidPattern.MatchString(value) && !osActorPattern.MatchString(value) {
		return bad("Invalid filter identity.")
	}
	if key == "device_id" && !uuidPattern.MatchString(value) {
		return bad("Invalid filter identity.")
	}
	if key == "sensitivity" {
		if Edition != "commercial" {
			return apiError{409, "capability_unavailable", "Usage sensitivity requires the Enterprise edition."}
		}
		if !slices.Contains(sensitivityValues, value) {
			return bad("Invalid sensitivity.")
		}
	}
	if key == "kind" && !slices.Contains(eventKinds, value) {
		return bad("Invalid event kind.")
	}
	if key == "action" && !slices.Contains(eventActions, value) {
		return bad("Invalid action.")
	}
	return nil
}

func shadowPeriod(q url.Values) (time.Time, time.Time, error) {
	now := time.Now().UTC()
	from, to := now.Add(-24*time.Hour), now
	for _, key := range []string{"from", "to"} {
		if len(q[key]) > 1 {
			return time.Time{}, time.Time{}, bad("Dates must have one value.")
		}
		if raw := q.Get(key); raw != "" {
			date, err := time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				return time.Time{}, time.Time{}, bad("Dates must be RFC3339.")
			}
			if key == "from" {
				from = date
			} else {
				to = date
			}
		}
	}
	if !from.Before(to) || to.Sub(from) > 366*24*time.Hour {
		return time.Time{}, time.Time{}, bad("Choose a valid period of at most 366 days.")
	}
	return from, to, nil
}

func shadowFilterValues(key string, values []string) ([]string, error) {
	if len(values) > 20 {
		return nil, bad("At most twenty selections per filter.")
	}
	out := []string{}
	for _, value := range values {
		if value == "" {
			continue
		}
		if err := validateShadowFilterValue(key, value); err != nil {
			return nil, err
		}
		if !slices.Contains(out, value) {
			out = append(out, value)
		}
	}
	return out, nil
}

func parseShadowFilter(q url.Values) (shadowFilter, error) {
	f := shadowFilter{Where: "TRUE", Args: []any{}, Criteria: map[string]any{}}
	add := func(expr string, value any) {
		f.Args = append(f.Args, value)
		f.Where += " AND " + fmt.Sprintf(expr, len(f.Args))
	}
	from, to, err := shadowPeriod(q)
	if err != nil {
		return f, err
	}
	add("e.occurred_at >= $%d", from)
	add("e.occurred_at <= $%d", to)
	f.From, f.To = from, to
	f.Criteria["from"] = from.Format(time.RFC3339Nano)
	f.Criteria["to"] = to.Format(time.RFC3339Nano)
	columns := map[string]string{"actor_id": actorBucket, "device_id": "e.device_id::text", "tool": "e.tool", "provider": "e.provider", "model": "coalesce(nullif(e.model,''),'unknown')", "sensitivity": "e.sensitivity", "action": "e.action", "kind": "e.kind"}
	for key, col := range columns {
		out, err := shadowFilterValues(key, q[key])
		if err != nil {
			return f, err
		}
		if len(out) > 0 {
			add(col+" = ANY($%d::text[])", out)
			f.Criteria[key] = out
		}
	}
	// Whether the record carries attached file names. A plain predicate rather than a
	// value list: the question is "are there any", and `files` is a jsonb array whose
	// empty state is `[]`, not NULL, so an emptiness test is the only correct form.
	//
	// It applies per record, like every other filter here, which is what makes it
	// behave the same way `kind` already does on the conversations listing: asking for
	// attachments narrows a thread to the messages that carry one.
	if attachment := q.Get("attachment"); attachment != "" {
		if len(q["attachment"]) > 1 || !slices.Contains([]string{"yes", "no"}, attachment) {
			return f, bad("Invalid attachment filter.")
		}
		if attachment == "yes" {
			f.Where += " AND jsonb_array_length(e.files)>0"
		} else {
			f.Where += " AND jsonb_array_length(e.files)=0"
		}
		f.Criteria["attachment"] = attachment
	}
	query := q.Get("query")
	if len(query) > 100 || len(q["query"]) > 1 {
		return f, bad("Search is limited to one hundred characters.")
	}
	if query != "" {
		f.Args = append(f.Args, query)
		n := len(f.Args)
		f.Where += fmt.Sprintf(" AND (e.provider ILIKE '%%'||$%d||'%%' OR e.tool ILIKE '%%'||$%d||'%%' OR e.model ILIKE '%%'||$%d||'%%' OR d.hostname ILIKE '%%'||$%d||'%%' OR c.alias ILIKE '%%'||$%d||'%%')", n, n, n, n, n)
		f.Criteria["query"] = query
	}
	return f, nil
}

const shadowJoins = ` FROM shadow_events e JOIN devices d ON d.organization_id=e.organization_id AND d.id=e.device_id LEFT JOIN collaborators c ON c.organization_id=e.organization_id AND c.id=e.collaborator_id `

// Who a record belongs to, in three states: the verified OIDC association, else
// the digest of the OS account it carries, else nothing. The journal filters and
// the cartography share this expression, so a person selected on the map is the
// same person in the journal. An `os:` bucket is deliberately not a UUID: no
// reveal grant, no membership and no permission can ever attach to it.
const actorBucket = `coalesce(e.collaborator_id::text,nullif('os:'||e.user_key,'os:'),'unknown')`

// Stable pseudonym for an OS bucket, used whenever the account itself is
// withheld. Same shape as the collaborator and device aliases: it separates two
// people without naming either.
const osAliasSQL = `nullif('Account '||upper(substr(e.user_key,1,16)),'Account ')`

// A device could report a different account on every record, so the number of
// buckets is not bounded by the number of people. The busiest ones are named;
// beyond that the map keeps aliases rather than decrypting without limit.
const osAccountLimit = 500

var osActorPattern = regexp.MustCompile(`^os:[0-9a-f]{64}$`)

const shadowProjection = `e.id,e.kind,e.occurred_at,e.provider,e.source,e.tool,e.model,e.effort,e.conversation_id,e.correlation_id,e.url,e.action,e.platform_id,e.decision_reason,e.characters,e.labels,e.policy_revision,e.device_id,d.hostname,d.hostname_ciphertext,coalesce(e.collaborator_id::text,'unknown'),coalesce(c.alias,'Unattributed'),e.sensitivity,e.files,e."user",e.detector,e.catalog_revision,e.input_tokens,e.output_tokens,e.body_bytes,e.characters_known,EXISTS(SELECT 1 FROM shadow_content sc WHERE sc.organization_id=e.organization_id AND sc.device_id=e.device_id AND sc.event_id=e.id AND sc.expires_at>now()),` + actorBucket

// A submission accompanied by a file leaves TWO records under the same correlation: the
// file leaves for the provider as soon as it is attached, so it is recorded before the
// text. This record belongs to the submission, it is not a
// second one -- the console has in fact shown it in the same bubble since 2026-09-15,
// while the counters used to announce two.
//
// The COUNTERS therefore exclude it. The journal, the detail view and the exports keep
// it: it is a real, timestamped, auditable record, and it is the one that proves a file
// left before the text. The criterion is that of the display merge -- a zero-character
// prompt sharing its correlation with a prompt carrying text -- and not the presence of
// file names: when their reporting is disabled, the attachment record carries none
// (observed 2026-09-15 on correlation 224a8be4).
func attachmentOnly(alias string) string {
	a := alias + "."
	return `(` + a + `kind='prompt' AND ` + a + `characters=0 AND ` + a + `correlation_id<>'' AND EXISTS(SELECT 1 FROM shadow_events b WHERE b.organization_id=` + a + `organization_id AND b.device_id=` + a + `device_id AND b.correlation_id=` + a + `correlation_id AND b.kind='prompt' AND b.characters>0))`
}

type ShadowEventView struct {
	V2Event
	DeviceID string `json:"device_id"`
	Hostname string `json:"hostname"`
	// The sealed machine name, read with the row so protectShadow can open it without a
	// second query per record. Never serialized: the alias or the opened name goes out.
	HostnameCiphertext string     `json:"-"`
	ActorID            string     `json:"actor_id"`
	ActorName          string     `json:"actor_name"`
	Sensitivity        string     `json:"sensitivity,omitempty"`
	IdentityExpiresAt  *time.Time `json:"identity_expires_at,omitempty"`
	HasContent         bool       `json:"has_content"`
	// The person a view of this record is audited under: the verified association,
	// else the OS-account bucket -- never serialized. ActorID stops at the association,
	// so ten OS accounts opened in a row were one `unknown` audit line (2026-09-24).
	AuditSubject string `json:"-"`
	// Whether an OS account was collected, stated without stating which one. Under
	// pseudonymity the account itself is withheld, and the console could not tell a
	// record naming nobody from one naming someone it may not show — so it called both
	// "unattributed", which is false for the second. This says only that a person is
	// there, under a pseudonym; revealing who still goes through the reveal path.
	UserKnown bool `json:"user_known,omitempty"`
}

func (v ShadowEventView) MarshalJSON() ([]byte, error) {
	type plain ShadowEventView
	raw, e := json.Marshal(plain(v))
	if e != nil {
		return nil, e
	}
	if v.CharactersKnown != nil && !*v.CharactersKnown {
		var out map[string]any
		if e = json.Unmarshal(raw, &out); e != nil {
			return nil, e
		}
		out["characters"] = nil
		return json.Marshal(out)
	}
	return raw, nil
}

// shadowDest lists the scan destinations of shadowProjection, in its order. A
// caller that selects extra columns after the projection appends its own
// destinations to this slice rather than restating the thirty-odd of them.
func shadowDest(v *ShadowEventView) []any {
	return []any{&v.ID, &v.Kind, &v.OccurredAt, &v.Provider, &v.Source, &v.Tool, &v.Model, &v.Effort, &v.ConversationID, &v.CorrelationID, &v.URL, &v.Action, &v.PlatformID, &v.DecisionReason, &v.Characters, &v.Labels, &v.PolicyRevision, &v.DeviceID, &v.Hostname, &v.HostnameCiphertext, &v.ActorID, &v.ActorName, &v.Sensitivity, &v.Files, &v.User, &v.Detector, &v.CatalogRevision, &v.InputTokens, &v.OutputTokens, &v.BodyBytes, &v.CharactersKnown, &v.HasContent, &v.AuditSubject}
}

// finishShadow applies the edition rules every read path owes a scanned row.
// Usage sensitivity is an Enterprise capability: Community never reports it.
// Blanking here covers the event list, the event detail, the conversations and
// the exports at once, since every read path passes through this function.
func finishShadow(v *ShadowEventView) {
	if Edition != "commercial" {
		v.Sensitivity = ""
	}
}
func scanShadow(row interface{ Scan(...any) error }) (ShadowEventView, error) {
	var v ShadowEventView
	e := row.Scan(shadowDest(&v)...)
	finishShadow(&v)
	return v, e
}
func queryShadow(r *http.Request, tx pgx.Tx, f shadowFilter, limit int) ([]ShadowEventView, error) {
	args := append([]any{}, f.Args...)
	args = append(args, limit)
	rows, e := tx.Query(r.Context(), `SELECT `+shadowProjection+shadowJoins+` WHERE `+f.Where+fmt.Sprintf(` ORDER BY e.occurred_at DESC,e.id DESC,e.device_id DESC LIMIT $%d`, len(args)), args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []ShadowEventView{}
	for rows.Next() {
		v, e := scanShadow(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	if e = rows.Err(); e != nil {
		return nil, e
	}
	// Closed before the loop, not only by the deferred call: protectShadow queries the
	// same transaction, and pgx keeps the connection busy while a cursor is open.
	rows.Close()
	for i := range out {
		if e = protectShadow(r, tx, &out[i]); e != nil {
			return nil, e
		}
	}
	return out, nil
}
func (a *App) shadowEvents(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if e := requireIndividual(r); e != nil {
		return e
	}
	f, e := parseShadowFilter(r.URL.Query())
	if e != nil {
		return e
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, e = strconv.Atoi(raw)
		if e != nil || limit < 1 || limit > 100 {
			return bad("Limit must be between 1 and 100.")
		}
	}
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		if len(raw) > 400 {
			return bad("Invalid cursor.")
		}
		b, e := base64.RawURLEncoding.DecodeString(raw)
		var c eventCursor
		if e != nil || json.Unmarshal(b, &c) != nil || c.Time.IsZero() || !uuidPattern.MatchString(c.ID) || !uuidPattern.MatchString(c.Device) {
			return bad("Invalid cursor.")
		}
		n := len(f.Args)
		f.Where += fmt.Sprintf(" AND (e.occurred_at,e.id,e.device_id)<($%d,$%d::uuid,$%d::uuid)", n+1, n+2, n+3)
		f.Args = append(f.Args, c.Time, c.ID, c.Device)
	}
	items, e := queryShadow(r, tx, f, limit+1)
	if e != nil {
		return e
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1]
		raw, _ := json.Marshal(eventCursor{last.OccurredAt, last.ID, last.DeviceID})
		next = base64.RawURLEncoding.EncodeToString(raw)
	}
	if e := auditSubjectFilters(r, tx, "journal", len(items)); e != nil {
		return e
	}
	if e := tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]any{"items": items, "next_cursor": next})
	return nil
}
func (a *App) shadowEventDetail(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if e := requireIndividual(r); e != nil {
		return e
	}
	id, device := r.PathValue("id"), r.URL.Query().Get("device_id")
	if !uuidPattern.MatchString(id) || !uuidPattern.MatchString(device) {
		return bad("Event and device identities are required.")
	}
	v, e := scanShadow(tx.QueryRow(r.Context(), `SELECT `+shadowProjection+shadowJoins+` WHERE e.id=$1 AND e.device_id=$2`, id, device))
	if e == pgx.ErrNoRows {
		return apiError{404, "not_found", "Event not found."}
	}
	if e != nil {
		return e
	}
	if e = protectShadow(r, tx, &v); e != nil {
		return e
	}
	if e = auditSubjectView(r, tx, v.AuditSubject, "detail", 1); e != nil {
		return e
	}
	access, e := contentAccessAvailable(r.Context(), tx, s.OrganizationID, s.UserID)
	if e != nil {
		return e
	}
	// Prompt content is the most sensitive thing the product holds, so a key needs
	// its own explicit grant on top of its creator's right to read: without this, a
	// key created to read event metadata would exfiltrate content the moment its
	// creator happened to hold that right. Revocable from either side.
	allowedIdentity, e := revealed(r, tx, v.ActorID)
	if e != nil {
		return e
	}
	access = access && s.contentUnlocked() && allowedIdentity
	out := map[string]any{"event": v, "can_read_content": access}
	if access && v.HasContent {
		var encrypted []byte
		if e = tx.QueryRow(r.Context(), `SELECT encrypted FROM shadow_content WHERE event_id=$1 AND device_id=$2 AND expires_at>now()`, id, device).Scan(&encrypted); e != nil {
			return e
		}
		plain, e := a.openShadow(s.OrganizationID, "event:"+device+":"+id, string(encrypted))
		if e != nil {
			return e
		}
		var content map[string]*string
		if e = json.Unmarshal(plain, &content); e != nil {
			return e
		}
		out["content"] = content
		if e = audit(r.Context(), tx, s.OrganizationID, s.UserID, "shadow.content.read", device+":"+id); e != nil {
			return e
		}
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, out)
	return nil
}

// osAccountNames resolves the OS-account buckets of a period to readable
// accounts, keyed by bucket, for the cartography to name them. The gate is the
// one the journal applies to the very same field: the account of a record
// without a verified association is an informational attribution, so the subject
// of the reveal check is `unknown`, exactly as in protectShadow. A pseudonymous
// organization, an `identity=aliases` request and an API key therefore get
// nothing here, and the map falls back to the digest alias, which still tells two
// people apart without naming either.
//
// The accounts are sealed per event, so one representative record per bucket is
// opened — the most recent, to name a person by what the machine reports now.
func (a *App) osAccountNames(r *http.Request, tx pgx.Tx, f shadowFilter) ([]byte, int, error) {
	empty := []byte("{}")
	yes, e := revealed(r, tx, "unknown")
	if e != nil || !yes {
		return empty, 0, e
	}
	p := privacyFor(r)
	if p == nil {
		return nil, 0, errors.New("privacy context missing")
	}
	type bucket struct{ key, device, event, cipher string }
	buckets := []bucket{}
	order := ` ORDER BY e.occurred_at DESC,e.id DESC`
	rows, e := tx.Query(r.Context(), `SELECT e.user_key,(array_agg(e.device_id::text`+order+`))[1],(array_agg(e.id::text`+order+`))[1],(array_agg(e."user"`+order+`))[1]`+
		shadowJoins+` WHERE `+f.Where+` AND e.kind='prompt' AND e.collaborator_id IS NULL AND e.user_key<>'' AND e."user"<>'' AND NOT `+attachmentOnly("e")+
		` GROUP BY 1 ORDER BY count(*) DESC,1 LIMIT `+strconv.Itoa(osAccountLimit), f.Args...)
	if e != nil {
		return nil, 0, e
	}
	for rows.Next() {
		var v bucket
		if e = rows.Scan(&v.key, &v.device, &v.event, &v.cipher); e != nil {
			rows.Close()
			return nil, 0, e
		}
		buckets = append(buckets, v)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return nil, 0, e
	}
	out := map[string]string{}
	for _, v := range buckets {
		name, e := a.openIdentity(p.session.OrganizationID, "event-user:"+v.device+":"+v.event, v.cipher)
		if e != nil {
			return nil, 0, e
		}
		if name != "" {
			out["os:"+v.key] = name
		}
	}
	encoded, e := json.Marshal(out)
	return encoded, len(out), e
}

func (a *App) cartography(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if e := requireIndividual(r); e != nil {
		return e
	}
	f, e := parseShadowFilter(r.URL.Query())
	if e != nil {
		return e
	}
	var raw json.RawMessage
	// Capture health: a browser service that is visited but never produces a
	// request suggests its DOM adapter no longer matches the site. Browser only —
	// native sources have no selectors to break.
	// Usage sensitivity is an Enterprise capability: Community emits neither the
	// per-flow counter nor the totals key, rather than a column of zeroes.
	flowSensitive, totalSensitive := "", ""
	if Edition == "commercial" {
		flowSensitive = `,count(*) FILTER(WHERE sensitivity='sensitive') sensitive`
		totalSensitive = `,'sensitive',count(*) FILTER(WHERE sensitivity='sensitive')`
	}
	// The map names a person by the verified association first, then by the OS
	// account the record belongs to: an informational attribution, kept apart from
	// the actor identity (`unknown` without an association) and from the
	// `unattributed` count, which stays verified-only.
	names, named, e := a.osAccountNames(r, tx, f)
	if e != nil {
		return e
	}
	// The model of an exchange, not the model of one record: a request is written
	// before it leaves, so the name of the model that answered is only known once the
	// answer is there, and it lands on the response. Reading it from prompts alone left
	// every browser flow at "unknown" while the name was collected all along. The
	// correlation the extension puts on one submission is what holds the two together.
	namesArg, criteriaArg := "$"+strconv.Itoa(len(f.Args)+1), "$"+strconv.Itoa(len(f.Args)+2)
	query := `WITH filtered AS (SELECT e.*,` + actorBucket + ` actor_bucket,coalesce(c.alias,` + namesArg + `::jsonb->>(` + actorBucket + `),` + osAliasSQL + `,'Unattributed') actor_name` + shadowJoins + ` WHERE ` + f.Where + ` AND NOT ` + attachmentOnly("e") + `), exchange AS (SELECT device_id,correlation_id,(array_agg(model ORDER BY occurred_at DESC,id DESC) FILTER (WHERE model<>''))[1] model FROM filtered WHERE correlation_id<>'' GROUP BY 1,2), flows AS (SELECT f.actor_bucket actor_id,f.actor_name,f.tool,f.provider,coalesce(nullif(f.model,''),nullif(xm.model,''),'unknown') model,count(*) count` + flowSensitive + `,count(*) FILTER(WHERE f.action='blocked') blocked FROM filtered f LEFT JOIN exchange xm ON xm.device_id=f.device_id AND xm.correlation_id=f.correlation_id WHERE f.kind='prompt' GROUP BY f.actor_bucket,f.actor_name,f.tool,f.provider,5), series AS (SELECT date_trunc('hour',occurred_at) at,count(*) requests FROM filtered WHERE kind='prompt' GROUP BY 1), capture AS (SELECT provider,count(*) FILTER(WHERE kind='navigation') navigations,count(*) FILTER(WHERE kind='prompt') requests,count(DISTINCT device_id) FILTER(WHERE kind='navigation') devices_seen,count(DISTINCT device_id) FILTER(WHERE kind='prompt') devices_reporting FROM filtered WHERE source='browser' GROUP BY provider) SELECT jsonb_build_object('totals',(SELECT jsonb_build_object('requests',count(*) FILTER(WHERE kind='prompt'),'responses',count(*) FILTER(WHERE kind='response'),'navigations',count(*) FILTER(WHERE kind='navigation'),'conversations',count(DISTINCT (device_id,conversation_id)) FILTER(WHERE conversation_id<>''),'actors',count(DISTINCT actor_bucket) FILTER(WHERE actor_bucket<>'unknown'),'tools',count(DISTINCT tool),'providers',count(DISTINCT provider),'models',count(DISTINCT model) FILTER(WHERE model<>'')` + totalSensitive + `,'blocked',count(*) FILTER(WHERE action='blocked')) FROM filtered),'flows',coalesce((SELECT jsonb_agg(x ORDER BY x.count DESC,x.actor_id,x.tool,x.provider,x.model) FROM flows x),'[]'::jsonb),'series',coalesce((SELECT jsonb_agg(x ORDER BY x.at) FROM series x),'[]'::jsonb),'capture',coalesce((SELECT jsonb_agg(x ORDER BY x.navigations DESC,x.provider) FROM capture x WHERE x.navigations>0),'[]'::jsonb),'unattributed',(SELECT count(*) FROM filtered WHERE collaborator_id IS NULL),'criteria',` + criteriaArg + `::jsonb)`
	criteria, _ := json.Marshal(f.Criteria)
	args := append(f.Args, names, criteria)
	if e = tx.QueryRow(r.Context(), query, args...).Scan(&raw); e != nil {
		return e
	}
	if e = auditSubjectFilters(r, tx, "cartography", named); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, raw)
	return nil
}
func csvSafe(s string) string {
	formula := func(v string) bool {
		return strings.HasPrefix(v, "=") || strings.HasPrefix(v, "+") || strings.HasPrefix(v, "-") || strings.HasPrefix(v, "@") || strings.HasPrefix(v, "\t") || strings.HasPrefix(v, "\r")
	}
	// A spreadsheet using ';' as its list separator (French Excel) splits an unquoted
	// field there, so a device-chosen "pc;=HYPERLINK(...)" started a live cell: each
	// segment is neutralized on its own (audit of 2026-09-24).
	segments := strings.Split(s, ";")
	for i, v := range segments {
		if formula(strings.TrimLeft(v, " ")) {
			segments[i] = "'" + v
		}
	}
	return strings.Join(segments, ";")
}
func writeShadowCSV(w http.ResponseWriter, items []ShadowEventView) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	cw := csv.NewWriter(w)
	header := []string{"id", "occurred_at", "kind", "collaborator", "device", "tool", "provider", "model", "action", "sensitivity", "characters"}
	if Edition != "commercial" {
		header = slices.Delete(header, 9, 10)
	}
	_ = cw.Write(header)
	for _, v := range items {
		characters := strconv.Itoa(v.Characters)
		if v.CharactersKnown != nil && !*v.CharactersKnown {
			characters = ""
		}
		row := []string{v.ID, v.OccurredAt.Format(time.RFC3339), v.Kind, v.ActorName, v.Hostname, v.Tool, v.Provider, v.Model, v.Action, v.Sensitivity, characters}
		if Edition != "commercial" {
			row = slices.Delete(row, 9, 10)
		}
		for i := range row {
			row[i] = csvSafe(row[i])
		}
		_ = cw.Write(row)
	}
	cw.Flush()
}

func (a *App) shadowExport(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if e := requireIndividual(r); e != nil {
		return e
	}
	f, e := parseShadowFilter(r.URL.Query())
	if e != nil {
		return e
	}
	// The export carries rows; the printed report is built by the console from the
	// cartography aggregates and printed by the browser (product decision, 2026-09-17).
	// The one-page PDF this handler used to write — Helvetica without an encoding, so
	// no accent rendered, six summary lines, no table and no chart — is gone with it.
	format := r.URL.Query().Get("format")
	if !slices.Contains([]string{"json", "csv"}, format) {
		return bad("Choose json or csv.")
	}
	// Exports require an explicit named request in addition to a live reveal.
	if r.URL.Query().Get("identity") != "revealed" {
		q := r.URL.Query()
		q.Set("identity", "aliases")
		u := *r.URL
		u.RawQuery = q.Encode()
		r = r.Clone(r.Context())
		r.URL = &u
	}
	items, e := queryShadow(r, tx, f, 10001)
	if e != nil {
		return e
	}
	if len(items) > 10000 {
		return apiError{409, "export_too_large", "Narrow the period to at most 10000 events."}
	}
	// Audited like every other view of a person's records: an export filtered on one
	// subject was the one way to read their history without leaving a subject.view
	// line, and its audit row named neither the criteria nor the identity mode
	// (audit of 2026-09-24).
	if e = auditSubjectFilters(r, tx, "export", len(items)); e != nil {
		return e
	}
	if e = privacyAudit(r, tx, s, "shadow.metadata.export", format, map[string]any{"criteria": f.Criteria, "identity": r.URL.Query().Get("identity"), "rows": len(items)}); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	w.Header().Set("Content-Disposition", `attachment; filename="milvago-events.`+format+`"`)
	switch format {
	case "json":
		reply(w, 200, map[string]any{"criteria": f.Criteria, "items": items})
	case "csv":
		writeShadowCSV(w, items)
	}
	return nil
}
