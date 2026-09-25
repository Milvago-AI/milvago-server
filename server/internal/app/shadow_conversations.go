package app

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// A conversation is a thread of records sharing one platform conversation
// identifier on one device. Three facts shape the grouping:
//
//   - The browser extension reads the identifier from the tab URL, so the very
//     first prompt of a new chat has none: the page is still on /new when the
//     gesture is captured. The extension keeps the same correlation identifier
//     across the URL assignment and emits a navigation carrying both, so that
//     opening prompt is recovered by correlation rather than left on its own.
//   - Records that can never carry one -- an isolated navigation, a command line
//     refusal, a network filter block -- become threads of a single message
//     instead of disappearing from the view.
//   - The identifier is per device: the same platform thread seen from two
//     machines is two threads here, because nothing links the two devices.
type conversationCursor struct {
	Time   time.Time `json:"t"`
	Device string    `json:"d"`
	Key    string    `json:"k"`
}

// ConversationView carries the counters of a thread and the whole of its most
// recent record. The record is a plain ShadowEventView so it passes through
// scanShadow and protectShadow unchanged: hostname aliasing, identity reveal and
// the blanking of user and file names are not restated here, and cannot drift.
type ConversationView struct {
	Key         string    `json:"key"`
	StartedAt   time.Time `json:"started_at"`
	LastAt      time.Time `json:"last_at"`
	Prompts     int       `json:"prompts"`
	Responses   int       `json:"responses"`
	Navigations int       `json:"navigations"`
	Blocked     int       `json:"blocked"`
	Redirected  int       `json:"redirected"`
	// Whether ANY message of the thread carried attached file names. A thread-level
	// answer, because that is the question being asked: "did a document leave with
	// this conversation". The names themselves stay on the message that carried them.
	HasAttachment bool            `json:"has_attachment"`
	Model         string          `json:"model"`
	Effort        string          `json:"effort"`
	Latest        ShadowEventView `json:"latest"`
}

// ThreadMessage says why a text is absent as precisely as the reader is allowed
// to know. The console turns content_state into the label of the tag it shows in
// place of the bubble, so the three refusals never read as the same thing.
type ThreadMessage struct {
	ShadowEventView
	ContentState string             `json:"content_state"`
	Content      map[string]*string `json:"content,omitempty"`
}

// ShadowEventView carries its own MarshalJSON, and embedding promotes it: without
// this method the encoder would call the embedded one and silently drop
// content_state and content, leaving every bubble looking like a navigation. The
// embedded marshaller is still the one that writes the record, so the rule that
// blanks an unknown character count is not restated here either.
func (m ThreadMessage) MarshalJSON() ([]byte, error) {
	raw, e := json.Marshal(m.ShadowEventView)
	if e != nil {
		return nil, e
	}
	var out map[string]any
	if e = json.Unmarshal(raw, &out); e != nil {
		return nil, e
	}
	out["content_state"] = m.ContentState
	if m.Content != nil {
		out["content"] = m.Content
	}
	return json.Marshal(out)
}

const (
	contentAvailable    = "available"
	contentDenied       = "denied"
	contentNotRetained  = "not_retained"
	contentIdentity     = "identity"
	conversationKeyMax  = 206
	conversationDefault = 10
	conversationMax     = 50

	msgInvalidCursor = "Invalid cursor."
)

// splitConversationKey parses the opaque key the list hands the console back.
// Validating it here keeps the console from having to know the shape, and keeps
// a hand written key from reaching a query as anything but a conversation
// identifier of the length the ingest accepts or an event UUID.
func splitConversationKey(key string) (conversation, correlation, event string, ok bool) {
	if len(key) > conversationKeyMax {
		return "", "", "", false
	}
	if rest, found := strings.CutPrefix(key, "conv:"); found {
		if validMetadata(rest, 200) {
			return rest, "", "", true
		}
		return "", "", "", false
	}
	if rest, found := strings.CutPrefix(key, "corr:"); found {
		if validMetadata(rest, 200) {
			return "", rest, "", true
		}
		return "", "", "", false
	}
	if rest, found := strings.CutPrefix(key, "event:"); found && uuidPattern.MatchString(rest) {
		return "", "", rest, true
	}
	return "", "", "", false
}

func conversationListPage(r *http.Request) (int, int, error) {
	var e error
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, e = strconv.Atoi(raw)
		if e != nil || limit < 1 || limit > 200 {
			return 0, 0, bad("Limit must be between 1 and 200.")
		}
	}
	// Numbered pages need to jump, which a keyset cursor cannot do, so the console
	// asks by offset and reads the matching total back. The cursor stays for the
	// callers that walk the list forward one page at a time; the two ways of naming
	// a position never travel together.
	offset := 0
	if raw := r.URL.Query().Get("offset"); raw != "" {
		if r.URL.Query().Get("cursor") != "" {
			return 0, 0, bad("Use either a cursor or an offset, not both.")
		}
		offset, e = strconv.Atoi(raw)
		if e != nil || offset < 0 || offset > 1000000 {
			return 0, 0, bad("Offset must be between 0 and 1000000.")
		}
	}
	return limit, offset, nil
}

func conversationCursorFilter(r *http.Request, args []any) ([]any, string, error) {
	cursorWhere := ""
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		if len(raw) > 400 {
			return nil, "", bad(msgInvalidCursor)
		}
		b, de := base64.RawURLEncoding.DecodeString(raw)
		var c conversationCursor
		if de != nil || json.Unmarshal(b, &c) != nil {
			return nil, "", bad(msgInvalidCursor)
		}
		if _, _, _, valid := splitConversationKey(c.Key); !valid || c.Time.IsZero() || !uuidPattern.MatchString(c.Device) {
			return nil, "", bad(msgInvalidCursor)
		}
		args = append(args, c.Time, c.Device, c.Key)
		cursorWhere = fmt.Sprintf(" WHERE (g.last_at,g.device_id,g.group_key)<($%d,$%d::uuid,$%d)", len(args)-2, len(args)-1, len(args))
	}
	return args, cursorWhere, nil
}

func (a *App) shadowConversations(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if e := requireIndividual(r); e != nil {
		return e
	}
	f, e := parseShadowFilter(r.URL.Query())
	if e != nil {
		return e
	}
	limit, offset, e := conversationListPage(r)
	if e != nil {
		return e
	}
	args := append([]any{}, f.Args...)
	// The correlation bridge is resolved over the period alone, not over the rest
	// of the filter. The period is repeated as its own parameters rather than
	// reusing the two the filter happens to add first, so a change of order in
	// parseShadowFilter cannot silently point this window at another column.
	args = append(args, f.From, f.To)
	window := fmt.Sprintf("occurred_at>=$%d AND occurred_at<=$%d", len(args)-1, len(args))
	args, cursorWhere, e := conversationCursorFilter(r, args)
	if e != nil {
		return e
	}
	// Everything the page and its count share. The count query reuses it verbatim so
	// the number under the pager can never describe a different set than the rows.
	countArgs := append([]any{}, args...)
	args = append(args, limit+1, offset)
	groups := `WITH scoped AS (SELECT e.id,e.device_id,e.occurred_at,e.kind,e.action,e.model,e.effort,e.conversation_id,e.correlation_id,jsonb_array_length(e.files)>0 AS has_files` + shadowJoins + `WHERE ` + f.Where + ` AND NOT ` + attachmentOnly("e") + `),
	link AS (SELECT device_id,correlation_id,min(conversation_id) AS conversation_id FROM shadow_events WHERE ` + window + ` AND correlation_id<>'' AND conversation_id<>'' GROUP BY 1,2),
	keyed AS (SELECT s.id,s.device_id,s.occurred_at,s.kind,s.action,s.model,s.effort,s.has_files,
		CASE WHEN s.conversation_id<>'' THEN 'conv:'||s.conversation_id
		     WHEN l.conversation_id IS NOT NULL THEN 'conv:'||l.conversation_id
		     -- No identifier anywhere in the exchange: the correlation the extension
		     -- puts on one submission still holds its prompt, its response and the
		     -- navigation together. Observed on real captures, where every URL is the
		     -- bare provider origin and no conversation identifier is ever produced.
		     WHEN s.correlation_id<>'' THEN 'corr:'||s.correlation_id
		     ELSE 'event:'||s.id::text END AS group_key
		FROM scoped s LEFT JOIN link l ON l.device_id=s.device_id AND l.correlation_id=s.correlation_id AND s.correlation_id<>''),
	g AS (SELECT device_id,group_key,min(occurred_at) AS started_at,max(occurred_at) AS last_at,
		count(*) FILTER (WHERE kind='prompt') AS prompts,
		count(*) FILTER (WHERE kind='response') AS responses,
		count(*) FILTER (WHERE kind='navigation') AS navigations,
		count(*) FILTER (WHERE action='blocked') AS blocked,
		count(*) FILTER (WHERE action='redirected') AS redirected,
		-- Attached to the THREAD, not to the last message: an attachment arrives with
		-- the request, and the thread's last record is most often the response, which
		-- carries none. Reading files off the last message alone would therefore have
		-- displayed "no file" on almost every conversation that has one.
		bool_or(has_files) AS has_attachment,
		(array_agg(id ORDER BY occurred_at DESC,id DESC))[1] AS latest,
		-- The most recent record that names a model, not the model of the most recent
		-- record: a navigation closing the exchange carries none, and the thread still
		-- has one. The value is a label the site displays, so no shape is assumed.
		(array_agg(model ORDER BY occurred_at DESC,id DESC) FILTER (WHERE model<>''))[1] AS model,
		(array_agg(effort ORDER BY occurred_at DESC,id DESC) FILTER (WHERE effort<>''))[1] AS effort
		FROM keyed GROUP BY device_id,group_key
		-- A group carrying no request and no response is a bare navigation: the fact
		-- that a site was opened, not a conversation. Filtered in the aggregate, not
		-- after the page, so the keyset cursor still returns full pages. The records
		-- stay in the database, where they keep the correlation that attaches an
		-- opening prompt and feed the per-service usage figures (product decision,
		-- 2026-09-14).
		HAVING count(*) FILTER (WHERE kind IN ('prompt','response'))>0)
	`
	query := groups + `SELECT ` + shadowProjection + `,g.group_key,g.started_at,g.last_at,g.prompts,g.responses,g.navigations,g.blocked,g.redirected,coalesce(g.has_attachment,false),coalesce(g.model,''),coalesce(g.effort,'')
	FROM g JOIN shadow_events e ON e.device_id=g.device_id AND e.id=g.latest
	JOIN devices d ON d.organization_id=e.organization_id AND d.id=e.device_id
	LEFT JOIN collaborators c ON c.organization_id=e.organization_id AND c.id=e.collaborator_id` + cursorWhere +
		fmt.Sprintf(` ORDER BY g.last_at DESC,g.device_id DESC,g.group_key DESC LIMIT $%d OFFSET $%d`, len(args)-1, len(args))
	rows, e := tx.Query(r.Context(), query, args...)
	if e != nil {
		return e
	}
	defer rows.Close()
	items := []ConversationView{}
	for rows.Next() {
		var v ConversationView
		dest := append(shadowDest(&v.Latest), &v.Key, &v.StartedAt, &v.LastAt, &v.Prompts, &v.Responses, &v.Navigations, &v.Blocked, &v.Redirected, &v.HasAttachment, &v.Model, &v.Effort)
		if e = rows.Scan(dest...); e != nil {
			return e
		}
		finishShadow(&v.Latest)
		items = append(items, v)
	}
	if e = rows.Err(); e != nil {
		return e
	}
	rows.Close()
	next := ""
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1]
		raw, _ := json.Marshal(conversationCursor{last.LastAt, last.Latest.DeviceID, last.Key})
		next = base64.RawURLEncoding.EncodeToString(raw)
	}
	for i := range items {
		if e = protectShadow(r, tx, &items[i].Latest); e != nil {
			return e
		}
	}
	body := map[string]any{"items": items, "next_cursor": next}
	// How many conversations the filter matches, so the console can offer the pages
	// that exist. Counted separately rather than as a window over the page: a page
	// past the end returns no row, and a total carried on the rows would come back
	// as zero exactly when the reader needs it to step back. A cursor names no
	// position in a whole, so it is not answered with one.
	if cursorWhere == "" {
		var total int64
		if e = tx.QueryRow(r.Context(), groups+`SELECT count(*) FROM g`, countArgs...).Scan(&total); e != nil {
			return e
		}
		body["total"] = total
	}
	if e = auditSubjectFilters(r, tx, "conversations", len(items)); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, body)
	return nil
}

// shadowConversation returns one page of a thread, newest page first but ordered
// oldest to newest for reading. It deliberately ignores the list filters: those
// choose which threads are shown, opening one shows all of it.
func (a *App) revealConversationMessage(r *http.Request, tx pgx.Tx, s *Session, m *ThreadMessage, grant, allowed bool) (bool, error) {
	switch {
	case m.Kind == "navigation":
		m.ContentState = ""
	case !allowed:
		m.ContentState = contentIdentity
	case !grant:
		m.ContentState = contentDenied
	case !m.HasContent:
		m.ContentState = contentNotRetained
	default:
		m.ContentState = contentAvailable
	}
	if m.ContentState != contentAvailable {
		return false, nil
	}
	var encrypted []byte
	if e := tx.QueryRow(r.Context(), `SELECT encrypted FROM shadow_content WHERE event_id=$1 AND device_id=$2 AND expires_at>now()`, m.ID, m.DeviceID).Scan(&encrypted); e != nil {
		// Expiry can land between the projection and this read; the honest
		// answer is then that no text is retained, not a failure.
		if e != pgx.ErrNoRows {
			return false, e
		}
		m.ContentState = contentNotRetained
		return false, nil
	}
	plain, oe := a.openShadow(s.OrganizationID, "event:"+m.DeviceID+":"+m.ID, string(encrypted))
	if oe != nil {
		return false, oe
	}
	if e := json.Unmarshal(plain, &m.Content); e != nil {
		return false, e
	}
	return true, nil
}

func (a *App) revealConversationContents(r *http.Request, tx pgx.Tx, s *Session, items []ThreadMessage) (bool, error) {
	grant, e := contentAccessAvailable(r.Context(), tx, s.OrganizationID, s.UserID)
	if e != nil {
		return false, e
	}
	grant = grant && s.contentUnlocked()
	identity, seen := map[string]bool{}, map[string]int{}
	targets := []string{}
	for i := range items {
		m := &items[i]
		seen[m.AuditSubject]++
		if _, done := identity[m.ActorID]; !done {
			allowed, ie := revealed(r, tx, m.ActorID)
			if ie != nil {
				return false, ie
			}
			identity[m.ActorID] = allowed
		}
		decrypted, re := a.revealConversationMessage(r, tx, s, m, grant, identity[m.ActorID])
		if re != nil {
			return false, re
		}
		if !decrypted {
			continue
		}
		targets = append(targets, m.DeviceID+":"+m.ID)
	}
	// One audit line per text actually decrypted, with the same action and target
	// shape as the single event detail, so existing audit queries keep working and
	// reading a thread is not cheaper to account for than reading its messages.
	if e = auditMany(r.Context(), tx, s.OrganizationID, s.UserID, "shadow.content.read", targets); e != nil {
		return false, e
	}
	for actor, count := range seen {
		if e = auditSubjectView(r, tx, actor, "conversation", count); e != nil {
			return false, e
		}
	}
	return grant, nil
}

func (a *App) shadowConversation(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	if e := requireIndividual(r); e != nil {
		return e
	}
	q := r.URL.Query()
	device := q.Get("device_id")
	conversation, correlation, event, ok := splitConversationKey(q.Get("key"))
	if !uuidPattern.MatchString(device) || !ok {
		return bad("A device identity and a conversation key are required.")
	}
	limit := conversationDefault
	if raw := q.Get("limit"); raw != "" {
		var e error
		limit, e = strconv.Atoi(raw)
		if e != nil || limit < 1 || limit > conversationMax {
			return bad(fmt.Sprintf("Limit must be between 1 and %d.", conversationMax))
		}
	}
	args := []any{device}
	var where string
	if event != "" {
		args = append(args, event)
		where = `e.device_id=$1 AND e.id=$2::uuid`
	} else if correlation != "" {
		// An exchange held together by its correlation alone, because nothing in it
		// ever carried a conversation identifier.
		args = append(args, correlation)
		where = `e.device_id=$1 AND e.correlation_id=$2`
	} else {
		args = append(args, conversation)
		// A record whose own identifier is empty belongs here only through the
		// correlation the extension kept across the URL assignment. The bridge is
		// not time bounded: a thread lasts as long as retention keeps it.
		where = `e.device_id=$1 AND (e.conversation_id=$2 OR (e.conversation_id='' AND EXISTS(
			SELECT 1 FROM shadow_events b WHERE b.device_id=e.device_id AND b.correlation_id=e.correlation_id
			AND e.correlation_id<>'' AND b.conversation_id=$2)))`
	}
	if raw := q.Get("cursor"); raw != "" {
		if len(raw) > 400 {
			return bad(msgInvalidCursor)
		}
		b, de := base64.RawURLEncoding.DecodeString(raw)
		var c eventCursor
		if de != nil || json.Unmarshal(b, &c) != nil || c.Time.IsZero() || !uuidPattern.MatchString(c.ID) {
			return bad(msgInvalidCursor)
		}
		args = append(args, c.Time, c.ID)
		where += fmt.Sprintf(" AND (e.occurred_at,e.id)<($%d,$%d::uuid)", len(args)-1, len(args))
	}
	args = append(args, limit+1)
	rows, e := tx.Query(r.Context(), `SELECT `+shadowProjection+shadowJoins+`WHERE `+where+
		fmt.Sprintf(` ORDER BY e.occurred_at DESC,e.id DESC LIMIT $%d`, len(args)), args...)
	if e != nil {
		return e
	}
	defer rows.Close()
	items := []ThreadMessage{}
	for rows.Next() {
		var m ThreadMessage
		if e = rows.Scan(shadowDest(&m.ShadowEventView)...); e != nil {
			return e
		}
		finishShadow(&m.ShadowEventView)
		items = append(items, m)
	}
	if e = rows.Err(); e != nil {
		return e
	}
	rows.Close()
	older := ""
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1]
		raw, _ := json.Marshal(eventCursor{last.OccurredAt, last.ID, last.DeviceID})
		older = base64.RawURLEncoding.EncodeToString(raw)
	}
	if len(items) == 0 {
		return apiError{404, "not_found", "Conversation not found."}
	}
	for i := range items {
		if e = protectShadow(r, tx, &items[i].ShadowEventView); e != nil {
			return e
		}
	}
	// The page is read oldest first, the way the exchange happened.
	for i, j := 0, len(items)-1; i < j; i, j = i+1, j-1 {
		items[i], items[j] = items[j], items[i]
	}
	// Same triple gate as the single event detail: the membership flag, then the
	// key's own content scope, then a live reveal of the actor. A key created to
	// read metadata must not become a content reader because its creator happened
	// to hold the flag.
	grant, e := a.revealConversationContents(r, tx, s, items)
	if e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]any{"key": q.Get("key"), "device_id": device, "items": items, "older_cursor": older, "can_read_content": grant})
	return nil
}
