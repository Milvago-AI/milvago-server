package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/hkdf"
)

// Sealed content carries the version of the root it was sealed with, and it
// carries it in the envelope rather than in a column. Every reversible ciphertext
// in the product already round-trips through sealShadow/openShadow, so versioning
// the envelope reaches prompt content, deployment keys, installation credentials
// and observability authorization at once, with no migration on any of those
// tables.
const contentEnvelope = "v"

// contentAAD binds the version into the additional data. The version travels
// outside the ciphertext, so without this a relabelled envelope would be a
// well-formed request to open the same bytes under a different key; and a value
// sealed for one version could be replayed as another.
func contentAAD(org, purpose string, version int) []byte {
	return []byte(org + "/" + purpose + "/v" + strconv.Itoa(version))
}

// shadowCipherKey is what the derivation below actually consumes. Nothing else
// varies, so it is the whole cache key.
type shadowCipherKey struct {
	org     string
	version int
}

func (a *App) shadowCipher(org string, version int) (cipher.AEAD, error) {
	id := shadowCipherKey{org, version}
	a.shadowCipherMu.Lock()
	defer a.shadowCipherMu.Unlock()
	if c, ok := a.shadowCiphers[id]; ok {
		return c, nil
	}
	// The version check stays ahead of the insert: an envelope naming an
	// unconfigured version is the one caller-influenced input on this path, and it
	// must never be able to add an entry.
	root, ok := a.config.ContentKeys[version]
	if !ok {
		// No fallback. This used to fall back to the policy signing key seed, which
		// silently conflated two roots with different lifetimes: a missing content
		// key must be a startup or configuration error, not a quiet substitution.
		return nil, fmt.Errorf("content key version %d is not configured", version)
	}
	key := make([]byte, 32)
	if _, e := io.ReadFull(hkdf.New(sha256.New, root, []byte(org), []byte("milvago/shadow-content/v2")), key); e != nil {
		return nil, e
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	c, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	if a.shadowCiphers == nil {
		a.shadowCiphers = map[shadowCipherKey]cipher.AEAD{}
	}
	a.shadowCiphers[id] = c
	return c, nil
}
func (a *App) sealShadow(org, purpose string, plain []byte) (string, error) {
	version := a.config.ContentVersion
	c, e := a.shadowCipher(org, version)
	if e != nil {
		return "", e
	}
	n := make([]byte, c.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return "", e
	}
	// Always the active version: a write is the moment a value moves onto the
	// current key, which is what makes rotation finish by itself for anything the
	// product rewrites (a rotated deployment key, a re-entered export credential).
	return contentEnvelope + strconv.Itoa(version) + "." + base64.StdEncoding.EncodeToString(c.Seal(n, n, plain, contentAAD(org, purpose, version))), nil
}
func (a *App) openShadow(org, purpose, encoded string) ([]byte, error) {
	// The separator decides, not the first byte. Base64 never contains '.', so its
	// absence means the value predates versioning -- whereas testing for a leading
	// "v" first misreads one legacy ciphertext in sixty-four, the ones whose base64
	// happens to start with that letter. Found by the format's own test.
	label, payload, versioned := strings.Cut(encoded, ".")
	if !versioned {
		return nil, errors.New("unversioned encrypted content: sealed before content keys carried a version, and no longer readable")
	}
	digits, ok := strings.CutPrefix(label, contentEnvelope)
	if !ok {
		return nil, errors.New("invalid encrypted content")
	}
	version, e := strconv.Atoi(digits)
	if e != nil || version < 1 {
		return nil, errors.New("invalid encrypted content")
	}
	c, e := a.shadowCipher(org, version)
	if e != nil {
		return nil, e
	}
	raw, e := base64.StdEncoding.DecodeString(payload)
	if e != nil || len(raw) < c.NonceSize() {
		return nil, errors.New("invalid encrypted content")
	}
	return c.Open(nil, raw[:c.NonceSize()], raw[c.NonceSize():], contentAAD(org, purpose, version))
}

type V2Event struct {
	PlatformID     string    `json:"platform_id,omitempty"`
	DecisionReason string    `json:"decision_reason,omitempty"`
	ID             string    `json:"id"`
	Kind           string    `json:"kind"`
	OccurredAt     time.Time `json:"occurred_at"`
	Provider       string    `json:"provider"`
	Source         string    `json:"source"`
	Tool           string    `json:"tool"`
	Model          string    `json:"model,omitempty"`
	Effort         string    `json:"effort,omitempty"`
	// "signed_in" or "signed_out", as the signed catalogue states for the send route the
	// browser observed. Signed-out ChatGPT names no model, so this is what the console
	// shows instead of an empty model.
	Session        string   `json:"session,omitempty"`
	ConversationID string   `json:"conversation_id,omitempty"`
	CorrelationID  string   `json:"correlation_id,omitempty"`
	URL            string   `json:"url,omitempty"`
	Action         string   `json:"action"`
	Characters     int      `json:"characters"`
	Labels         []string `json:"labels"`
	Prompt         *string  `json:"prompt,omitempty"`
	Response       *string  `json:"response,omitempty"`
	// Names of the files attached to a request. Names only, never contents; the
	// signed policy is what turns them on, so a device cannot start sending them.
	Files []string `json:"files,omitempty"`
	// OS account the record belongs to, on a machine where several people sign in:
	// the profile a native record was collected from, or the account behind the
	// browser connection for a browser record (stamped by the agent, never by the
	// extension). Informational, like the device's OS user: it never grants
	// authority and never replaces the verified association.
	User            string `json:"user,omitempty"`
	PolicyRevision  int64  `json:"policy_revision"`
	Detector        string `json:"detector,omitempty"`
	CatalogRevision *int64 `json:"catalog_revision,omitempty"`
	InputTokens     *int64 `json:"input_tokens,omitempty"`
	OutputTokens    *int64 `json:"output_tokens,omitempty"`
	BodyBytes       *int64 `json:"body_bytes,omitempty"`
	CharactersKnown *bool  `json:"characters_known,omitempty"`
}

func normalizeEventURL(raw, provider string) (string, error) {
	if raw == "" {
		return "", nil
	}
	if len(raw) > 2048 {
		return "", bad("URL is too long.")
	}
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.User != nil || !strings.EqualFold(u.Hostname(), provider) || u.Port() != "" {
		return "", bad("Browser URL must use the provider HTTPS origin.")
	}
	path := "/"
	for _, prefix := range []string{"/c/", "/uc/", "/chat/", "/chats/", "/a/chat/s/", "/app/", "/notebook/", "/search/"} {
		if strings.HasPrefix(u.Path, prefix) {
			path = prefix + ":conversation"
			break
		}
	}
	return "https://" + strings.ToLower(u.Hostname()) + path, nil
}

// Vocabularies checked once per event by validateV2, hoisted so a 100-event batch
// does not rebuild the same slice literals on every call.
var eventDetectors = []string{"dom", "network", "both", "otlp", "native_cache", "presence"}
var eventDecisionReasons = []string{"model_denied", "model_unknown", "control_unavailable"}
var eventKinds = []string{"navigation", "prompt", "response"}
var eventActions = []string{"observed", "blocked", "redirected"}
var eventSources = []string{"browser", "native"}
var nativeEventTools = []string{"claude-code", "codex", "claude-desktop", "claude-desktop-agent"}

func validateV2(v *V2Event, now time.Time) error {
	if e := validateEventDetector(v); e != nil {
		return e
	}
	if e := validateEventIdentity(v, now); e != nil {
		return e
	}
	if e := validateEventContent(v); e != nil {
		return e
	}
	var e error
	v.URL, e = normalizeEventURL(v.URL, v.Provider)
	if e != nil {
		return e
	}
	if v.Source == "native" && v.URL != "" {
		return bad("Native records must not contain browser URLs.")
	}
	return nil
}
func validateEventDetector(v *V2Event) error {
	// "presence" is the browser service worker reporting that a known platform was
	// reached, with nothing read from the page. Accepting it here is server-only and
	// backwards compatible; what a record of that kind may carry is decided in
	// detectionEventBatch.authorize, which reduces it whatever the endpoint sent.
	if v.Detector != "" && !slices.Contains(eventDetectors, v.Detector) {
		return bad("Invalid detector.")
	}
	if (v.Detector == "otlp" || v.Detector == "native_cache") && v.Source != "native" {
		return bad("Invalid detector channel.")
	}
	if v.Detector == "presence" && v.Source != "browser" {
		return bad("Invalid detector channel.")
	}
	for _, n := range []*int64{v.CatalogRevision, v.InputTokens, v.OutputTokens, v.BodyBytes} {
		if !validEventMeasurement(n) {
			return bad("Invalid measurement.")
		}
	}
	if v.PlatformID != "" && !modelPlatformShape(v.PlatformID, v.Source) {
		return bad("Invalid platform for this channel.")
	}
	if !validEventDecision(v) {
		return bad("Invalid model decision metadata.")
	}
	return nil
}

func validEventMeasurement(n *int64) bool {
	return n == nil || (*n >= 0 && *n <= 1000000000000)
}

func validEventDecision(v *V2Event) bool {
	return v.DecisionReason == "" || (slices.Contains(eventDecisionReasons, v.DecisionReason) && v.PlatformID != "" && v.Action == "blocked" && v.Kind == "prompt")
}

func validateEventIdentity(v *V2Event, now time.Time) error {
	if !uuidPattern.MatchString(v.ID) || v.OccurredAt.IsZero() || v.OccurredAt.After(now.Add(5*time.Minute)) || v.OccurredAt.Before(now.AddDate(-1, 0, 0)) || v.PolicyRevision < 1 {
		return bad("Invalid event identity, time or policy revision.")
	}
	if !slices.Contains(eventKinds, v.Kind) || !slices.Contains(eventActions, v.Action) || !slices.Contains(eventSources, v.Source) || !categoryPattern.MatchString(v.Tool) || !domainPattern.MatchString(v.Provider) || len(v.Provider) > 100 || v.Characters < 0 || v.Characters > 10000000 || v.Labels == nil || len(v.Labels) > 16 {
		return bad("Invalid event metadata.")
	}
	if Edition == "community" && v.Source != "browser" {
		return forbidden()
	}
	if v.Source == "browser" && !slices.Contains(browserTools, v.Tool) {
		return bad("Browser records require a supported browser identifier.")
	}
	if v.Source == "native" && !slices.Contains(nativeEventTools, v.Tool) {
		return bad("Native conversation collector is not supported.")
	}
	return nil
}

var eventSessions = []string{"", "signed_in", "signed_out"}

func validateEventContent(v *V2Event) error {
	for _, s := range []string{v.Model, v.Effort, v.ConversationID, v.CorrelationID} {
		if s != "" && !validMetadata(s, 200) {
			return bad("Invalid optional metadata.")
		}
	}
	if !slices.Contains(eventSessions, v.Session) {
		return bad("Invalid session state.")
	}
	for _, s := range v.Labels {
		if !categoryPattern.MatchString(s) {
			return bad("Invalid category.")
		}
	}
	if !validEventBodyKind(v) {
		return bad("Content does not match the event kind or exceeds 32 KiB.")
	}
	if e := validateEventFiles(v); e != nil {
		return e
	}
	if v.User != "" && !validOSUser(v.User) {
		return bad("Invalid collected profile.")
	}
	return nil
}

func validateEventFiles(v *V2Event) error {
	if len(v.Files) > 20 || (len(v.Files) > 0 && v.Kind != "prompt") {
		return bad("File names are limited to 20 entries on a request.")
	}
	for _, name := range v.Files {
		if !validEventFileName(name) {
			return bad("Invalid file name.")
		}
	}
	return nil
}

func validEventBodyKind(v *V2Event) bool {
	return (v.Prompt == nil || (v.Kind == "prompt" && len(*v.Prompt) <= 32768)) &&
		(v.Response == nil || (v.Kind == "response" && len(*v.Response) <= 32768))
}

func validEventFileName(name string) bool {
	// Bidi overrides can make one file extension display as another.
	return name != "" && len(name) <= 200 && utf8.ValidString(name) && !strings.ContainsFunc(name, func(c rune) bool {
		return unicode.IsControl(c) || unicode.Is(unicode.Bidi_Control, c) || c == '\u2028' || c == '\u2029'
	})
}

func (a *App) v2Policy(w http.ResponseWriter, r *http.Request) {
	if e := a.v2PolicyRequest(w, r); e != nil {
		a.fail(w, e)
	}
}
func (a *App) v3Policy(w http.ResponseWriter, r *http.Request) {
	if e := a.versionedPolicyRequest(w, r, 3); e != nil {
		a.fail(w, e)
	}
}
func (a *App) v2PolicyRequest(w http.ResponseWriter, r *http.Request) error {
	return a.versionedPolicyRequest(w, r, 2)
}
func (a *App) versionedPolicyRequest(w http.ResponseWriter, r *http.Request, version int) error {
	tx, org, id, e := a.deviceTx(r)
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	settings, e := a.effectiveShadow(r.Context(), tx, org, id)
	if e != nil {
		return e
	}
	var (
		caps          []string
		engineVersion string
	)
	if e = tx.QueryRow(r.Context(), `SELECT capabilities,version FROM devices WHERE id=$1`, id).Scan(&caps, &engineVersion); e != nil {
		return e
	}
	if version < 3 {
		settings.Config = legacyModelConfig(settings.Config)
	}
	rawConfig, _ := json.Marshal(settings.Config)
	var config map[string]json.RawMessage
	_ = json.Unmarshal(rawConfig, &config)
	delete(config, "operations")
	delete(config, "enrollment")
	if !detectionEngineCapable(engineVersion) {
		delete(config, "discovery")
	}
	// Community has no per-model control: the signed policy never carries a rule,
	// so neither the agent nor the extension can be driven into enforcing one.
	if version < 3 || Edition != "commercial" {
		delete(config, "model_access")
	}
	// Blocking a known platform is Enterprise: a Community device is never handed a list.
	if Edition != "commercial" {
		delete(config, "blocked_platforms")
	}
	now := time.Now().UTC()
	raw, e := json.Marshal(map[string]any{"version": version, "revision": settings.Revision, "issued_at": now, "expires_at": now.Add(15 * time.Minute), "config": config, "capabilities": caps})
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
func (a *App) v2Ingest(w http.ResponseWriter, r *http.Request) {
	if e := a.v2IngestRequest(w, r); e != nil {
		a.fail(w, e)
	}
}

// V2Completion names what an outgoing request said about an exchange that was already
// recorded. A prompt is made durable BEFORE it is sent, so that nothing leaves without
// a trace; the conversation identifier, the model and the effort only exist once the
// request itself is on the wire. They arrive here afterwards, against the event the
// agent already stored.
type V2Completion struct {
	ID             string `json:"id"`
	Model          string `json:"model,omitempty"`
	Effort         string `json:"effort,omitempty"`
	ConversationID string `json:"conversation_id,omitempty"`
	BodyBytes      *int64 `json:"body_bytes,omitempty"`
	Session        string `json:"session,omitempty"`
}

func (a *App) v2Complete(w http.ResponseWriter, r *http.Request) {
	if e := a.v2CompleteRequest(w, r); e != nil {
		a.fail(w, e)
	}
}

// v2CompleteRequest fills in what was unknown when the event was written, and only
// that. It is the first production path that touches an existing shadow_events row, so
// it is bounded on every side: a column already carrying a value is never overwritten,
// only the authenticated device's own events are reachable, content and counters are
// out of reach entirely, and a replay changes nothing. The "fill only when empty"
// shape follows the one already in service for invitations (invitations.go).
func validateCompletion(c V2Completion) error {
	for _, s := range []string{c.Model, c.Effort, c.ConversationID} {
		if s != "" && !validMetadata(s, 200) {
			return bad("Invalid optional metadata.")
		}
	}
	if c.BodyBytes != nil && (*c.BodyBytes < 0 || *c.BodyBytes > 1e12) {
		return bad("Invalid measurement.")
	}
	if !slices.Contains(eventSessions, c.Session) {
		return bad("Invalid session state.")
	}
	// An empty completion cannot count as an applied observation.
	if c.Model == "" && c.Effort == "" && c.ConversationID == "" && c.BodyBytes == nil && c.Session == "" {
		return bad("A completion must carry at least one observation.")
	}
	return nil
}

func validateCompletions(completions []V2Completion) error {
	seen := map[string]bool{}
	for _, c := range completions {
		if !uuidPattern.MatchString(c.ID) || seen[c.ID] {
			return bad("Completion identities must be valid and unique within a batch.")
		}
		seen[c.ID] = true
		if e := validateCompletion(c); e != nil {
			return e
		}
	}
	return nil
}

func (a *App) v2CompleteRequest(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Completions []V2Completion `json:"completions"`
	}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	if len(body.Completions) < 1 || len(body.Completions) > 100 {
		return bad("Submit between 1 and 100 completions.")
	}
	if e := validateCompletions(body.Completions); e != nil {
		return e
	}
	tx, org, device, e := a.deviceTx(r)
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	// Observing which model answered is inventory in every edition; the decision is
	// not, and a completion carries none. Community keeps the model, like ingestion.
	applied := []string{}
	for _, c := range body.Completions {
		tag, e := tx.Exec(r.Context(), `UPDATE shadow_events SET
			model=CASE WHEN model='' AND $4<>'' THEN $4 ELSE model END,
			effort=CASE WHEN effort='' AND $5<>'' THEN $5 ELSE effort END,
			conversation_id=CASE WHEN conversation_id='' AND $6<>'' THEN $6 ELSE conversation_id END,
			body_bytes=CASE WHEN body_bytes IS NULL THEN $7 ELSE body_bytes END,
			session=CASE WHEN session='' AND $8<>'' THEN $8 ELSE session END,
			detector=CASE WHEN detector='dom' THEN 'both' ELSE detector END
			WHERE organization_id=$1 AND device_id=$2 AND id=$3`,
			org, device, c.ID, c.Model, c.Effort, c.ConversationID, c.BodyBytes, c.Session)
		if e != nil {
			return e
		}
		// An unknown identity is not an error: the event may have been purged by
		// retention between the send and the completion. It simply applies to nothing.
		if tag.RowsAffected() > 0 {
			applied = append(applied, c.ID)
		}
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]any{"applied_ids": applied})
	return nil
}
func validateIngestEvents(events []V2Event, deviceKind string, now time.Time) ([]string, error) {
	rejected := []string{}
	seen := map[string]bool{}
	for i := range events {
		v := &events[i]
		if !uuidPattern.MatchString(v.ID) || seen[v.ID] {
			return nil, bad("Event identities must be valid and unique within a batch.")
		}
		seen[v.ID] = true
		if v.Source == "native" && deviceKind != "native" {
			return nil, forbidden()
		}
		if err := validateV2(v, now); err != nil {
			var ae apiError
			if !errors.As(err, &ae) || ae.status != http.StatusBadRequest {
				return nil, err
			}
			rejected = append(rejected, v.ID)
		}
	}
	return rejected, nil
}

func eventSensitivity(v V2Event, cfg ShadowSettings) string {
	// Community has no usage sensitivity, so it stores an unknown value.
	if Edition != "commercial" {
		return "unknown"
	}
	sensitivity := "normal"
	sensitiveCategories := cfg.Config.Classification.Browser
	if v.Source == "native" && v.Tool != "claude-desktop" {
		sensitiveCategories = cfg.Config.Classification.Coding
	}
	for _, label := range v.Labels {
		if !slices.Contains(classificationTypes, label) && sensitivity != "sensitive" {
			sensitivity = "unknown"
		}
		if slices.Contains(sensitiveCategories, label) {
			sensitivity = "sensitive"
		}
	}
	return sensitivity
}

type ingestBatchState struct {
	org, device, deviceKind string
	cfg                     ShadowSettings
	retainedAfter           time.Time
	aliasKey                []byte
	catalogues              detectionEventBatch
	writes                  pgx.Batch
	accepted                []string
}

func (a *App) queueIngestEvent(r *http.Request, tx pgx.Tx, state *ingestBatchState, v V2Event) error {
	if v.Source == "native" && state.deviceKind != "native" {
		return forbidden()
	}
	hasContent := v.Prompt != nil || v.Response != nil
	if hasContent && (!state.cfg.Config.Collection.StoreContent || v.PolicyRevision != state.cfg.Revision) {
		return apiError{409, "content_policy_changed", "Refresh the policy and remove unauthorized queued content before retrying."}
	}
	if len(v.Files) > 0 && (!state.cfg.Config.Collection.StoreFileNames || v.PolicyRevision != state.cfg.Revision) {
		return apiError{409, "content_policy_changed", "Refresh the policy and remove unauthorized queued file names before retrying."}
	}
	if v.OccurredAt.Before(state.retainedAfter) {
		state.accepted = append(state.accepted, v.ID)
		return nil
	}
	if e := state.catalogues.authorize(r.Context(), tx, &v); e != nil {
		return e
	}
	return a.sealAndQueueIngestEvent(r, tx, state, v)
}

func (a *App) sealAndQueueIngestEvent(r *http.Request, tx pgx.Tx, state *ingestBatchState, v V2Event) error {
	labels, _ := json.Marshal(v.Labels)
	if v.Files == nil {
		v.Files = []string{}
	}
	files, _ := json.Marshal(v.Files)
	sensitivity := eventSensitivity(v, state.cfg)
	// The digest is taken before sealing so the sealed value remains unlinkable.
	userKey := ""
	if v.User != "" {
		if state.aliasKey == nil {
			aliasKey, e := a.identityAliasKey(r.Context(), tx, state.org)
			if e != nil {
				return e
			}
			state.aliasKey = aliasKey
		}
		userKey = osAccountKey(state.aliasKey, v.User)
	}
	sealedUser, e := a.sealIdentity(state.org, "event-user:"+state.device+":"+v.ID, v.User)
	if e != nil {
		return e
	}
	v.User = sealedUser
	var content []byte
	if v.Prompt != nil || v.Response != nil {
		plain, _ := json.Marshal(map[string]*string{"prompt": v.Prompt, "response": v.Response})
		encrypted, e := a.sealShadow(state.org, "event:"+state.device+":"+v.ID, plain)
		if e != nil {
			return e
		}
		content = []byte(encrypted)
	}
	// Pipeline bounded writes on this transaction's connection. The CTE's
	// RETURNING set keeps content insertion conditional on a NEW event, so a
	// replay cannot recreate purged content or overwrite the original record.
	// Association remains resolved at the event's timestamp under tenant RLS.
	state.writes.Queue(`WITH inserted AS (
 INSERT INTO shadow_events(organization_id,device_id,id,occurred_at,kind,provider,source,tool,model,effort,conversation_id,correlation_id,url,action,characters,labels,policy_revision,collaborator_id,sensitivity,platform_id,decision_reason,files,"user",user_key,detector,catalog_revision,input_tokens,output_tokens,body_bytes,characters_known,session)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
  (SELECT collaborator_id FROM device_collaborators WHERE device_id=$2 AND bound_at<=$18::timestamptz AND expires_at>$18::timestamptz AND expires_at>now()),
  $19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$33)
 ON CONFLICT DO NOTHING RETURNING organization_id,device_id,id
)
INSERT INTO shadow_content(organization_id,device_id,event_id,encrypted,expires_at)
 SELECT organization_id,device_id,id,$31::bytea,now()+make_interval(days=>$32)
 FROM inserted WHERE $31::bytea IS NOT NULL`, state.org, state.device, v.ID, v.OccurredAt, v.Kind, v.Provider, v.Source, v.Tool, v.Model, v.Effort, v.ConversationID, v.CorrelationID, v.URL, v.Action, v.Characters, labels, v.PolicyRevision, v.OccurredAt, sensitivity, v.PlatformID, v.DecisionReason, files, v.User, userKey, v.Detector, v.CatalogRevision, v.InputTokens, v.OutputTokens, v.BodyBytes, v.CharactersKnown == nil || *v.CharactersKnown, content, state.cfg.Config.Collection.ContentRetentionDays, v.Session)
	state.accepted = append(state.accepted, v.ID)
	return nil
}

func (a *App) writeIngestBatch(r *http.Request, tx pgx.Tx, state *ingestBatchState, events []V2Event) error {
	for _, v := range events {
		if e := a.queueIngestEvent(r, tx, state, v); e != nil {
			return e
		}
	}
	if state.writes.Len() == 0 {
		return nil
	}
	return tx.SendBatch(r.Context(), &state.writes).Close()
}

func (a *App) v2IngestRequest(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Events []V2Event `json:"events"`
	}
	if e := decode(w, r, &body); e != nil {
		return e
	}
	if len(body.Events) < 1 || len(body.Events) > 100 {
		return bad("Submit between 1 and 100 events.")
	}
	tx, org, device, e := a.deviceTx(r)
	if e != nil {
		return e
	}
	defer tx.Rollback(r.Context())
	cfg, e := a.effectiveShadow(r.Context(), tx, org, device)
	if e != nil {
		return e
	}
	if !cfg.Config.Collection.Enabled {
		return apiError{403, "collection_disabled", "Collection is disabled for this installation."}
	}
	var deviceKind string
	if e = tx.QueryRow(r.Context(), `SELECT kind FROM devices WHERE id=$1`, device).Scan(&deviceKind); e != nil {
		return e
	}
	// Only authenticated, approved devices receive permanent per-event rejects.
	// Policy, authorization and envelope errors never authorize queue deletion.
	now := time.Now()
	rejected, e := validateIngestEvents(body.Events, deviceKind, now)
	if e != nil {
		return e
	}
	if len(rejected) > 0 {
		reply(w, http.StatusBadRequest, map[string]any{"error": "invalid_event", "message": "Remove only the identified invalid events before retrying.", "rejected_ids": rejected})
		return nil
	}
	// The request holds the privacy and policy barriers until commit. Resolve
	// their effective values once for this bounded batch, not once per event.
	privacy, e := a.readPrivacy(r.Context(), tx, org)
	if e != nil {
		return e
	}
	var retentionDays int
	if e = tx.QueryRow(r.Context(), "SELECT retention_days FROM settings WHERE organization_id=$1 FOR SHARE", org).Scan(&retentionDays); e != nil {
		return e
	}
	retainedAfter := now.Add(-time.Duration(min(retentionDays, privacy.Config.IdentityDays)) * 24 * time.Hour)
	state := ingestBatchState{
		org: org, device: device, deviceKind: deviceKind, cfg: cfg,
		retainedAfter: retainedAfter, accepted: make([]string, 0, len(body.Events)),
	}
	if e = a.writeIngestBatch(r, tx, &state, body.Events); e != nil {
		return e
	}
	if _, e = tx.Exec(r.Context(), `UPDATE devices SET last_seen=now() WHERE id=$1`, device); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]any{"accepted_ids": state.accepted})
	return nil
}
