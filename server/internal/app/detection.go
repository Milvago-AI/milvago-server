package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

//go:embed detection_migration.sql
var detectionMigration string

//go:embed detection_factory.json
var detectionFactory []byte

type DetectionDOM struct {
	Editor   string `json:"editor"`
	Send     string `json:"send"`
	Response string `json:"response"`
}
type DetectionNetwork struct {
	Method   string `json:"method"`
	Host     string `json:"host"`
	Path     string `json:"path"`
	TextPath string `json:"text_path"`
	// Ordered fallbacks for the text, first non-empty wins. A provider can rename
	// the field between the request that opens a conversation and the ones that
	// continue it -- chat.mistral.ai sends content[*].text on create and
	// messageInput[*].text on append -- and a rule carries a single path. Declaring
	// two rules on the same route is not a way out: the engine refuses an ambiguous
	// match outright and observes nothing at all.
	TextPaths []string `json:"text_paths"`
	ModelPath string   `json:"model_path"`
	// The reasoning effort a provider was asked for, where it sends one: "effort"
	// on claude.ai, "thinking_effort" on chatgpt.com -- hence a path per provider
	// rather than a fixed key. Its own field because Go re-marshals what it decoded:
	// a key this struct does not declare is silently dropped on the way to the agent,
	// so a rule could carry an effort_path that never reaches a device.
	EffortPath       string `json:"effort_path"`
	ConversationPath string `json:"conversation_path"`
	// Where the conversation identifier sits in the REQUEST PATH, as a zero-based
	// segment index, for providers that never put it in the body: claude.ai states it
	// only as `/api/organizations/<org>/chat_conversations/<uuid>/completion`. The body
	// path above keeps precedence; this is consulted when it yields nothing. Absent
	// unless a rule needs it, because `Network` refuses unknown fields on the agent:
	// a catalogue published with this segment reaches only agents that already know it.
	ConversationURLSegment *int `json:"conversation_url_segment,omitempty"`
	// Les champs de formulaire qui portent eux-mêmes un document JSON. ChatGPT
	// anonyme/mobile envoie un `application/x-www-form-urlencoded` dont
	// `imageAttachments` et `conversationState` sont des documents entiers ; sans les
	// nommer, aucun chemin ne peut descendre dedans. Nommés plutôt que devinés : un
	// prompt qui se trouve être du JSON deviendrait sinon un objet, et son texte
	// disparaîtrait en silence.
	JSONFields []string `json:"json_fields,omitempty"`
	// Où la requête énonce les noms des fichiers joints. Seule voie là où le composeur
	// n'expose pas de sélecteur de fichiers à intercepter. Jamais leur contenu.
	FilesPath string `json:"files_path,omitempty"`
	// Ce que la route transporte. Absent ou "prompt" : un envoi, que l'observation lit et
	// que le contrôle de contenu soumet au texte approuvé. "file" : un téléversement, que
	// le blocage des envois de fichiers scelle et que l'observation ignore — l'observer
	// produirait un événement de requête à zéro caractère.
	Kind string `json:"kind,omitempty"`
	// `omitempty` sur les deux, comme `conversation_url_segment` et pour la même
	// raison : `Network` refuse les champs inconnus côté agent, donc un catalogue qui
	// les porterait systématiquement serait rejeté en bloc par tout agent antérieur.
}
type DetectionProvider struct {
	ID                  string             `json:"id"`
	Label               string             `json:"label"`
	Domains             []string           `json:"domains"`
	Aliases             []string           `json:"aliases"`
	ConversationPath    string             `json:"conversation_path"`
	ConversationSegment int                `json:"conversation_segment"`
	DOM                 DetectionDOM       `json:"dom"`
	Network             []DetectionNetwork `json:"network"`
	QualifiedAt         string             `json:"qualified_at"`
	// Hôtes que la page du fournisseur a le droit de CHARGER sous contrôle de contenu,
	// en plus de son domaine et de ses sous-domaines : claude.ai sert son interface
	// depuis `assets-proxy.anthropic.com`, un domaine enregistrable différent. Chargé,
	// jamais couvert — ni script de contenu, ni attribution. Mesuré sur le site, jamais
	// supposé. `omitempty` pour la raison donnée sur `Network` : l'agent refuse les
	// champs inconnus, donc les catalogues d'aujourd'hui gardent leurs octets et seul un
	// catalogue qui nomme un hôte porte le champ — après que les agents le connaissent.
	AssetHosts []string `json:"asset_hosts,omitempty"`
}

// DetectionKnownPlatform names an AI platform the fleet may reach without this
// catalogue covering it: no selector, no network rule, nothing read. The endpoint only
// reports that the host was reached, which is inventory, not capture.
//
// It is a section of its own rather than a provider with empty selectors, and that
// separation is the safety property: nothing here ever reaches applyCatalog or
// registerContentScripts, so declaring a platform can never inject a content script
// into a site this edition carries no qualification for -- which is exactly what the
// 2026-09-15 decision closed for Community.
type DetectionKnownPlatform struct {
	ID      string   `json:"id"`
	Label   string   `json:"label"`
	Domains []string `json:"domains"`
	// Path prefixes on those hosts, for a platform living under a path of a domain that
	// is not itself an AI product: github.com/copilot, x.com/i/grok. Absent means the
	// whole host counts. Without it these are all-or-nothing, and taking github.com whole
	// would report every developer in the company as an AI user.
	//
	// `omitempty` for the reason given on Network: the agent refuses unknown fields, so
	// only a catalogue that names a prefix carries the key.
	Paths []string `json:"paths,omitempty"`
}
type DetectionNative struct {
	ID                string   `json:"id"`
	Platform          string   `json:"platform"`
	QualifiedVersions []string `json:"qualified_versions"`
	Parser            string   `json:"parser"`
	TextVersions      []string `json:"telemetry_text_qualified_versions"`
}
type DetectionHeuristics struct {
	Keys      []string `json:"keys"`
	MIMETypes []string `json:"mime_types"`
}
type DetectionContent struct {
	Providers   []DetectionProvider `json:"providers"`
	NativeTools []DetectionNative   `json:"native_tools"`
	Heuristics  DetectionHeuristics `json:"heuristics"`
	// `omitempty` so a catalogue that names no platform keeps the exact bytes older
	// agents already accept: the section reaches a device only once the device knows it.
	KnownPlatforms []DetectionKnownPlatform `json:"known_platforms,omitempty"`
}

// validDetectionTextPaths bounds the fallback list. Four is deliberate: a rule
// naming an unbounded number of paths would have the engine scan one request as
// many times, and no provider observed so far needs more than two. An entry may
// not be empty -- an empty path matches nothing and would silently shorten the
// list without saying so.
func validDetectionTextPaths(paths []string) bool {
	if len(paths) > 4 {
		return false
	}
	for _, p := range paths {
		if p == "" || !validDetectionJSONPath(p) {
			return false
		}
	}
	return true
}

var detectionID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
var detectionPath = regexp.MustCompile(`^/[a-zA-Z0-9/_.\*-]{0,255}$`)
var detectionJSONSegment = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}(\[\*\])?$`)
var detectionFieldName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
var detectionNativeVersion = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

func validDetectionJSONPath(s string) bool {
	if s == "" {
		return true
	}
	parts := strings.Split(s, ".")
	if len(parts) > 12 || len(s) > 256 {
		return false
	}
	for _, v := range parts {
		if !detectionJSONSegment.MatchString(v) || slices.Contains([]string{"__proto__", "constructor", "prototype"}, strings.TrimSuffix(v, "[*]")) {
			return false
		}
	}
	return true
}
func validateDetection(c DetectionContent) error {
	if len(c.Providers) == 0 || len(c.Providers) > 128 || len(c.NativeTools) > 32 || len(c.Heuristics.Keys) > 16 || len(c.Heuristics.MIMETypes) > 8 {
		return bad("Invalid detection catalogue size.")
	}
	ids := map[string]bool{}
	domains := map[string]bool{}
	assetHosts := map[string]bool{}
	for _, p := range c.Providers {
		if !detectionID.MatchString(p.ID) || slices.Contains([]string{"codex", "claude-code", "claude-desktop", "claude-desktop-agent"}, p.ID) || ids[p.ID] || !validMetadata(p.Label, 100) || len(p.Domains) == 0 || len(p.Domains)+len(p.Aliases) > 32 || len(p.Network) > 32 || p.ConversationSegment < 0 || p.ConversationSegment > 16 || len(p.AssetHosts) > 8 {
			return bad("Invalid provider.")
		}
		ids[p.ID] = true
		if p.ConversationPath != "" && (!detectionPath.MatchString(p.ConversationPath) || strings.Count(p.ConversationPath, "*") > 8) {
			return bad("Invalid conversation path.")
		}
		for _, d := range append(append([]string{}, p.Domains...), p.Aliases...) {
			if !domainPattern.MatchString(d) || len(d) > 253 || domains[d] {
				return bad("Invalid or duplicate catalogue domain.")
			}
			domains[d] = true
		}
		// Un hôte d'assets est un nom d'hôte comme les autres, nommé une seule fois dans
		// tout le catalogue. Qu'il ne soit le domaine ou l'alias d'AUCUN fournisseur se
		// vérifie après la boucle, une fois chaque fournisseur déclaré.
		for _, h := range p.AssetHosts {
			if !domainPattern.MatchString(h) || len(h) > 253 || assetHosts[h] {
				return bad("Invalid or duplicate asset host.")
			}
			assetHosts[h] = true
		}
		for _, s := range []string{p.DOM.Editor, p.DOM.Send, p.DOM.Response} {
			if s != "" && !validMetadata(s, 512) {
				return bad("Invalid DOM selector.")
			}
		}
		if _, e := time.Parse(time.RFC3339, p.QualifiedAt); e != nil {
			return bad("Qualification date required.")
		}
		for _, n := range p.Network {
			if !slices.Contains([]string{"POST", "PUT"}, n.Method) || !domainPattern.MatchString(n.Host) || (!slices.Contains(p.Domains, n.Host) && !slices.Contains(p.Aliases, n.Host)) || !detectionPath.MatchString(n.Path) || strings.Count(n.Path, "*") > 8 || !validDetectionJSONPath(n.TextPath) || !validDetectionTextPaths(n.TextPaths) || !validDetectionJSONPath(n.ModelPath) || !validDetectionJSONPath(n.EffortPath) || !validDetectionJSONPath(n.ConversationPath) {
				return bad("Invalid network rule.")
			}
			if !validDetectionJSONPath(n.FilesPath) || len(n.JSONFields) > 4 || !slices.Contains([]string{"", "prompt", "file"}, n.Kind) {
				return bad("Invalid network rule.")
			}
			for _, field := range n.JSONFields {
				// Un nom de champ, pas un chemin : le déballage ne vaut qu'à la racine
				// du corps, là où un formulaire place ses champs. Même forme qu'un
				// segment de chemin — les champs réels sont en casse mixte
				// (`imageAttachments`) — et les trois noms qui atteindraient le
				// prototype sont refusés ici comme ils le sont dans le moteur.
				if !detectionFieldName.MatchString(field) || slices.Contains([]string{"__proto__", "constructor", "prototype"}, field) {
					return bad("Invalid JSON field name.")
				}
			}
			if n.ConversationURLSegment != nil && (*n.ConversationURLSegment < 0 || *n.ConversationURLSegment > 16) {
				return bad("Invalid conversation segment.")
			}
		}
	}
	for h := range assetHosts {
		// Une page couverte autorisée à appeler le site d'un autre fournisseur emporterait
		// de la donnée d'un fournisseur à l'autre : un hôte d'assets n'est jamais couvert.
		if domains[h] {
			return bad("An asset host cannot be a covered domain.")
		}
	}
	for _, n := range c.NativeTools {
		if !slices.Contains([]string{"claude-code", "codex", "claude-desktop"}, n.ID) || !slices.Contains([]string{"windows", "linux"}, n.Platform) || !slices.Contains([]string{"otlp-v1", "claude-desktop-v1"}, n.Parser) || len(n.QualifiedVersions) > 128 || len(n.TextVersions) > 128 {
			return bad("Unknown compiled native parser.")
		}
		for _, list := range [][]string{n.QualifiedVersions, n.TextVersions} {
			for _, v := range list {
				if len(v) > 64 || !detectionNativeVersion.MatchString(v) {
					return bad("Invalid native version.")
				}
			}
		}
		// No raw-text qualification has yet been demonstrated on a real managed tool.
		if len(n.TextVersions) > 0 {
			return apiError{409, "qualification_required", "Raw telemetry text requires a qualified engine release."}
		}
	}
	// Known platforms are checked for internal consistency only. A domain appearing both
	// here and in `providers` is NOT refused: gemini.google.com is a covered provider in
	// Enterprise and is not one in Community, where presence is exactly what is asked for,
	// and a published catalogue carries the same bytes to both. Refusing the overlap would
	// make a document valid on one side and impossible on the other. The overlap is
	// resolved where the catalogue is consumed instead -- a covered provider silences the
	// presence path for that host, on the endpoint and again in detectionEventBatch.authorize.
	if len(c.KnownPlatforms) > 256 {
		return bad("Invalid known platform count.")
	}
	platformIDs, platformDomains := map[string]bool{}, map[string]bool{}
	for _, p := range c.KnownPlatforms {
		if !detectionID.MatchString(p.ID) || platformIDs[p.ID] || !validMetadata(p.Label, 100) || len(p.Domains) == 0 || len(p.Domains) > 8 || len(p.Paths) > 8 {
			return bad("Invalid known platform.")
		}
		platformIDs[p.ID] = true
		for _, d := range p.Domains {
			if !domainPattern.MatchString(d) || len(d) > 253 || platformDomains[d] {
				return bad("Invalid or duplicate known platform domain.")
			}
			platformDomains[d] = true
		}
		for _, path := range p.Paths {
			if !detectionPath.MatchString(path) || strings.Count(path, "*") > 8 {
				return bad("Invalid known platform path.")
			}
		}
	}
	for _, k := range c.Heuristics.Keys {
		if !detectionID.MatchString(k) {
			return bad("Invalid heuristic key.")
		}
	}
	for _, m := range c.Heuristics.MIMETypes {
		if !slices.Contains([]string{"text/event-stream", "application/json"}, m) {
			return bad("Invalid heuristic MIME type.")
		}
	}
	return nil
}

// detectionDecoded memoizes the last decoded catalogue. One slot, not a map: every
// caller reads the latest revision, so the slot hits on every request but the first
// after a publication, and there is nothing to bound or evict.
//
// Keyed on the SHA-256 of the bytes, deliberately NOT on the revision. The revision is
// a sequence in one database and this process serves several: the test harness drops
// the schema between cases, so revision 1 names a different document each time, and
// the built-in upgrade rewrites the content of an existing revision in place. A
// revision key would serve a stale document, and under `go test -shuffle=on` it would
// do so intermittently. A digest is a pure function of the bytes actually decoded, so
// a hit can only return the decode of exactly those bytes.
//
// A Go struct copy shares its slices' backing arrays, so handing the memo out by
// value alone would let any caller write through c.Providers[i] and corrupt every
// later request in the process -- silently, and across organizations. No caller does
// that today, but a comment is not a guard: cloneDetection below makes the copy real,
// and TestDecodedDetectionIsNotMutableThroughItsCopies proves it stays real. Cloning a
// dozen slices is still far cheaper than the strict double decode plus validation it
// replaces.
var detectionDecoded struct {
	mu      sync.Mutex
	digest  [32]byte
	content DetectionContent
	valid   bool
}

// cloneDetection returns a copy that shares no backing array with its argument, so a
// caller may write through it without reaching the memo. Every slice the document
// carries is cloned, at every depth it has.
func cloneDetection(c DetectionContent) DetectionContent {
	out := c
	out.Heuristics.Keys = slices.Clone(c.Heuristics.Keys)
	out.Heuristics.MIMETypes = slices.Clone(c.Heuristics.MIMETypes)
	out.Providers = slices.Clone(c.Providers)
	for i, p := range out.Providers {
		out.Providers[i].Domains = slices.Clone(p.Domains)
		out.Providers[i].Aliases = slices.Clone(p.Aliases)
		out.Providers[i].AssetHosts = slices.Clone(p.AssetHosts)
		out.Providers[i].Network = slices.Clone(p.Network)
		for j, n := range out.Providers[i].Network {
			out.Providers[i].Network[j].TextPaths = slices.Clone(n.TextPaths)
			out.Providers[i].Network[j].JSONFields = slices.Clone(n.JSONFields)
			// A slice clone copies this struct by value, and the struct carries a
			// pointer: without this the memo and every copy handed to a caller share
			// the same *int. The shipped factory catalogue sets it on one rule, so
			// the sharing is real, not hypothetical. Found by an adversarial review
			// on 2026-09-21; the clone's contract said otherwise.
			if n.ConversationURLSegment != nil {
				segment := *n.ConversationURLSegment
				out.Providers[i].Network[j].ConversationURLSegment = &segment
			}
		}
	}
	out.NativeTools = slices.Clone(c.NativeTools)
	for i, n := range out.NativeTools {
		out.NativeTools[i].QualifiedVersions = slices.Clone(n.QualifiedVersions)
		out.NativeTools[i].TextVersions = slices.Clone(n.TextVersions)
	}
	out.KnownPlatforms = slices.Clone(c.KnownPlatforms)
	for i, k := range out.KnownPlatforms {
		out.KnownPlatforms[i].Domains = slices.Clone(k.Domains)
		out.KnownPlatforms[i].Paths = slices.Clone(k.Paths)
	}
	return out
}

// decodedDetection is decodeDetection behind that memo.
func decodedDetection(raw []byte) (DetectionContent, error) {
	digest := sha256.Sum256(raw)
	detectionDecoded.mu.Lock()
	hit, cached := detectionDecoded.valid && detectionDecoded.digest == digest, detectionDecoded.content
	detectionDecoded.mu.Unlock()
	if hit {
		return cloneDetection(cached), nil
	}
	// Decoded outside the lock: two concurrent misses both decode and the last writer
	// wins, which is harmless because the results are byte-identical.
	c, e := decodeDetection(raw)
	if e != nil {
		return c, e
	}
	detectionDecoded.mu.Lock()
	detectionDecoded.digest, detectionDecoded.content, detectionDecoded.valid = digest, cloneDetection(c), true
	detectionDecoded.mu.Unlock()
	return c, nil
}

func decodeDetection(raw []byte) (DetectionContent, error) {
	var c DetectionContent
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > 512*1024 {
		return c, bad("Catalogue exceeds size limit.")
	}
	if e := d.Decode(&c); e != nil {
		return c, bad("Invalid catalogue document.")
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return c, bad("One catalogue document is required.")
	}
	normalizeDetectionLists(&c)
	return c, validateDetection(c)
}

// The edition decides which providers it covers, and Community qualifies the two it
// ships a browser package for. The narrowing happens where a catalogue is *created* --
// the built-in one at startup -- never where one is read: a published or imported
// document keeps the bytes it was signed with, and the Community extension refuses on
// its own the providers it carries no selectors for.
// Known platforms are deliberately NOT narrowed here. Presence is inventory without
// capture -- a host name reached, nothing read -- and an administrator has to see the AI
// their people use whichever edition they bought. It is the same reasoning that opened
// model observation to both editions on 2026-09-14, and it reopens nothing: the section
// never reaches applyCatalog or registerContentScripts.
func restrictEditionProviders(c *DetectionContent) {
	if editionProviders == nil {
		return
	}
	kept := []DetectionProvider{}
	for _, p := range c.Providers {
		if slices.Contains(editionProviders, p.ID) {
			kept = append(kept, p)
		}
	}
	c.Providers = kept
}

// A Go nil slice marshals as `null`, and the agent's serde structs declare their lists
// as `Vec`: `#[serde(default)]` covers a key that is *absent*, never one that is
// present and null. Re-marshalling a catalogue whose rule omits `text_paths` therefore
// produced a document every deployed agent refused — silently, because the refusal is
// logged below the default level and `health` does not look at the catalogue. Found the
// hard way on 2026-09-14: a device stayed three revisions behind for hours while every
// indicator said it was fine.
//
// Normalising here rather than on the agent is deliberate: it repairs the devices
// already in the field without shipping them anything.
func normalizeDetectionLists(c *DetectionContent) {
	list := func(s []string) []string {
		if s == nil {
			return []string{}
		}
		return s
	}
	if c.Providers == nil {
		c.Providers = []DetectionProvider{}
	}
	if c.NativeTools == nil {
		c.NativeTools = []DetectionNative{}
	}
	c.Heuristics.Keys = list(c.Heuristics.Keys)
	c.Heuristics.MIMETypes = list(c.Heuristics.MIMETypes)
	for i := range c.Providers {
		p := &c.Providers[i]
		p.Domains, p.Aliases = list(p.Domains), list(p.Aliases)
		if p.Network == nil {
			p.Network = []DetectionNetwork{}
		}
		for j := range p.Network {
			p.Network[j].TextPaths = list(p.Network[j].TextPaths)
		}
	}
	for i := range c.NativeTools {
		c.NativeTools[i].QualifiedVersions = list(c.NativeTools[i].QualifiedVersions)
		c.NativeTools[i].TextVersions = list(c.NativeTools[i].TextVersions)
	}
	// Domains follow the rule above; Paths deliberately does not. It is `omitempty`, so
	// turning nil into [] would add a key to every platform and hand older agents a
	// document they refuse -- the very outage this function exists to prevent.
	for i := range c.KnownPlatforms {
		c.KnownPlatforms[i].Domains = list(c.KnownPlatforms[i].Domains)
	}
}
func initializeDetection(ctx context.Context, tx pgx.Tx, role string) error {
	// Serialize startup replacement with owner/import publication before any DDL
	// takes table locks: an edited catalog must remain the latest revision.
	if _, e := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(726403212)"); e != nil {
		return e
	}
	if _, e := tx.Exec(ctx, detectionMigration); e != nil {
		return e
	}
	c, e := decodeDetection(detectionFactory)
	if e != nil {
		return e
	}
	restrictEditionProviders(&c)
	raw, _ := json.Marshal(c)
	sum := sha256.Sum256(raw)
	if _, e = tx.Exec(ctx, `INSERT INTO detection_catalogs(content,content_hash,source) SELECT $1,$2,'builtin' WHERE NOT EXISTS(SELECT 1 FROM detection_catalogs)`, raw, hex.EncodeToString(sum[:])); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO detection_catalogs(content,content_hash,source) SELECT $1,$2,'builtin' WHERE (SELECT source='builtin' AND content_hash<>$2 FROM detection_catalogs ORDER BY revision DESC LIMIT 1)`, raw, hex.EncodeToString(sum[:])); e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `GRANT SELECT,INSERT ON detection_catalogs TO `+role+`; GRANT USAGE ON SEQUENCE detection_catalogs_revision_seq TO `+role+`; GRANT SELECT,INSERT,UPDATE,DELETE ON detector_health,candidate_domains,muted_platforms TO `+role)
	return e
}

// mutedPlatformSet reads the platforms this organization has silenced in Discovery.
// Both readers below used to carry the same thirteen lines. The cursor is closed before
// returning because each caller then queries the same transaction, and pgx keeps the
// connection busy while one is open.
func mutedPlatformSet(ctx context.Context, tx pgx.Tx) (map[string]bool, error) {
	rows, e := tx.Query(ctx, "SELECT platform_id FROM muted_platforms")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if e := rows.Scan(&id); e != nil {
			return nil, e
		}
		out[id] = true
	}
	return out, rows.Err()
}

// currentDetectionRaw answers the latest catalogue as stored: its revision and the
// bytes that were signed. It does not decode. Three callers never look at the
// document -- the device-facing route signs the raw bytes, publication and import only
// compare revisions -- and decoding a 26 KiB document strictly, twice, to throw it
// away was the whole cost of those requests.
func currentDetectionRaw(ctx context.Context, tx pgx.Tx) (int64, []byte, error) {
	var rev int64
	var raw []byte
	e := tx.QueryRow(ctx, "SELECT revision,content FROM detection_catalogs ORDER BY revision DESC LIMIT 1").Scan(&rev, &raw)
	return rev, raw, e
}

func currentDetection(ctx context.Context, tx pgx.Tx) (int64, []byte, DetectionContent, error) {
	rev, raw, e := currentDetectionRaw(ctx, tx)
	if e != nil {
		return 0, nil, DetectionContent{}, e
	}
	c, e := decodedDetection(raw)
	return rev, raw, c, e
}
func isInstanceOwner(ctx context.Context, tx pgx.Tx, s *Session) bool {
	// A machine credential is never the instance owner, whatever its holder is: the
	// answer travels into /api/session, which a model reads through MCP.
	if s.pinned() || s.Role != "owner" {
		return false
	}
	var root string
	return tx.QueryRow(ctx, "SELECT organization_id FROM app_config").Scan(&root) == nil && root == s.OrganizationID
}
func (a *App) getDetectionCatalog(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	rev, _, c, e := currentDetection(r.Context(), tx)
	if e != nil {
		return e
	}
	reply(w, 200, map[string]any{"revision": rev, "content": c, "can_publish": isInstanceOwner(r.Context(), tx, s)})
	return nil
}
func (a *App) publishDetectionCatalog(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	// Hand-editing a catalogue is a maintenance path, closed unless the operator asked
	// for it. The refusal is the one a non-owner already gets, and comes first, so the
	// answer never tells a caller whether this instance runs with the flag: a probe
	// learns "not you", never "not here". The automatic publisher import
	// (importPublisher) is a different path and stays open -- the flag must not be able
	// to freeze detector corrections on a running instance.
	if !a.config.ConsoleDebug {
		return forbidden()
	}
	if !isInstanceOwner(r.Context(), tx, s) {
		return forbidden()
	}
	if e := a.requireFreshMFA(r, tx, s); e != nil {
		return e
	}
	var b struct {
		Revision int64            `json:"revision"`
		Content  DetectionContent `json:"content"`
	}
	if e := decode(w, r, &b); e != nil {
		return e
	}
	if e := validateDetection(b.Content); e != nil {
		return e
	}
	if _, e := tx.Exec(r.Context(), "SELECT pg_advisory_xact_lock(726403212)"); e != nil {
		return e
	}
	rev, _, e := currentDetectionRaw(r.Context(), tx)
	if e != nil {
		return e
	}
	if rev != b.Revision {
		return apiError{409, "revision_conflict", "Catalogue changed. Reload before publishing."}
	}
	// Omitted lists become [] rather than null, as on every other path: an agent
	// refuses a catalogue with a null list, which took the whole fleet's detection down.
	normalizeDetectionLists(&b.Content)
	raw, _ := json.Marshal(b.Content)
	if len(raw) > 512*1024 {
		return bad("Catalogue exceeds size limit.")
	}
	digest := sha256.Sum256(raw)
	if e = tx.QueryRow(r.Context(), `INSERT INTO detection_catalogs(content,content_hash,source) VALUES($1,$2,'edited') RETURNING revision`, raw, hex.EncodeToString(digest[:])).Scan(&rev); e != nil {
		return e
	}
	if e = privacyAudit(r, tx, s, "detection.catalog.publish", "instance", map[string]any{"revision": rev, "content_hash": hex.EncodeToString(digest[:])}); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]any{"revision": rev, "content": b.Content, "can_publish": true})
	return nil
}
func (a *App) deviceDetectionCatalog(w http.ResponseWriter, r *http.Request) {
	tx, org, _, e := a.deviceTx(r)
	if e != nil {
		a.fail(w, e)
		return
	}
	defer tx.Rollback(r.Context())
	rev, raw, e := currentDetectionRaw(r.Context(), tx)
	if e != nil {
		a.fail(w, e)
		return
	}
	digest := sha256.Sum256(raw)
	now := time.Now().UTC()
	header, _ := json.Marshal(map[string]any{"kind": "detection_catalog", "schema": 1, "revision": rev, "issued_at": now, "expires_at": now.Add(24 * time.Hour), "min_engine": map[string]string{"extension": "0.5.0", "bridge": "0.5.0"}, "content_hash": hex.EncodeToString(digest[:]), "content": base64.StdEncoding.EncodeToString(raw)})
	signature := ed25519.Sign(a.policyKey(org), header)
	if e = tx.Commit(r.Context()); e != nil {
		a.fail(w, e)
		return
	}
	reply(w, 200, map[string]string{"payload": base64.StdEncoding.EncodeToString(header), "signature": base64.StdEncoding.EncodeToString(signature)})
}

type DetectorCounters struct {
	Provider    string `json:"provider"`
	Navigations int64  `json:"navigations"`
	Network     int64  `json:"prompts_network"`
	DOM         int64  `json:"prompts_dom"`
	Responses   int64  `json:"responses_dom"`
	Candidates  int64  `json:"candidates"`
}
type CandidateCounter struct {
	Domain  string   `json:"domain"`
	Signals []string `json:"signals"`
	Count   int64    `json:"count"`
}
type DetectorBatch struct {
	ID               string             `json:"id"`
	Tool             string             `json:"tool"`
	ExtensionVersion string             `json:"extension_version"`
	CatalogRevision  int64              `json:"catalog_revision"`
	CatalogState     string             `json:"catalog_state"`
	Start            time.Time          `json:"window_start"`
	End              time.Time          `json:"window_end"`
	Providers        []DetectorCounters `json:"providers"`
	Candidates       []CandidateCounter `json:"candidates"`
}
type CollectorHealth struct {
	Tool         string     `json:"tool"`
	State        string     `json:"state"`
	Version      string     `json:"version,omitempty"`
	LastOK       *time.Time `json:"last_ok_at,omitempty"`
	SkippedTrees int64      `json:"skipped_trees"`
	Tampered     int64      `json:"managed_config_tampered"`
}

func (a *App) acceptDetectorHealth(r *http.Request, tx pgx.Tx, org, device string, batches []DetectorBatch) ([]string, error) {
	if len(batches) > 8 {
		return nil, bad("Too many detector batches.")
	}
	p, e := a.readPrivacy(r.Context(), tx, org)
	if e != nil {
		return nil, e
	}
	accepted := []string{}
	now := time.Now()
	for _, b := range batches {
		if !uuidPattern.MatchString(b.ID) || !slices.Contains(browserTools, b.Tool) || !versionPattern.MatchString(b.ExtensionVersion) || b.CatalogRevision < 0 || !slices.Contains([]string{"ok", "missing", "stale"}, b.CatalogState) || b.Start.IsZero() || b.Start.After(b.End) || b.End.Sub(b.Start) > 24*time.Hour || b.End.After(now.Add(time.Minute)) || b.Start.Before(now.Add(-30*24*time.Hour)) || len(b.Providers) > 128 || len(b.Candidates) > 128 {
			return nil, bad("Invalid detector batch.")
		}
		seenProviders := map[string]bool{}
		for _, c := range b.Providers {
			if seenProviders[c.Provider] {
				return nil, bad("Duplicate detector provider.")
			}
			seenProviders[c.Provider] = true
			if !detectionID.MatchString(c.Provider) {
				return nil, bad("Invalid detector provider.")
			}
			for _, n := range []int64{c.Navigations, c.Network, c.DOM, c.Responses, c.Candidates} {
				if n < 0 || n > 1000000 {
					return nil, bad("Invalid detector counter.")
				}
			}
		}
		if !p.Config.DiscoveryEnabled {
			b.Candidates = nil
		}
		for _, c := range b.Candidates {
			if !domainPattern.MatchString(c.Domain) || len(c.Domain) > 253 || slices.Contains(p.Config.IgnoredDomains, c.Domain) || sameServerDomain(a.config.PublicURL, c.Domain) || sameServerDomain(a.config.AppURL, c.Domain) || c.Count < 1 || c.Count > 1000000 || len(c.Signals) == 0 || len(c.Signals) > 2 {
				return nil, bad("Invalid discovery candidate.")
			}
			for _, signal := range c.Signals {
				if !slices.Contains([]string{"json_keys", "sse"}, signal) {
					return nil, bad("Invalid discovery signal.")
				}
			}
		}
		raw, _ := json.Marshal(b)
		tag, e := tx.Exec(r.Context(), `INSERT INTO detector_health(organization_id,device_id,id,payload) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, org, device, b.ID, raw)
		if e != nil {
			return nil, e
		}
		if tag.RowsAffected() == 0 {
			var identical bool
			if e = tx.QueryRow(r.Context(), "SELECT payload=$4::jsonb FROM detector_health WHERE organization_id=$1 AND device_id=$2 AND id=$3", org, device, b.ID, raw).Scan(&identical); e != nil {
				return nil, e
			}
			if !identical {
				return nil, bad("A health batch identity cannot change its payload.")
			}
		}
		if tag.RowsAffected() > 0 {
			for _, c := range b.Candidates {
				_, e = tx.Exec(r.Context(), `INSERT INTO candidate_domains(organization_id,domain,count,first_seen,last_seen) VALUES($1,$2,$3,$4,$4) ON CONFLICT(organization_id,domain) DO UPDATE SET count=candidate_domains.count+excluded.count,last_seen=greatest(candidate_domains.last_seen,excluded.last_seen)`, org, c.Domain, c.Count, b.End)
				if e != nil {
					return nil, e
				}
			}
		}
		accepted = append(accepted, b.ID)
	}
	return accepted, nil
}

// detectorSample is what one provider, under one catalogue revision, showed in
// the observation window: how many devices navigated to it (the denominator),
// the counters they reported, and the prompts seen in the seven days before the
// window (the reference for "it used to work").
type detectorSample struct{ Devices, Navigations, Network, DOM, Responses, Previous int64 }

// detectorState is the verdict for one sample. Network capture is the reference
// signal, DOM capture the fragile one, and a verdict is only given once enough
// devices have actually visited the provider: an unvisited provider is
// unmeasured, not degraded.
//
//	insufficient_data  fewer devices than the threshold, or no prompt and no history
//	suspect            devices navigate, nothing is captured, and prompts were captured before
//	degraded_dom       DOM captures fall under the configured share of network captures
//	dom_only           only the DOM captures: the network rule is missing or broken
//	ok                 prompts are captured and the DOM keeps up with the network
func detectorState(v detectorSample, minDevices, domRatioPercent int) string {
	if v.Devices < int64(minDevices) {
		return "insufficient_data"
	}
	if v.Network == 0 && v.DOM == 0 {
		if v.Previous > 0 {
			return "suspect"
		}
		return "insufficient_data"
	}
	if v.Network == 0 {
		return "dom_only"
	}
	if v.DOM*100 < v.Network*int64(domRatioPercent) {
		return "degraded_dom"
	}
	return "ok"
}

// detectorHealth reports, per provider and per catalogue revision, what the fleet
// observed in the configured window, plus the transport itself: a fleet that sent
// no heartbeat is reported as silent, never as "zero prompts".
func (a *App) detectorHealth(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	p, e := a.readPrivacy(r.Context(), tx, s.OrganizationID)
	if e != nil {
		return e
	}
	window := time.Duration(p.Config.HealthWindowHours) * time.Hour
	var reporting, approved int64
	if e = tx.QueryRow(r.Context(), `SELECT (SELECT count(DISTINCT h.device_id) FROM detector_health h JOIN devices d ON d.organization_id=h.organization_id AND d.id=h.device_id WHERE d.status='approved' AND h.received_at>now()-$1::interval),(SELECT count(*) FROM devices WHERE status='approved')`, window).Scan(&reporting, &approved); e != nil {
		return e
	}
	rows, e := tx.Query(r.Context(), `WITH counters AS (
  SELECT h.device_id,coalesce((h.payload->>'catalog_revision')::bigint,0) revision,c->>'provider' provider,
   coalesce((c->>'navigations')::bigint,0) navigations,coalesce((c->>'prompts_network')::bigint,0) network,coalesce((c->>'prompts_dom')::bigint,0) dom,coalesce((c->>'responses_dom')::bigint,0) responses,
   (h.payload->>'window_end')::timestamptz>now()-$1::interval AS current
  FROM detector_health h CROSS JOIN LATERAL jsonb_array_elements(h.payload->'providers') c
  WHERE (h.payload->>'window_end')::timestamptz>now()-$1::interval-interval '7 days'
  AND (h.payload->>'window_end')::timestamptz<=now()+interval '1 minute')
 SELECT provider,revision,
  count(DISTINCT device_id) FILTER(WHERE current AND navigations>0),
  coalesce(sum(navigations) FILTER(WHERE current),0),coalesce(sum(network) FILTER(WHERE current),0),coalesce(sum(dom) FILTER(WHERE current),0),coalesce(sum(responses) FILTER(WHERE current),0),
  coalesce(sum(network+dom) FILTER(WHERE NOT current),0)
 FROM counters GROUP BY provider,revision ORDER BY provider,revision DESC`, window)
	if e != nil {
		return e
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var provider string
		var rev int64
		var v detectorSample
		if e = rows.Scan(&provider, &rev, &v.Devices, &v.Navigations, &v.Network, &v.DOM, &v.Responses, &v.Previous); e != nil {
			return e
		}
		items = append(items, map[string]any{"provider": provider, "catalog_revision": rev, "devices": v.Devices, "navigations": v.Navigations, "network_prompts": v.Network, "dom_prompts": v.DOM, "dom_responses": v.Responses, "previous_prompts": v.Previous, "state": detectorState(v, p.Config.HealthMinDevices, p.Config.HealthDOMRatio)})
	}
	if e = rows.Err(); e != nil {
		return e
	}
	transport := "ok"
	switch {
	case approved > 0 && reporting == 0:
		transport = "no_transport"
	case reporting < approved:
		transport = "partial"
	}
	reply(w, 200, map[string]any{"items": items, "window_hours": p.Config.HealthWindowHours, "thresholds": map[string]int{"min_devices": p.Config.HealthMinDevices, "dom_ratio_percent": p.Config.HealthDOMRatio}, "transport": map[string]any{"state": transport, "devices_reporting": reporting, "devices_approved": approved}})
	return nil
}

// The discovery page reads both halves of "what escapes this catalogue" from here: the
// domains the heuristic proposed, and the known platforms the fleet actually reached.
//
// The platform half stays an aggregate on purpose. Which machine and which OS account
// are behind a visit is read through the conversations view, where protectShadow
// resolves the machine name and holds the account behind the organization's
// pseudonymisation and a time-boxed reveal. Exposing them from a counting query would
// walk around all of it.
//
// The candidate half is drillable in Enterprise since 2026-09-17 (product decision): a
// candidate domain is a host nobody has decided to watch yet, and naming the machines
// that reached it is what turns the row into a decision. That answer has its own route,
// its own gates and its own file — candidateDomainDevices in
// detection_devices_commercial.go — and never widens this listing.
func (a *App) candidateDomains(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	p, e := a.readPrivacy(r.Context(), tx, s.OrganizationID)
	if e != nil {
		return e
	}
	// Under aggregate-only reporting a platform reached by fewer machines than the
	// aggregation threshold names its user by elimination in a small organization, so it
	// is withheld exactly as a report cell is. Outside that mode the same reader already
	// sees the devices themselves.
	floor := 0
	if p.Config.AggregateOnly {
		floor = p.Config.K
	}
	hidden, covered, e := discoveryExclusions(r.Context(), tx)
	if e != nil {
		return e
	}
	return jsonQuery(w, r, tx, `SELECT jsonb_build_object(
 'items',coalesce((SELECT jsonb_agg(c) FROM (SELECT domain,count,first_seen,last_seen,status FROM candidate_domains WHERE domain<>ALL($3) ORDER BY last_seen DESC LIMIT 500) c),'[]'),
 'platforms',coalesce((SELECT jsonb_agg(p) FROM (
   SELECT provider,count(*) visits,count(DISTINCT device_id) devices,count(DISTINCT user_key) FILTER(WHERE user_key<>'') accounts,max(occurred_at) last_seen
   FROM shadow_events WHERE detector='presence' AND provider<>ALL($2) AND provider<>ALL($3) GROUP BY provider HAVING count(DISTINCT device_id)>=$1 ORDER BY max(occurred_at) DESC LIMIT 256) p),'[]'))`, floor, hidden, covered)
}

// discoveryExclusions returns the hosts Discovery must not name: those the organization
// silenced, and those this edition already captures in full. One catalogue read for both,
// since each answer is a projection of the same document.
//
// `muted` is stored by catalogue identifier because an identifier survives a revision that
// adds or drops a domain; the query needs hosts because reducedToPresence keeps the host
// in `provider` and erases platform_id.
//
// `covered` is the edition's own providers, domains and aliases alike. Discovery answers
// "which AI do my people use that I do not watch", so a service the product already reads
// in full has no business on that screen -- reported there it is noise an administrator
// dismisses by hand, every time, for a service that is not a gap. Which providers those
// are is an edition fact: Community captures two, Enterprise nine, and the same published
// catalogue carries both. Settled at consumption, exactly as the presence precedence is.
//
// An empty list matches nothing, which is what `<> ALL` on an empty array already means,
// so neither case needs special handling.
func discoveryExclusions(ctx context.Context, tx pgx.Tx) (muted []string, covered []string, err error) {
	silenced, e := mutedPlatformSet(ctx, tx)
	if e != nil {
		return nil, nil, e
	}
	_, _, cat, e := currentDetection(ctx, tx)
	if e != nil {
		return nil, nil, e
	}
	muted, covered = []string{}, []string{}
	for _, p := range cat.KnownPlatforms {
		if silenced[p.ID] {
			muted = append(muted, p.Domains...)
		}
	}
	restrictEditionProviders(&cat)
	for _, p := range cat.Providers {
		covered = append(covered, p.Domains...)
		covered = append(covered, p.Aliases...)
	}
	return muted, covered, nil
}

// knownPlatformInventory lists what the catalogue names, so an administrator can silence
// a platform the company sanctions. It is the catalogue's own list rather than what has
// been reached: a platform must be silenceable before anyone visits it, not after the
// alert.
func (a *App) knownPlatformInventory(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	_, _, cat, e := currentDetection(r.Context(), tx)
	if e != nil {
		return e
	}
	// Edition narrowing applies to providers only -- known platforms are inventory and
	// reach both editions. It is read here to drop the platforms this edition captures in
	// full: capture wins over presence, so they can never reach Discovery, and listing a
	// switch that decides nothing is worse than listing nothing. Two disappear in
	// Community, seven more in Enterprise (product decision, 2026-09-16).
	//
	// Exact host comparison, deliberately: detectionEventBatch.authorize settles the same
	// precedence with the same comparison, so the screen and the record cannot disagree
	// about whether a platform is covered.
	restrictEditionProviders(&cat)
	covered := map[string]bool{}
	for _, p := range cat.Providers {
		for _, d := range p.Domains {
			covered[d] = true
		}
		for _, d := range p.Aliases {
			covered[d] = true
		}
	}
	muted, e := mutedPlatformSet(r.Context(), tx)
	if e != nil {
		return e
	}
	type platform struct {
		ID      string   `json:"id"`
		Label   string   `json:"label"`
		Domains []string `json:"domains"`
		Paths   []string `json:"paths,omitempty"`
		Muted   bool     `json:"muted"`
	}
	items := []platform{}
	for _, p := range cat.KnownPlatforms {
		if slices.ContainsFunc(p.Domains, func(d string) bool { return covered[d] }) {
			continue
		}
		items = append(items, platform{ID: p.ID, Label: p.Label, Domains: p.Domains, Paths: p.Paths, Muted: muted[p.ID]})
	}
	reply(w, 200, map[string]any{"platforms": items})
	return nil
}

// updateKnownPlatform silences a platform in Discovery, or brings it back. It does not
// bump the shadow revision and nothing is redistributed: this is a reading choice on one
// console screen, not a change to what the fleet detects. Muting through the catalogue
// instead would mean a signed revision and a fleet-wide redelivery on every toggle.
func (a *App) updateKnownPlatform(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	var b struct {
		ID    string `json:"id"`
		Muted bool   `json:"muted"`
	}
	if e := decode(w, r, &b); e != nil {
		return e
	}
	if !detectionID.MatchString(b.ID) {
		return bad("Invalid platform identifier.")
	}
	// An id the catalogue does not carry would store a row nothing ever reads, and the
	// screen would report a platform as silenced while Discovery kept naming it.
	_, _, cat, e := currentDetection(r.Context(), tx)
	if e != nil {
		return e
	}
	if !slices.ContainsFunc(cat.KnownPlatforms, func(p DetectionKnownPlatform) bool { return p.ID == b.ID }) {
		return apiError{404, "not_found", "Platform not found in the published catalogue."}
	}
	action := "detection.platform.shown"
	if b.Muted {
		action = "detection.platform.hidden"
		_, e = tx.Exec(r.Context(), "INSERT INTO muted_platforms(organization_id,platform_id) VALUES($1,$2) ON CONFLICT DO NOTHING", s.OrganizationID, b.ID)
	} else {
		_, e = tx.Exec(r.Context(), "DELETE FROM muted_platforms WHERE platform_id=$1", b.ID)
	}
	if e != nil {
		return e
	}
	if e = audit(r.Context(), tx, s.OrganizationID, s.UserID, action, b.ID); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]bool{"ok": true})
	return nil
}
func (a *App) updateCandidate(w http.ResponseWriter, r *http.Request, tx pgx.Tx, s *Session) error {
	var b struct {
		Domain string `json:"domain"`
		Status string `json:"status"`
	}
	if e := decode(w, r, &b); e != nil {
		return e
	}
	if !domainPattern.MatchString(b.Domain) || !slices.Contains([]string{"new", "ignored", "promoted"}, b.Status) {
		return bad("Invalid candidate update.")
	}
	if b.Status == "promoted" {
		_, _, catalog, err := currentDetection(r.Context(), tx)
		if err != nil {
			return err
		}
		published := false
		for _, provider := range catalog.Providers {
			if slices.Contains(provider.Domains, b.Domain) || slices.Contains(provider.Aliases, b.Domain) {
				published = true
				break
			}
		}
		if !published {
			return apiError{409, "catalog_publication_required", "Publish this domain in the catalogue before promoting the candidate."}
		}
	}
	tag, e := tx.Exec(r.Context(), "UPDATE candidate_domains SET status=$2 WHERE domain=$1", b.Domain, b.Status)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return apiError{404, "not_found", "Candidate not found."}
	}
	if _, e = tx.Exec(r.Context(), "UPDATE shadow_settings SET revision=nextval('shadow_revision') WHERE organization_id=$1", s.OrganizationID); e != nil {
		return e
	}
	if e = audit(r.Context(), tx, s.OrganizationID, s.UserID, "detection.candidate."+b.Status, b.Domain); e != nil {
		return e
	}
	if e = tx.Commit(r.Context()); e != nil {
		return e
	}
	reply(w, 200, map[string]bool{"ok": true})
	return nil
}
func (a *App) registerDetectionRoutes() {
	a.mux.HandleFunc("GET /v3/detection-catalog", a.deviceDetectionCatalog)
	a.console("GET /api/detection/catalog", permPolicyManage, a.getDetectionCatalog)
	a.sessionOnly("PUT /api/detection/catalog", permPolicyManage, a.publishDetectionCatalog)
	a.sessionOnly("POST /api/detection/catalog/import", permPolicyManage, a.importDetectionCatalog)
	a.console("GET /api/detection/health", permPolicyManage, a.detectorHealth)
	a.console("GET /api/detection/candidates", permPolicyManage, a.candidateDomains)
	a.sessionOnly("PATCH /api/detection/candidates", permPolicyManage, a.updateCandidate)
	a.console("GET /api/detection/platforms", permPolicyManage, a.knownPlatformInventory)
	a.sessionOnly("PATCH /api/detection/platforms", permPolicyManage, a.updateKnownPlatform)
}
