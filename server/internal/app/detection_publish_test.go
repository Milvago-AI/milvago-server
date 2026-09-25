package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type detectionPublishFixture struct {
	p *projectionFixture

	revision int64
	content  DetectionContent
	target   int
	body     map[string]any
}

func newDetectionPublishFixture(t *testing.T) *detectionPublishFixture {
	t.Helper()
	p := newProjectionFixture(t)
	// The editor is enabled only for the publication scenario.
	p.a.config.ConsoleDebug = true
	ctx := context.Background()
	var revision int64
	if err := p.admin.QueryRow(ctx, "SELECT max(revision) FROM detection_catalogs").Scan(&revision); err != nil {
		t.Fatal(err)
	}
	var content DetectionContent
	if err := json.Unmarshal(detectionFactory, &content); err != nil {
		t.Fatal(err)
	}
	target := -1
	for i, provider := range content.Providers {
		if provider.ID == "chatgpt" {
			target = i
		}
	}
	if target < 0 {
		t.Fatal("the factory catalogue no longer ships a chatgpt provider")
	}
	// Publish a measured rule with all the fields the device must receive.
	content.Providers[target].Network = []DetectionNetwork{{
		Method: "POST", Host: "chatgpt.com", Path: "/backend-api/f/conversation",
		TextPath: "messages[*].content.parts[*]", ModelPath: "model",
		EffortPath: "thinking_effort", ConversationPath: "conversation_id",
		TextPaths: []string{"messageInput[*].text", "content[*].text"},
	}}
	return &detectionPublishFixture{p: p, revision: revision, content: content,
		target: target, body: map[string]any{"revision": revision, "content": content}}
}

func (fixture *detectionPublishFixture) assertStaleRevision(t *testing.T, ctx context.Context) {
	requireHTTP(t, fixture.p.as("owner", "PUT", "/api/detection/catalog", map[string]any{"revision": fixture.revision + 1, "content": fixture.content}), 409)
}

func (fixture *detectionPublishFixture) assertInvalidCatalog(t *testing.T, ctx context.Context) {
	broken := fixture.content
	broken.Providers = append([]DetectionProvider{}, fixture.content.Providers...)
	broken.Providers[fixture.target].Network = []DetectionNetwork{{
		Method: "POST", Host: "chatgpt.com", Path: "/backend-api/conversation",
		// A JSON path may not carry a numeric index, only [*].
		ModelPath: "choices[0].model",
	}}
	requireHTTP(t, fixture.p.as("owner", "PUT", "/api/detection/catalog", map[string]any{"revision": fixture.revision, "content": broken}), 400)
}

func (fixture *detectionPublishFixture) assertTextFallbacks(t *testing.T, ctx context.Context) {
	for _, paths := range [][]string{
		{"a", "b", "c", "d", "e"},
		{"messageInput[*].text", ""},
		{"__proto__.secret"},
		{"choices[0].text"},
	} {
		refused := fixture.content
		refused.Providers = append([]DetectionProvider{}, fixture.content.Providers...)
		refused.Providers[fixture.target].Network = []DetectionNetwork{{
			Method: "POST", Host: "chatgpt.com", Path: "/backend-api/f/conversation", TextPaths: paths,
		}}
		requireHTTP(t, fixture.p.as("owner", "PUT", "/api/detection/catalog", map[string]any{"revision": fixture.revision, "content": refused}), 400)
	}
}

func (fixture *detectionPublishFixture) assertForeignHost(t *testing.T, ctx context.Context) {
	foreign := fixture.content
	foreign.Providers = append([]DetectionProvider{}, fixture.content.Providers...)
	foreign.Providers[fixture.target].Network = []DetectionNetwork{{
		Method: "POST", Host: "api.example.invalid", Path: "/v1/chat", ModelPath: "model",
	}}
	requireHTTP(t, fixture.p.as("owner", "PUT", "/api/detection/catalog", map[string]any{"revision": fixture.revision, "content": foreign}), 400)
}

func (fixture *detectionPublishFixture) assertRequestSizeCeiling(t *testing.T, ctx context.Context) {
	// The request body reaches its 128 KiB limit before the catalog's 512 KiB limit.
	wide := "textarea" + string(bytes.Repeat([]byte("a"), 500))
	big := fixture.content
	big.Providers = append([]DetectionProvider{}, fixture.content.Providers...)
	for i := 0; len(big.Providers) < 128; i++ {
		filler := fixture.content.Providers[fixture.target]
		filler.ID = fmt.Sprintf("filler-%03d", i)
		filler.Label = fmt.Sprintf("Filler %03d", i)
		filler.Domains = []string{fmt.Sprintf("filler-%03d.example.invalid", i)}
		filler.Aliases = nil
		filler.Network = nil
		filler.DOM = DetectionDOM{Editor: wide, Send: wide, Response: wide}
		big.Providers = append(big.Providers, filler)
	}
	requireHTTP(t, fixture.p.as("owner", "PUT", "/api/detection/catalog", map[string]any{"revision": fixture.revision, "content": big}), 400)
}

func assertPublishedRule(t *testing.T, content DetectionContent) {
	t.Helper()
	for _, provider := range content.Providers {
		if provider.ID != "chatgpt" {
			continue
		}
		if len(provider.Network) != 1 {
			t.Fatalf("the published rule did not survive: %+v", provider.Network)
		}
		rule := provider.Network[0]
		if rule.ModelPath != "model" || rule.EffortPath != "thinking_effort" || rule.ConversationPath != "conversation_id" || rule.TextPath != "messages[*].content.parts[*]" {
			t.Fatalf("a field of the rule was dropped in the round trip: %+v", rule)
		}
		if len(rule.TextPaths) != 2 || rule.TextPaths[0] != "messageInput[*].text" || rule.TextPaths[1] != "content[*].text" {
			t.Fatalf("the ordered text fallbacks did not survive: %v", rule.TextPaths)
		}
		return
	}
	t.Fatal("chatgpt missing from the served catalogue")
}

func (fixture *detectionPublishFixture) assertDeviceCatalog(t *testing.T, ctx context.Context, revision int64) {
	credential := randomToken()
	if tag, err := fixture.p.admin.Exec(ctx, "UPDATE devices SET credential_hash=$1 WHERE id=$2", hash(credential), fixture.p.device); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("device credential fixture missing", err)
	}
	request := httptest.NewRequest("GET", "/v3/detection-catalog", nil)
	request.Header.Set("Authorization", "Bearer "+credential)
	served := httptest.NewRecorder()
	fixture.p.a.mux.ServeHTTP(served, request)
	requireHTTP(t, served, 200)
	var envelope publisherEnvelope
	if err := json.Unmarshal(served.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil || !ed25519.Verify(fixture.p.a.policyKey(fixture.p.org).Public().(ed25519.PublicKey), payload, signature) {
		t.Fatal("the served catalogue is not signed for this organization", err)
	}
	var header publisherHeader
	if err = json.Unmarshal(payload, &header); err != nil || header.Revision != revision {
		t.Fatal("the device was served another revision", err, header.Revision, revision)
	}
	bodyBytes, err := base64.StdEncoding.DecodeString(header.Content)
	if err != nil {
		t.Fatal(err)
	}
	// The handler re-marshals omitted lists as [] rather than null.
	normalizeDetectionLists(&fixture.content)
	expected, _ := json.Marshal(fixture.content)
	if !bytes.Equal(bodyBytes, expected) {
		t.Fatal("the served bytes are not the published ones")
	}
	var round DetectionContent
	if err = json.Unmarshal(bodyBytes, &round); err != nil {
		t.Fatal(err)
	}
	assertPublishedRule(t, round)
}

func (fixture *detectionPublishFixture) assertPublished(t *testing.T, ctx context.Context) {
	response := fixture.p.as("owner", "PUT", "/api/detection/catalog", fixture.body)
	requireHTTP(t, response, 200)
	var out struct {
		Revision int64 `json:"revision"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &out); err != nil || out.Revision <= fixture.revision {
		t.Fatal("publication did not advance the revision", err, out.Revision)
	}
	var audited int
	if err := fixture.p.admin.QueryRow(ctx, "SELECT count(*) FROM audit WHERE action='detection.catalog.publish'").Scan(&audited); err != nil || audited != 1 {
		t.Fatal("publication not audited exactly once", err, audited)
	}
	fixture.assertDeviceCatalog(t, ctx, out.Revision)
}

func (fixture *detectionPublishFixture) assertStaleMFA(t *testing.T, ctx context.Context) {
	if tag, err := fixture.p.admin.Exec(ctx, "UPDATE sessions SET mfa_verified_at=clock_timestamp()-interval '6 minutes' WHERE token_hash=$1", hash(fixture.p.owner.Value)); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("stale MFA fixture missing", err)
	}
	var current int64
	if err := fixture.p.admin.QueryRow(ctx, "SELECT max(revision) FROM detection_catalogs").Scan(&current); err != nil {
		t.Fatal(err)
	}
	requireHTTP(t, fixture.p.as("owner", "PUT", "/api/detection/catalog", map[string]any{"revision": current, "content": fixture.content}), 403)
}

// The catalogue edited in the console must reach the device as signed bytes.
func TestDetectionCatalogPublish(t *testing.T) {
	fixture := newDetectionPublishFixture(t)
	ctx := context.Background()
	for _, actor := range []string{"admin", "viewer", "reporter", "key"} {
		t.Run("refuse_"+actor, func(t *testing.T) {
			requireHTTP(t, fixture.p.as(actor, "PUT", "/api/detection/catalog", fixture.body), 403)
		})
	}
	t.Run("a stale revision is refused rather than overwriting a concurrent edit", func(t *testing.T) { fixture.assertStaleRevision(t, ctx) })
	t.Run("an invalid catalogue never reaches the fleet", func(t *testing.T) { fixture.assertInvalidCatalog(t, ctx) })
	t.Run("the text fallbacks are bounded and never empty", func(t *testing.T) { fixture.assertTextFallbacks(t, ctx) })
	t.Run("a network rule on a host the provider does not own is refused", func(t *testing.T) { fixture.assertForeignHost(t, ctx) })
	t.Run("the effective size ceiling is the request body, not the documented catalogue limit", func(t *testing.T) { fixture.assertRequestSizeCeiling(t, ctx) })
	t.Run("a published catalogue reaches a device, signed for its organization", func(t *testing.T) { fixture.assertPublished(t, ctx) })
	t.Run("a stale second factor cannot publish", func(t *testing.T) { fixture.assertStaleMFA(t, ctx) })
}

// The factory catalogue ships twice: once for the extension build and once
// embedded in the server binary. They were byte-identical when this test was
// written and nothing compared them, so editing one and forgetting the other
// would have made the served catalogue disagree with the compiled fallback
// without a single signal.
// MILVAGO_DEBUG decides whether an instance carries the catalogue editor at all. It
// closes the two console routes that write a catalogue, and closes them identically for
// every caller: a root owner with a fresh MFA receives exactly what a plain admin
// receives, so probing the pair cannot read the instance's configuration off the
// difference. Reading stays open, because the discovery page needs the published domains
// to know which candidate is already covered.
//
// The last assertion is the one that matters most. The flag is a noise decision, and a
// noise decision that quietly froze the automatic publisher import would turn a hidden
// editor into a fleet that stops receiving detector corrections — a far worse outage
// than the clutter it removes.
func assertCatalogDebugSession(t *testing.T, p *projectionFixture) {
	t.Helper()
	for _, on := range []bool{false, true} {
		p.a.config.ConsoleDebug = on
		response := p.as("owner", "GET", "/api/session", nil)
		requireHTTP(t, response, 200)
		var session struct {
			ConsoleDebug bool `json:"console_debug"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &session); err != nil {
			t.Fatal(err)
		}
		if session.ConsoleDebug != on {
			t.Fatalf("session reported console_debug=%v with the flag %v", session.ConsoleDebug, on)
		}
	}
	p.a.config.ConsoleDebug = false
}

func assertAutomaticCatalogImport(t *testing.T, p *projectionFixture, ctx context.Context, signed []byte, revision int64) {
	t.Helper()
	publisher := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/detection-catalog/latest" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(signed)
	}))
	defer publisher.Close()
	p.a.config.PublisherURL = publisher.URL
	p.a.config.PublisherCredential = strings.Repeat("x", 40)
	tx, err := tenantTx(ctx, p.a.db, p.org)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err = p.a.importPublisher(ctx, tx, p.org, 0, ""); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var imported int64
	if err = p.admin.QueryRow(ctx, "SELECT max(revision) FROM detection_catalogs").Scan(&imported); err != nil {
		t.Fatal(err)
	}
	if imported <= revision {
		t.Fatal("the flag froze the automatic catalogue import")
	}
}

func TestDetectionCatalogWritesClosedWithoutDebug(t *testing.T) {
	p := newProjectionFixture(t)
	ctx := context.Background()
	if p.a.config.ConsoleDebug {
		t.Fatal("the fixture must keep the closed zero value")
	}
	var revision int64
	if e := p.admin.QueryRow(ctx, "SELECT max(revision) FROM detection_catalogs").Scan(&revision); e != nil {
		t.Fatal(e)
	}
	var content DetectionContent
	if e := json.Unmarshal(detectionFactory, &content); e != nil {
		t.Fatal(e)
	}
	// The automatic publisher delivers an edition-specific signed envelope.
	// Keep this flag test valid under the independent Community capture guard.
	restrictEditionProviders(&content)
	if Edition == "community" {
		content.NativeTools = []DetectionNative{}
	}
	publisherContent, e := json.Marshal(content)
	if e != nil {
		t.Fatal(e)
	}
	signed, key := publisherSigned(t, publisherContent, 10, time.Now().UTC())
	p.a.config.PublisherPublicKey = key
	var envelope publisherEnvelope
	if e := json.Unmarshal(signed, &envelope); e != nil {
		t.Fatal(e)
	}
	for _, route := range []struct {
		name, method, path string
		body               map[string]any
	}{
		{"publish", "PUT", "/api/detection/catalog", map[string]any{"revision": revision, "content": content}},
		{"import", "POST", "/api/detection/catalog/import", map[string]any{"expected_revision": revision, "envelope": envelope, "publish": true}},
	} {
		t.Run(route.name, func(t *testing.T) {
			owner := p.as("owner", route.method, route.path, route.body)
			requireHTTP(t, owner, 403)
			admin := p.as("admin", route.method, route.path, route.body)
			requireHTTP(t, admin, 403)
			if owner.Body.String() != admin.Body.String() {
				t.Fatalf("the refusal discloses the flag: owner %q, admin %q", owner.Body.String(), admin.Body.String())
			}
		})
	}
	t.Run("reading the catalogue stays open", func(t *testing.T) {
		requireHTTP(t, p.as("owner", "GET", "/api/detection/catalog", nil), 200)
	})
	// The console hides the editor on what the session says, so the session has to say
	// it -- and has to say it from the configuration alone. Nothing reads console_debug
	// from a request: this is the only way it travels.
	t.Run("the session carries the flag and follows the configuration", func(t *testing.T) {
		assertCatalogDebugSession(t, p)
	})
	var refused int64
	if e := p.admin.QueryRow(ctx, "SELECT max(revision) FROM detection_catalogs").Scan(&refused); e != nil {
		t.Fatal(e)
	}
	if refused != revision {
		t.Fatalf("a refused write still published revision %d", refused)
	}
	t.Run("the automatic publisher import does not notice the flag", func(t *testing.T) {
		assertAutomaticCatalogImport(t, p, ctx, signed, revision)
	})

}

// The catalogue travels to the agent as bytes this package re-marshals, and the agent
// parses it with serde: `#[serde(default)]` covers a key that is absent, never one that
// is present and null. A Go nil slice marshals as `null`, so a rule that simply omits
// `text_paths` used to produce a document every deployed agent refused — and the refusal
// is invisible at the default log level, so a device silently stayed on an old revision.
//
// This test walks the re-marshalled bytes and refuses any null list, which is what the
// agent's parser refuses too. It would have caught the 2026-09-14 outage before release.
func TestDetectionContentNeverMarshalsNullLists(t *testing.T) {
	for _, name := range []string{"factory", "rule without text_paths"} {
		raw := detectionFactory
		if name != "factory" {
			raw = []byte(`{"providers":[{"id":"p","label":"p","domains":["example.test"],"aliases":[],` +
				`"conversation_path":"/c/*","conversation_segment":1,` +
				`"dom":{"editor":"","send":"","response":""},` +
				`"network":[{"method":"POST","host":"example.test","path":"/x","text_path":"prompt",` +
				`"model_path":"","effort_path":"","conversation_path":""}],` +
				`"qualified_at":"2026-09-11T00:00:00Z"}],"native_tools":[],` +
				`"heuristics":{"keys":[],"mime_types":[]}}`)
		}
		c, e := decodeDetection(raw)
		if e != nil {
			t.Fatalf("%s: the catalogue should decode: %v", name, e)
		}
		out, e := json.Marshal(c)
		if e != nil {
			t.Fatalf("%s: the catalogue should re-marshal: %v", name, e)
		}
		if bytes.Contains(out, []byte(":null")) {
			t.Fatalf("%s: a null list reaches the agent, whose parser refuses it: %s", name, out)
		}
	}
}

// The field precedes the catalogue that will use it: the agent refuses unknown fields, so
// the server has to read it, bound it and stay silent when it is empty -- otherwise
// today's catalogues would change bytes and an earlier agent would refuse them.
func TestDetectionAssetHosts(t *testing.T) {
	provider := func(assetHosts string) []byte {
		return []byte(`{"providers":[{"id":"p","label":"p","domains":["example.test"],"aliases":[],` +
			`"conversation_path":"/c/*","conversation_segment":1,` +
			`"dom":{"editor":"","send":"","response":""},"network":[],` +
			`"qualified_at":"2026-09-11T00:00:00Z"` + assetHosts + `},` +
			`{"id":"q","label":"q","domains":["other.test"],"aliases":[],"conversation_path":"",` +
			`"conversation_segment":0,"dom":{"editor":"","send":"","response":""},"network":[],` +
			`"qualified_at":"2026-09-11T00:00:00Z"}],"native_tools":[],"heuristics":{"keys":[],"mime_types":[]}}`)
	}
	for _, tc := range []struct {
		name, assetHosts string
		ok               bool
	}{
		{"absent", ``, true},
		{"named", `,"asset_hosts":["cdn.example.test"]`, true},
		{"another provider's domain", `,"asset_hosts":["other.test"]`, false},
		{"own domain", `,"asset_hosts":["example.test"]`, false},
		{"malformed", `,"asset_hosts":["not a host"]`, false},
		{"duplicate", `,"asset_hosts":["cdn.example.test","cdn.example.test"]`, false},
		{"too many", `,"asset_hosts":["a1.t","a2.t","a3.t","a4.t","a5.t","a6.t","a7.t","a8.t","a9.t"]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// `decodeDetection` already validates: a refused catalogue never leaves decoding.
			c, e := decodeDetection(provider(tc.assetHosts))
			if (e == nil) != tc.ok {
				t.Fatalf("decode ok=%v, want %v (%v)", e == nil, tc.ok, e)
			}
			if !tc.ok {
				return
			}
			out, e := json.Marshal(c)
			if e != nil {
				t.Fatal(e)
			}
			if bytes.Contains(out, []byte("asset_hosts")) != strings.Contains(tc.assetHosts, "asset_hosts") {
				t.Fatalf("asset_hosts must travel exactly when named, never as an empty list: %s", out)
			}
		})
	}
}
func TestDetectionFactoryCopiesAgree(t *testing.T) {
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test file")
	}
	endpoint := filepath.Join(filepath.Dir(here), "..", "..", "..", "endpoint")
	if _, e := os.Stat(endpoint); errors.Is(e, fs.ErrNotExist) {
		// The server-only repository (milvago-server) carries no endpoint/: no second copy to agree with.
		t.Skip("no endpoint/ in this tree")
	}
	extension := filepath.Join(endpoint, "extension", "detection-factory.json")
	other, e := os.ReadFile(extension)
	if e != nil {
		t.Fatal("the extension copy of the factory catalogue is unreadable", e)
	}
	if !bytes.Equal(bytes.ReplaceAll(other, []byte("\r\n"), []byte("\n")), bytes.ReplaceAll(detectionFactory, []byte("\r\n"), []byte("\n"))) {
		t.Fatalf("server/internal/app/detection_factory.json and %s have diverged; edit both", filepath.Clean(extension))
	}
}
