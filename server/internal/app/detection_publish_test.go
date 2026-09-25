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

// The catalogue edited in the console is the product's own way of teaching the
// fleet where to read a model name, without a new agent or a new installer. Until
// now `publishDetectionCatalog` had no test at all: the only proven round trip was
// the signed vendor import, which is a different handler. This exercises the path
// the Publish button actually takes -- edit, publish, then read it back as a device
// does -- because a catalogue that is stored but never served teaches nothing.
func TestDetectionCatalogPublish(t *testing.T) {
	p := newProjectionFixture(t)
	// The editor is a maintenance path, closed unless the operator asked for it. The
	// fixture keeps the zero value, so the test that exercises publication says so
	// here rather than having the whole suite run with the flag on.
	p.a.config.ConsoleDebug = true
	ctx := context.Background()
	var revision int64
	if e := p.admin.QueryRow(ctx, "SELECT max(revision) FROM detection_catalogs").Scan(&revision); e != nil {
		t.Fatal(e)
	}
	var content DetectionContent
	if e := json.Unmarshal(detectionFactory, &content); e != nil {
		t.Fatal(e)
	}
	// The change under test is exactly the one this chantier needs: naming where a
	// provider's completion request carries the model that answered.
	target := -1
	for i, provider := range content.Providers {
		if provider.ID == "chatgpt" {
			target = i
		}
	}
	if target < 0 {
		t.Fatal("the factory catalogue no longer ships a chatgpt provider")
	}
	// The factory catalogue declares a chatgpt network rule since 2026-09-14; this test
	// publishes its own and asserts what survives the trip, so it replaces whatever is
	// there rather than requiring the slot to be empty. The earlier assertion turned a
	// legitimate catalogue change into a failing suite.
	content.Providers[target].Network = nil
	// Read off the real page on 2026-09-14: the body carries the model and the effort
	// at the root, the text under messages[*].content.parts[*], and the conversation
	// identifier from the second message on. Publishing the rule exactly as it will be
	// written is what proves none of those fields is lost on the way to a device.
	content.Providers[target].Network = []DetectionNetwork{{
		Method: "POST", Host: "chatgpt.com", Path: "/backend-api/f/conversation",
		TextPath: "messages[*].content.parts[*]", ModelPath: "model",
		EffortPath: "thinking_effort", ConversationPath: "conversation_id",
		// Ordered fallbacks, as chat.mistral.ai needs: it renames the text field between
		// the request that opens a conversation and the ones that continue it.
		TextPaths: []string{"messageInput[*].text", "content[*].text"},
	}}
	body := map[string]any{"revision": revision, "content": content}

	for _, actor := range []string{"admin", "viewer", "reporter", "key"} {
		t.Run("refuse_"+actor, func(t *testing.T) {
			requireHTTP(t, p.as(actor, "PUT", "/api/detection/catalog", body), 403)
		})
	}
	t.Run("a stale revision is refused rather than overwriting a concurrent edit", func(t *testing.T) {
		requireHTTP(t, p.as("owner", "PUT", "/api/detection/catalog", map[string]any{"revision": revision + 1, "content": content}), 409)
	})
	t.Run("an invalid catalogue never reaches the fleet", func(t *testing.T) {
		broken := content
		broken.Providers = append([]DetectionProvider{}, content.Providers...)
		broken.Providers[target].Network = []DetectionNetwork{{
			Method: "POST", Host: "chatgpt.com", Path: "/backend-api/conversation",
			// A JSON path may not carry a numeric index, only [*].
			ModelPath: "choices[0].model",
		}}
		requireHTTP(t, p.as("owner", "PUT", "/api/detection/catalog", map[string]any{"revision": revision, "content": broken}), 400)
	})
	t.Run("the text fallbacks are bounded and never empty", func(t *testing.T) {
		for _, paths := range [][]string{
			{"a", "b", "c", "d", "e"},    // five is one too many
			{"messageInput[*].text", ""}, // an empty entry would shorten the list in silence
			{"__proto__.secret"},         // the same reserved names as any other path
			{"choices[0].text"},          // no numeric index, only [*]
		} {
			refused := content
			refused.Providers = append([]DetectionProvider{}, content.Providers...)
			refused.Providers[target].Network = []DetectionNetwork{{
				Method: "POST", Host: "chatgpt.com", Path: "/backend-api/f/conversation", TextPaths: paths,
			}}
			requireHTTP(t, p.as("owner", "PUT", "/api/detection/catalog", map[string]any{"revision": revision, "content": refused}), 400)
		}
	})
	t.Run("a network rule on a host the provider does not own is refused", func(t *testing.T) {
		foreign := content
		foreign.Providers = append([]DetectionProvider{}, content.Providers...)
		foreign.Providers[target].Network = []DetectionNetwork{{
			Method: "POST", Host: "api.example.invalid", Path: "/v1/chat", ModelPath: "model",
		}}
		requireHTTP(t, p.as("owner", "PUT", "/api/detection/catalog", map[string]any{"revision": revision, "content": foreign}), 400)
	})
	t.Run("the effective size ceiling is the request body, not the documented catalogue limit", func(t *testing.T) {
		// publishDetectionCatalog refuses a marshalled catalogue above 512 KiB, but
		// `decode` caps the request body at 128 KiB first, so that branch cannot be
		// reached over HTTP. The ceiling a console user actually meets is 128 KiB,
		// and it answers 400. Pinned so the discrepancy is noticed if either moves.
		// A selector may be 512 characters; three of them per provider, times the 128
		// providers the schema allows, comfortably passes 128 KiB while staying valid.
		wide := "textarea" + string(bytes.Repeat([]byte("a"), 500))
		big := content
		big.Providers = append([]DetectionProvider{}, content.Providers...)
		for i := 0; len(big.Providers) < 128; i++ {
			filler := content.Providers[target]
			filler.ID = fmt.Sprintf("filler-%03d", i)
			filler.Label = fmt.Sprintf("Filler %03d", i)
			filler.Domains = []string{fmt.Sprintf("filler-%03d.example.invalid", i)}
			filler.Aliases = nil
			filler.Network = nil
			filler.DOM = DetectionDOM{Editor: wide, Send: wide, Response: wide}
			big.Providers = append(big.Providers, filler)
		}
		requireHTTP(t, p.as("owner", "PUT", "/api/detection/catalog", map[string]any{"revision": revision, "content": big}), 400)
	})
	t.Run("a published catalogue reaches a device, signed for its organization", func(t *testing.T) {
		w := p.as("owner", "PUT", "/api/detection/catalog", body)
		requireHTTP(t, w, 200)
		var out struct {
			Revision int64 `json:"revision"`
		}
		if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil || out.Revision <= revision {
			t.Fatal("publication did not advance the revision", e, out.Revision)
		}
		var audited int
		if e := p.admin.QueryRow(ctx, "SELECT count(*) FROM audit WHERE action='detection.catalog.publish'").Scan(&audited); e != nil || audited != 1 {
			t.Fatal("publication not audited exactly once", e, audited)
		}
		// Read it back the way an approved device does. A catalogue stored but not
		// served would leave the fleet on the compiled factory table for ever.
		credential := randomToken()
		if tag, e := p.admin.Exec(ctx, "UPDATE devices SET credential_hash=$1 WHERE id=$2", hash(credential), p.device); e != nil || tag.RowsAffected() != 1 {
			t.Fatal("device credential fixture missing", e)
		}
		r := httptest.NewRequest("GET", "/v3/detection-catalog", nil)
		r.Header.Set("Authorization", "Bearer "+credential)
		served := httptest.NewRecorder()
		p.a.mux.ServeHTTP(served, r)
		requireHTTP(t, served, 200)
		var envelope publisherEnvelope
		if e := json.Unmarshal(served.Body.Bytes(), &envelope); e != nil {
			t.Fatal(e)
		}
		payload, e := base64.StdEncoding.DecodeString(envelope.Payload)
		if e != nil {
			t.Fatal(e)
		}
		signature, e := base64.StdEncoding.DecodeString(envelope.Signature)
		if e != nil || !ed25519.Verify(p.a.policyKey(p.org).Public().(ed25519.PublicKey), payload, signature) {
			t.Fatal("the served catalogue is not signed for this organization", e)
		}
		var header publisherHeader
		if e = json.Unmarshal(payload, &header); e != nil || header.Revision != out.Revision {
			t.Fatal("the device was served another revision", e, header.Revision, out.Revision)
		}
		bodyBytes, e := base64.StdEncoding.DecodeString(header.Content)
		if e != nil {
			t.Fatal(e)
		}
		// The handler re-marshals what it validated, with omitted lists written as []
		// rather than null, so compare against that rather than the file bytes.
		normalizeDetectionLists(&content)
		expected, _ := json.Marshal(content)
		if !bytes.Equal(bodyBytes, expected) {
			t.Fatal("the served bytes are not the published ones")
		}
		var round DetectionContent
		if e = json.Unmarshal(bodyBytes, &round); e != nil {
			t.Fatal(e)
		}
		for _, provider := range round.Providers {
			if provider.ID != "chatgpt" {
				continue
			}
			// Go decodes then re-marshals: a field the struct does not declare vanishes
			// here without a word. That is exactly how effort_path was nearly lost.
			if len(provider.Network) != 1 {
				t.Fatalf("the published rule did not survive: %+v", provider.Network)
			}
			rule := provider.Network[0]
			if rule.ModelPath != "model" || rule.EffortPath != "thinking_effort" || rule.ConversationPath != "conversation_id" || rule.TextPath != "messages[*].content.parts[*]" {
				t.Fatalf("a field of the rule was dropped in the round trip: %+v", rule)
			}
			// A slice is as easy to lose as a string, and its order carries meaning.
			if len(rule.TextPaths) != 2 || rule.TextPaths[0] != "messageInput[*].text" || rule.TextPaths[1] != "content[*].text" {
				t.Fatalf("the ordered text fallbacks did not survive: %v", rule.TextPaths)
			}
			return
		}
		t.Fatal("chatgpt missing from the served catalogue")
	})
	t.Run("a stale second factor cannot publish", func(t *testing.T) {
		if tag, e := p.admin.Exec(ctx, "UPDATE sessions SET mfa_verified_at=clock_timestamp()-interval '6 minutes' WHERE token_hash=$1", hash(p.owner.Value)); e != nil || tag.RowsAffected() != 1 {
			t.Fatal("stale MFA fixture missing", e)
		}
		var current int64
		if e := p.admin.QueryRow(ctx, "SELECT max(revision) FROM detection_catalogs").Scan(&current); e != nil {
			t.Fatal(e)
		}
		requireHTTP(t, p.as("owner", "PUT", "/api/detection/catalog", map[string]any{"revision": current, "content": content}), 403)
	})
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
		for _, on := range []bool{false, true} {
			p.a.config.ConsoleDebug = on
			w := p.as("owner", "GET", "/api/session", nil)
			requireHTTP(t, w, 200)
			var session struct {
				ConsoleDebug bool `json:"console_debug"`
			}
			if e := json.Unmarshal(w.Body.Bytes(), &session); e != nil {
				t.Fatal(e)
			}
			if session.ConsoleDebug != on {
				t.Fatalf("session reported console_debug=%v with the flag %v", session.ConsoleDebug, on)
			}
		}
		p.a.config.ConsoleDebug = false
	})
	var refused int64
	if e := p.admin.QueryRow(ctx, "SELECT max(revision) FROM detection_catalogs").Scan(&refused); e != nil {
		t.Fatal(e)
	}
	if refused != revision {
		t.Fatalf("a refused write still published revision %d", refused)
	}
	t.Run("the automatic publisher import does not notice the flag", func(t *testing.T) {
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
		tx, e := tenantTx(ctx, p.a.db, p.org)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		if e = p.a.importPublisher(ctx, tx, p.org, 0, ""); e != nil {
			t.Fatal(e)
		}
		if e = tx.Commit(ctx); e != nil {
			t.Fatal(e)
		}
		var imported int64
		if e = p.admin.QueryRow(ctx, "SELECT max(revision) FROM detection_catalogs").Scan(&imported); e != nil {
			t.Fatal(e)
		}
		if imported <= revision {
			t.Fatal("the flag froze the automatic catalogue import")
		}
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

// Le champ précède le catalogue qui l'utilisera : l'agent refuse les champs inconnus, donc
// le serveur doit le lire, le borner et le taire quand il est vide — sans quoi les
// catalogues d'aujourd'hui changeraient d'octets et un agent antérieur les refuserait.
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
			// `decodeDetection` valide déjà : un catalogue refusé ne sort pas du décodage.
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
