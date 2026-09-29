package app

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

func factoryWithPlatforms(t *testing.T, platforms ...DetectionKnownPlatform) DetectionContent {
	t.Helper()
	var c DetectionContent
	if e := json.Unmarshal(detectionFactory, &c); e != nil {
		t.Fatal(e)
	}
	c.KnownPlatforms = platforms
	return c
}

// A known platform is named, never covered: no selector, no network rule, nothing read.
// The validation therefore checks the list against itself and nothing else -- in
// particular it must NOT refuse a host that is also a covered provider, because the
// editions cover different providers while a published catalogue carries the same bytes
// to both. Refusing the overlap would make a document valid on one side and impossible on
// the other; the overlap is settled where the catalogue is consumed.
func TestKnownPlatformValidation(t *testing.T) {
	covered := "chatgpt.com"
	for _, c := range []struct {
		name     string
		refused  bool
		platform DetectionKnownPlatform
	}{
		{name: "dedicated host", platform: DetectionKnownPlatform{ID: "aggregator", Label: "Aggregator", Domains: []string{"aggregator.example.invalid"}}},
		{name: "shared host under a prefix", platform: DetectionKnownPlatform{ID: "forge", Label: "Forge", Domains: []string{"forge.example.invalid"}, Paths: []string{"/assistant*"}}},
		{name: "a covered domain is allowed here", platform: DetectionKnownPlatform{ID: "covered", Label: "Covered", Domains: []string{covered}}},
		{name: "no domain", refused: true, platform: DetectionKnownPlatform{ID: "empty", Label: "Empty"}},
		{name: "invalid identifier", refused: true, platform: DetectionKnownPlatform{ID: "Not An Id", Label: "Bad", Domains: []string{"a.example.invalid"}}},
		{name: "invalid domain", refused: true, platform: DetectionKnownPlatform{ID: "bad", Label: "Bad", Domains: []string{"not a domain"}}},
		{name: "invalid path", refused: true, platform: DetectionKnownPlatform{ID: "bad", Label: "Bad", Domains: []string{"a.example.invalid"}, Paths: []string{"assistant"}}},
		{name: "empty label", refused: true, platform: DetectionKnownPlatform{ID: "bad", Domains: []string{"a.example.invalid"}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := validateDetection(factoryWithPlatforms(t, c.platform))
			if c.refused != (e != nil) {
				t.Fatalf("refused=%v, error=%v", c.refused, e)
			}
		})
	}
	t.Run("a domain named twice in the list", func(t *testing.T) {
		if validateDetection(factoryWithPlatforms(t,
			DetectionKnownPlatform{ID: "one", Label: "One", Domains: []string{"a.example.invalid"}},
			DetectionKnownPlatform{ID: "two", Label: "Two", Domains: []string{"a.example.invalid"}})) == nil {
			t.Fatal("a duplicate platform domain was accepted")
		}
	})
	t.Run("an identifier named twice", func(t *testing.T) {
		if validateDetection(factoryWithPlatforms(t,
			DetectionKnownPlatform{ID: "one", Label: "One", Domains: []string{"a.example.invalid"}},
			DetectionKnownPlatform{ID: "one", Label: "One again", Domains: []string{"b.example.invalid"}})) == nil {
			t.Fatal("a duplicate platform identifier was accepted")
		}
	})
	t.Run("beyond the ceiling", func(t *testing.T) {
		many := make([]DetectionKnownPlatform, 257)
		for i := range many {
			id := "p" + strconv.Itoa(i)
			many[i] = DetectionKnownPlatform{ID: id, Label: "P", Domains: []string{id + ".example.invalid"}}
		}
		if validateDetection(factoryWithPlatforms(t, many...)) == nil {
			t.Fatal("an unbounded platform list was accepted")
		}
	})
}

// The section survives the edition narrowing on purpose. Presence is inventory without
// capture -- a host name reached, nothing read -- so an administrator sees the AI their
// people use whichever edition they bought, exactly as model observation was opened to
// both editions on 2026-09-14.
func TestKnownPlatformsSurviveEditionNarrowing(t *testing.T) {
	c := factoryWithPlatforms(t, DetectionKnownPlatform{ID: "aggregator", Label: "Aggregator", Domains: []string{"aggregator.example.invalid"}})
	restrictEditionProviders(&c)
	if len(c.KnownPlatforms) != 1 {
		t.Fatal("the edition narrowing dropped the known platforms")
	}
	if Edition != "commercial" && len(c.Providers) >= 9 {
		t.Fatal("this build should narrow the covered providers")
	}
}

// A presence record says the host was reached, and the guarantee that it says nothing
// else belongs to the server. The endpoint is meant to send nothing more, but a modified
// extension that attached an address, a prompt or a conversation identifier must not
// succeed in having any of it stored.
func TestPresenceRecordIsReducedWhateverTheEndpointSent(t *testing.T) {
	prompt := "a prompt that must not survive"
	v := &V2Event{
		Provider: "aggregator.example.invalid", Source: "browser", Tool: "chrome",
		Kind: "navigation", Action: "observed", Detector: "presence",
		URL:            "https://aggregator.example.invalid/c/secret-conversation?q=secret",
		ConversationID: "secret-conversation", CorrelationID: "correlated",
		Model: "some-model", Effort: "high", Characters: 4096,
		Labels: []string{"email"}, Files: []string{"payroll.xlsx"}, Prompt: &prompt,
		PlatformID: "aggregator", DecisionReason: "model_denied",
		User: "an-os-account",
	}
	reducedToPresence(v)
	if v.Provider != "aggregator.example.invalid" {
		t.Fatal("the platform is the one thing presence keeps")
	}
	for name, got := range map[string]string{"url": v.URL, "conversation": v.ConversationID, "correlation": v.CorrelationID, "model": v.Model, "effort": v.Effort, "platform_id": v.PlatformID, "decision_reason": v.DecisionReason} {
		if got != "" {
			t.Fatalf("presence kept %s: %q", name, got)
		}
	}
	if v.Characters != 0 || v.Labels != nil || v.Files != nil || v.Prompt != nil || v.Response != nil {
		t.Fatal("presence kept content it must not carry")
	}
	if v.Detector != "presence" {
		t.Fatal("the record must describe how it was seen")
	}
	// Both editions keep the OS account the agent stamped, so the record says who was
	// signed in at the time.
	if v.User != "an-os-account" {
		t.Fatal("the OS account behind the visit must be kept")
	}
}

// "presence" belongs to the browser service worker and to nothing else: a native
// collector claiming it would be describing a page it never saw.
func TestPresenceIsABrowserChannel(t *testing.T) {
	now := time.Now().UTC()
	base := func() *V2Event {
		return &V2Event{ID: "1f1f1f1f-1f1f-4f1f-8f1f-1f1f1f1f1f1f", Kind: "navigation", OccurredAt: now, Provider: "aggregator.example.invalid", Tool: "chrome", Source: "browser", Action: "observed", Detector: "presence", PolicyRevision: 1, Labels: []string{}}
	}
	if e := validateV2(base(), now); e != nil {
		t.Fatalf("a browser presence record was refused: %v", e)
	}
	native := base()
	native.Source, native.Tool = "native", "codex"
	if validateV2(native, now) == nil {
		t.Fatal("a native record claimed the browser presence channel")
	}
	invented := base()
	invented.Detector = "guessed"
	if validateV2(invented, now) == nil {
		t.Fatal("an invented detector was accepted")
	}
}

// Under aggregate-only reporting, a platform reached by fewer machines than the
// aggregation threshold names its user by elimination in a small organization. It is
// withheld exactly as a report cell is.
func TestPresenceAggregateRespectsTheThreshold(t *testing.T) {
	p := newProjectionFixture(t)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, e := p.admin.Exec(ctx, `INSERT INTO shadow_events(organization_id,device_id,id,occurred_at,kind,provider,tool,source,action,policy_revision,characters,sensitivity,detector)
 VALUES($1,$2,gen_random_uuid(),now(),'navigation','aggregator.example.invalid','chrome','browser','observed',1,0,'normal','presence')`, p.org, p.device); e != nil {
			t.Fatal(e)
		}
	}
	platforms := func() int {
		w := p.as("owner", "GET", "/api/detection/candidates", nil)
		requireHTTP(t, w, 200)
		var body struct {
			Platforms []struct {
				Provider string `json:"provider"`
				Visits   int    `json:"visits"`
				Devices  int    `json:"devices"`
			} `json:"platforms"`
		}
		if e := json.Unmarshal(w.Body.Bytes(), &body); e != nil {
			t.Fatal(e)
		}
		return len(body.Platforms)
	}
	if platforms() != 1 {
		t.Fatal("two visits from one device should be reported outside aggregate-only mode")
	}
	// One machine, threshold of five: the platform disappears rather than pointing at
	// whoever is behind it.
	if _, e := p.admin.Exec(ctx, `INSERT INTO privacy_settings(organization_id) VALUES($1) ON CONFLICT DO NOTHING`, p.org); e != nil {
		t.Fatal(e)
	}
	if tag, e := p.admin.Exec(ctx, `UPDATE privacy_settings SET configuration=configuration||'{"aggregate_only":true,"k_anonymity":5}'::jsonb WHERE organization_id=$1`, p.org); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("privacy fixture missing", e)
	}
	if platforms() != 0 {
		t.Fatal("a single-device platform survived the aggregation threshold")
	}
}

// The console now offers "promote" from the published catalogue rather than from a
// publication made in the current browsing session. The server stays the authority: a
// domain the catalogue does not carry is refused whatever the interface offered.
func TestPromotingAnUncoveredDomainIsRefused(t *testing.T) {
	p := newProjectionFixture(t)
	ctx := context.Background()
	if _, e := p.admin.Exec(ctx, `INSERT INTO candidate_domains(organization_id,domain,count) VALUES($1,'unlisted.example.invalid',3)`, p.org); e != nil {
		t.Fatal(e)
	}
	w := p.as("owner", "PATCH", "/api/detection/candidates", map[string]any{"domain": "unlisted.example.invalid", "status": "promoted"})
	requireHTTP(t, w, 409)
	if !strings.Contains(w.Body.String(), "catalog_publication_required") {
		t.Fatalf("unexpected refusal: %s", w.Body.String())
	}
	var status string
	if e := p.admin.QueryRow(ctx, "SELECT status FROM candidate_domains WHERE domain='unlisted.example.invalid'").Scan(&status); e != nil {
		t.Fatal(e)
	}
	if status != "new" {
		t.Fatalf("a refused promotion still changed the candidate to %q", status)
	}
}

// End to end against a stored catalogue: which hosts count is the server's decision, read
// from the signed document it holds, not from what the device claims.
func TestPresenceAuthorizationAgainstTheStoredCatalogue(t *testing.T) {
	p := newProjectionFixture(t)
	ctx := context.Background()
	content := factoryWithPlatforms(t,
		DetectionKnownPlatform{ID: "aggregator", Label: "Aggregator", Domains: []string{"aggregator.example.invalid"}},
		// Also a covered provider of the Enterprise factory catalogue: the same document
		// serves both editions, and precedence settles it at consumption.
		DetectionKnownPlatform{ID: "gemini-presence", Label: "Gemini", Domains: []string{"gemini.google.com"}})
	if e := validateDetection(content); e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(content)
	var revision int64
	if e := p.admin.QueryRow(ctx, `INSERT INTO detection_catalogs(content,content_hash,source) VALUES($1,'presence-test','edited') RETURNING revision`, raw).Scan(&revision); e != nil {
		t.Fatal(e)
	}
	tx, e := tenantTx(ctx, p.a.db, p.org)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	// One batch for the whole subtest, as an ingest request builds one: the batch
	// memoizes the decoded catalogue by revision, which is the point of the type.
	batch := detectionEventBatch{catalogs: map[int64]DetectionContent{}}
	authorize := func(t *testing.T, provider string) *V2Event {
		t.Helper()
		v := &V2Event{Provider: provider, Source: "browser", Tool: "chrome", Kind: "navigation", Action: "observed", Detector: "presence", URL: "https://" + provider + "/c/secret", Characters: 12, CatalogRevision: &revision}
		if e := batch.authorize(ctx, tx, v); e != nil {
			t.Fatal(e)
		}
		return v
	}
	t.Run("a named platform keeps its name and loses everything else", func(t *testing.T) {
		v := authorize(t, "aggregator.example.invalid")
		if v.Provider != "aggregator.example.invalid" || v.URL != "" || v.Characters != 0 {
			t.Fatalf("presence not reduced: %+v", v)
		}
	})
	t.Run("a host named nowhere stays unknown", func(t *testing.T) {
		v := authorize(t, "unlisted.example.invalid")
		if v.Provider != "unknown" || v.URL != "" {
			t.Fatalf("an unnamed host was attributed: %+v", v)
		}
	})
	t.Run("a covered provider wins over the presence entry", func(t *testing.T) {
		assertCoveredProviderPrecedence(t, authorize(t, "gemini.google.com"))
	})
	// Nobody blocks the platform here, so an endpoint claiming a blocked attempt is
	// recorded as the visit it was.
	t.Run("a blocked attempt on a platform nobody blocks is an ordinary visit", func(t *testing.T) {
		v := &V2Event{Provider: "aggregator.example.invalid", Source: "browser", Tool: "chrome", Kind: "navigation", Action: "blocked", Detector: "presence", CatalogRevision: &revision}
		if e := batch.authorize(ctx, tx, v); e != nil {
			t.Fatal(e)
		}
		if v.Action != "observed" {
			t.Fatalf("an unblocked platform kept action %q", v.Action)
		}
	})
}

func assertCoveredProviderPrecedence(t *testing.T, v *V2Event) {
	t.Helper()
	if Edition == "commercial" {
		// Covered here: the record keeps what capture gathered, and is not reduced.
		if v.Provider != "gemini.google.com" || v.URL == "" {
			t.Fatalf("a covered provider was reduced to presence: %+v", v)
		}
		return
	}
	// Not covered in this edition, so the presence entry applies and reduces it.
	if v.Provider != "gemini.google.com" || v.URL != "" || v.Characters != 0 {
		t.Fatalf("presence not applied where the provider is absent: %+v", v)
	}
}

// Hiding a platform is a reading choice on one console screen, not a change to what the
// fleet detects: the rows stay in shadow_events, so showing it again restores its history
// instead of starting a new one. Written against the factory catalogue, which is what an
// administrator actually sees the day the product is installed.
func TestMutingAPlatformHidesItFromDiscoveryWithoutErasingIt(t *testing.T) {
	p := newProjectionFixture(t)
	ctx := context.Background()
	// The event carries the host, not the identifier: reducedToPresence keeps the host in
	// `provider` and erases platform_id, so the mute has to resolve one to the other.
	for i := 0; i < 2; i++ {
		if _, e := p.admin.Exec(ctx, `INSERT INTO shadow_events(organization_id,device_id,id,occurred_at,kind,provider,tool,source,action,policy_revision,characters,sensitivity,detector)
 VALUES($1,$2,gen_random_uuid(),now(),'navigation','fireflies.ai','chrome','browser','observed',1,0,'normal','presence')`, p.org, p.device); e != nil {
			t.Fatal(e)
		}
	}
	reported := func() int {
		w := p.as("owner", "GET", "/api/detection/candidates", nil)
		requireHTTP(t, w, 200)
		var body struct {
			Platforms []struct {
				Provider string `json:"provider"`
			} `json:"platforms"`
		}
		if e := json.Unmarshal(w.Body.Bytes(), &body); e != nil {
			t.Fatal(e)
		}
		return len(body.Platforms)
	}
	if reported() != 1 {
		t.Fatal("a reached platform should be reported before anything is muted")
	}
	requireHTTP(t, p.as("owner", "PATCH", "/api/detection/platforms", map[string]any{"id": "fireflies", "muted": true}), 200)
	if reported() != 0 {
		t.Fatal("a muted platform was still named in Discovery")
	}
	// The point of muting rather than filtering at the source: the visits survive.
	var kept int
	if e := p.admin.QueryRow(ctx, "SELECT count(*) FROM shadow_events WHERE detector='presence' AND provider='fireflies.ai'").Scan(&kept); e != nil {
		t.Fatal(e)
	}
	if kept != 2 {
		t.Fatalf("muting deleted presence records: %d left", kept)
	}
	requireHTTP(t, p.as("owner", "PATCH", "/api/detection/platforms", map[string]any{"id": "fireflies", "muted": false}), 200)
	if reported() != 1 {
		t.Fatal("unmuting did not bring the platform's history back")
	}
}

// An identifier the catalogue does not carry would store a row nothing ever reads, and
// the screen would report a platform as silenced while Discovery kept naming it.
func TestMutingAnUnknownPlatformIsRefused(t *testing.T) {
	p := newProjectionFixture(t)
	requireHTTP(t, p.as("owner", "PATCH", "/api/detection/platforms", map[string]any{"id": "not-in-the-catalogue", "muted": true}), 404)
	var rows int
	if e := p.admin.QueryRow(context.Background(), "SELECT count(*) FROM muted_platforms").Scan(&rows); e != nil {
		t.Fatal(e)
	}
	if rows != 0 {
		t.Fatalf("a refused mute still wrote %d row(s)", rows)
	}
}

// The inventory is the catalogue's own list rather than what has been reached, so a
// platform can be silenced before anyone visits it instead of after the alert.
func TestKnownPlatformInventoryListsTheCatalogueNotTheVisits(t *testing.T) {
	p := newProjectionFixture(t)
	w := p.as("owner", "GET", "/api/detection/platforms", nil)
	requireHTTP(t, w, 200)
	var body struct {
		Platforms []struct {
			ID      string   `json:"id"`
			Label   string   `json:"label"`
			Domains []string `json:"domains"`
			Muted   bool     `json:"muted"`
		} `json:"platforms"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &body); e != nil {
		t.Fatal(e)
	}
	if len(body.Platforms) == 0 {
		t.Fatal("the factory catalogue names no platform")
	}
	// The seven this catalogue names AND Enterprise captures in full. Community covers
	// neither of them -- they are exactly what presence was asked for there.
	capturedByEnterprise := map[string]bool{"gemini": true, "copilot": true, "lechat": true, "deepseek": true, "perplexity": true, "grok": true, "notebooklm": true}
	var fireflies, aistudio, shared, offered int
	for _, item := range body.Platforms {
		if capturedByEnterprise[item.ID] {
			offered++
		}
		switch item.ID {
		case "fireflies":
			fireflies++
			if item.Label != "Fireflies" || len(item.Domains) != 1 || item.Domains[0] != "fireflies.ai" || item.Muted {
				t.Fatalf("unexpected inventory row: %+v", item)
			}
		case "aistudio":
			// Named by the catalogue and covered by neither edition: the guard against a
			// filter that drops more than the providers it was given.
			aistudio++
		case "teams-copilot", "slack-ai", "atlassian-rovo":
			// Shared hosts whose path was never measured: publishing them whole would
			// report every user of Teams, Slack or Atlassian as an AI user.
			shared++
		}
	}
	if fireflies != 1 || aistudio != 1 {
		t.Fatalf("expected one row each for fireflies and aistudio, got %d and %d", fireflies, aistudio)
	}
	if shared != 0 {
		t.Fatalf("%d shared host(s) with no measured path reached the catalogue", shared)
	}
	// A platform this edition captures in full can never reach Discovery, so the screen
	// does not offer a switch that would decide nothing (product decision, 2026-09-16).
	want := len(capturedByEnterprise)
	if Edition == "commercial" {
		want = 0
	}
	if offered != want {
		t.Fatalf("edition %q offers %d of the seven Enterprise-captured platforms, expected %d", Edition, offered, want)
	}
}

// Discovery answers "which AI do my people use that I do not watch". A service this
// edition already captures in full is not that, so it is filtered out on both sides of
// the screen -- the candidate domains and the platforms reached. Product decision,
// 2026-09-16.
//
// The assertion is edition-sensitive on purpose: chatgpt is covered by both editions,
// gemini only by Enterprise, and Community is precisely where presence was asked for.
// A test that only checked chatgpt would pass just as well with the narrowing removed.
func TestDiscoveryHidesWhatTheEditionAlreadyCaptures(t *testing.T) {
	p := newProjectionFixture(t)
	ctx := context.Background()
	for _, domain := range []string{"chatgpt.com", "gemini.google.com", "mammouth.ai"} {
		if _, e := p.admin.Exec(ctx, `INSERT INTO candidate_domains(organization_id,domain,count) VALUES($1,$2,3)`, p.org, domain); e != nil {
			t.Fatal(e)
		}
		if _, e := p.admin.Exec(ctx, `INSERT INTO shadow_events(organization_id,device_id,id,occurred_at,kind,provider,tool,source,action,policy_revision,characters,sensitivity,detector)
 VALUES($1,$2,gen_random_uuid(),now(),'navigation',$3,'chrome','browser','observed',1,0,'normal','presence')`, p.org, p.device, domain); e != nil {
			t.Fatal(e)
		}
	}
	w := p.as("owner", "GET", "/api/detection/candidates", nil)
	requireHTTP(t, w, 200)
	var body struct {
		Items []struct {
			Domain string `json:"domain"`
		} `json:"items"`
		Platforms []struct {
			Provider string `json:"provider"`
		} `json:"platforms"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &body); e != nil {
		t.Fatal(e)
	}
	named := map[string]bool{}
	for _, item := range body.Items {
		named["candidate:"+item.Domain] = true
	}
	for _, item := range body.Platforms {
		named["platform:"+item.Provider] = true
	}
	// Covered by both editions: never a discovery finding.
	for _, key := range []string{"candidate:chatgpt.com", "platform:chatgpt.com"} {
		assertDiscoveryNamed(t, named, key, false)
	}
	// Covered only by Enterprise. Community is where the presence path applies, so it
	// must still be reported there -- filtering it in both editions would be the same
	// bug in the other direction.
	for _, key := range []string{"candidate:gemini.google.com", "platform:gemini.google.com"} {
		assertDiscoveryNamed(t, named, key, Edition != "commercial")
	}
	// The guard against a filter that hides everything: an uncovered platform survives.
	for _, key := range []string{"candidate:mammouth.ai", "platform:mammouth.ai"} {
		assertDiscoveryNamed(t, named, key, true)
	}
}

func assertDiscoveryNamed(t *testing.T, named map[string]bool, key string, want bool) {
	t.Helper()
	if named[key] != want {
		t.Fatalf("Discovery %s reported=%v, want %v in edition %q", key, named[key], want, Edition)
	}
}
