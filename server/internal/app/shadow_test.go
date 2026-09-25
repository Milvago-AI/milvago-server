package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestShadowValidation(t *testing.T) {
	c := defaultShadowConfig()
	if e := validateShadow(c); e != nil {
		t.Fatal(e)
	}
	// Both editions start with signed updates active: the console only shows the
	// Operations section under MILVAGO_DEBUG, so this default is what governs an
	// ordinary deployment.
	if !c.Operations.Updates.Enabled {
		t.Fatal("signed updates must be enabled in the default policy of both editions")
	}
	c.Privacy.CustomRules = []PrivacyRule{{ID: "11111111-1111-4111-8111-111111111111", Label: "Risky expression", Pattern: "(a+)+", Enabled: true}}
	if validateShadow(c) == nil {
		t.Fatal("nested repetition accepted")
	}
	// Product decision of 2026-09-16: a label that its own expression captures is
	// refused -- the marker `[LABEL]` inserted into the masked text would in turn be
	// masked, without end. The check is on the label alone, with the rule's case
	// sensitivity: "NUMERO" against `[0-9]+` remains allowed, `[NUMERO1]` being the
	// intended form of the numbered marker.
	for _, tc := range []struct {
		label, pattern string
		ci, ok         bool
	}{
		{"NUMERO", `[0-9]+`, false, true},
		{"CODE12", `[A-Z]+[0-9]+`, false, false},
		{"IP", `[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`, false, true},
		{"iban", `IBAN`, false, true},
		{"iban", `IBAN`, true, false},
		{"MOT", `[A-Z]{3}`, false, false},
	} {
		c.Privacy.CustomRules = []PrivacyRule{{ID: "11111111-1111-4111-8111-111111111111", Label: tc.label, Pattern: tc.pattern, CaseInsensitive: tc.ci, Enabled: true}}
		if (validateShadow(c) == nil) != tc.ok {
			t.Fatalf("label %q against %q (ci=%v): accepted=%v, want %v", tc.label, tc.pattern, tc.ci, validateShadow(c) == nil, tc.ok)
		}
	}
	c.Privacy.CustomRules = nil
	v := V2Event{ID: "11111111-1111-4111-8111-111111111111", Kind: "navigation", OccurredAt: time.Now(), Provider: "claude.ai", Source: "browser", Tool: "chrome", URL: "https://claude.ai/chat/opaque?secret=hidden#fragment", Action: "observed", Labels: []string{}, PolicyRevision: 1}
	if e := validateV2(&v, time.Now()); e != nil {
		t.Fatal(e)
	}
	if v.URL != "https://claude.ai/chat/:conversation" {
		t.Fatal("URL did not minimize opaque identifiers")
	}
	v.Prompt = new(string)
	if validateV2(&v, time.Now()) == nil {
		t.Fatal("navigation accepted prompt body")
	}
	q := url.Values{"tool": {"chrome", "firefox"}, "actor_id": {"unknown"}, "model": {"unknown"}}
	f, e := parseShadowFilter(q)
	if e != nil || !strings.Contains(f.Where, "ANY(") {
		t.Fatal("multi-select filter missing", e)
	}
	q.Set("actor_id", "invalid")
	if _, e = parseShadowFilter(q); e == nil {
		t.Fatal("invalid actor filter")
	}
	if csvSafe("=1+1") != "'=1+1" {
		t.Fatal("CSV formula not escaped")
	}
	a := &App{config: Config{SigningKey: ed25519.NewKeyFromSeed(make([]byte, 32)), ContentKeys: testContentKeys(), ContentVersion: 1}}
	sealed, e := a.sealShadow("org-one", "event:one", []byte("synthetic sensitive text"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.openShadow("org-two", "event:one", sealed); e == nil {
		t.Fatal("cross-org ciphertext accepted")
	}
	if _, e = a.openShadow("org-one", "event:two", sealed); e == nil {
		t.Fatal("event ciphertext substitution accepted")
	}
}

func TestDesktopAgentCollectorEditionBoundary(t *testing.T) {
	v := V2Event{ID: "11111111-1111-4111-8111-111111111111", Kind: "prompt", OccurredAt: time.Now(), Provider: "claude.ai", Source: "native", Tool: "claude-desktop-agent", Action: "observed", Labels: []string{}, PolicyRevision: 1}
	err := validateV2(&v, time.Now())
	if (Edition == "community") != (err != nil) {
		t.Fatalf("desktop agent collector edition boundary: edition=%s error=%v", Edition, err)
	}
}

func testShadowSubsystem(t *testing.T, f subsystemFixture) {
	t.Helper()
	a, admin, cookie, csrf, org, user, p := f.a, f.admin, f.cookie, f.csrf, f.org, f.user, f.identity
	ctx := context.Background()
	call := func(method, path string, body any, bearer string) *httptest.ResponseRecorder {
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", a.config.AppURL)
		r.Header.Set("X-CSRF-Token", csrf)
		r.AddCookie(cookie)
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		return w
	}
	getConfig := func() ShadowSettings {
		w := call("GET", "/api/shadow/settings", nil, "")
		requireHTTP(t, w, 200)
		var c ShadowSettings
		if e := json.Unmarshal(w.Body.Bytes(), &c); e != nil {
			t.Fatal(e)
		}
		return c
	}
	cfg := getConfig()
	if cfg.Config.Collection.StoreContent {
		t.Fatal("content enabled by default")
	}
	enrollment := call("POST", "/api/enrollments", map[string]string{"label": "Shadow integration"}, "")
	requireHTTP(t, enrollment, 201)
	var provision map[string]string
	_ = json.Unmarshal(enrollment.Body.Bytes(), &provision)
	enrolled := call("POST", "/v2/enroll", map[string]any{"token": provision["token"], "hostname": "shadow-test-device", "platform": "test", "version": "0.2.0", "kind": "browser", "capabilities": []string{"browser.navigation", "browser.prompt"}}, "")
	requireHTTP(t, enrolled, 201)
	var device map[string]string
	_ = json.Unmarshal(enrolled.Body.Bytes(), &device)
	credential, id := device["credential"], device["device_id"]
	requireHTTP(t, call("POST", "/api/devices/"+id+"/approve", map[string]any{}, ""), 200)
	t.Run("shadow signed v2 and no control secrets", func(t *testing.T) {
		w := call("GET", "/v2/policy", nil, credential)
		requireHTTP(t, w, 200)
		var envelope map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &envelope)
		raw, e := base64.StdEncoding.DecodeString(envelope["payload"])
		if e != nil {
			t.Fatal(e)
		}
		signature, _ := base64.StdEncoding.DecodeString(envelope["signature"])
		key, _ := base64.StdEncoding.DecodeString(provision["policy_public_key"])
		if !ed25519.Verify(key, raw, signature) || bytes.Contains(raw, []byte("operations")) {
			t.Fatal("invalid signature or leaked control config")
		}
	})
	t.Run("model policy downgrade and authenticated freshness", func(t *testing.T) {
		// Per-model control is an Enterprise capability: validateShadow refuses a
		// model_access rule in Community with 409 capability_unavailable, so this
		// whole subtest can only pass there. The expectation predates that guard
		// and was masked until now, because the enclosing test used to abort
		// earlier on a stale self-lock expectation in security_test.go. Community
		// keeps its own coverage that the section is refused (see the
		// capability_unavailable assertions in this file).
		if Edition != "commercial" {
			t.Skip("per-model control is Enterprise only")
		}
		previous := getConfig()
		next := previous
		next.Config.ModelAccess = []ModelAccessRule{{"chatgpt", "browser", "denylist", []string{"Astra6"}}}
		requireHTTP(t, call("PUT", "/api/shadow/settings", map[string]any{"revision": next.Revision, "config": next.Config, "inherit_sections": next.InheritSections}, ""), 200)
		current := getConfig()
		requireHTTP(t, call("GET", "/v1/policy", nil, credential), 409)
		defer func() {
			restore := getConfig()
			restore.Config = previous.Config
			requireHTTP(t, call("PUT", "/api/shadow/settings", map[string]any{"revision": restore.Revision, "config": restore.Config, "inherit_sections": restore.InheritSections}, ""), 200)
		}()
		for _, version := range []int{2, 3} {
			w := call("GET", fmt.Sprintf("/v%d/policy", version), nil, credential)
			requireHTTP(t, w, 200)
			var env map[string]string
			_ = json.Unmarshal(w.Body.Bytes(), &env)
			raw, _ := base64.StdEncoding.DecodeString(env["payload"])
			sig, _ := base64.StdEncoding.DecodeString(env["signature"])
			key, _ := base64.StdEncoding.DecodeString(provision["policy_public_key"])
			if !ed25519.Verify(key, raw, sig) {
				t.Fatal("invalid model policy signature")
			}
			var payload struct {
				Version int          `json:"version"`
				Config  ShadowConfig `json:"config"`
			}
			if e := json.Unmarshal(raw, &payload); e != nil {
				t.Fatal(e)
			}
			if payload.Version != version {
				t.Fatal("wrong policy version")
			}
			if version == 2 && (bytes.Contains(raw, []byte("model_access")) || payload.Config.Services[0].Mode != "block") {
				t.Fatal("legacy policy silently drops restriction")
			}
			if version == 3 && (len(payload.Config.ModelAccess) != 1 || payload.Config.Services[0].Mode != "observe") {
				t.Fatal("v3 loses granular policy")
			}
		}
		report := enforcementReport{current.Revision, "chatgpt", "browser", "applied", "", "browser-request"}
		requireHTTP(t, call("POST", "/v3/enforcement", report, ""), 401)
		report.Revision++
		requireHTTP(t, call("POST", "/v3/enforcement", report, credential), 409)
		report.Revision--
		requireHTTP(t, call("POST", "/v3/enforcement", report, credential), 200)
		status := call("GET", "/api/model-access/status", nil, "")
		requireHTTP(t, status, 200)
		if !bytes.Contains(status.Body.Bytes(), []byte("\"status\":\"applied\"")) {
			t.Fatal(status.Body.String())
		}
		if _, e := admin.Exec(ctx, `UPDATE model_enforcement SET reported_at=now()-interval '4 minutes' WHERE device_id=$1`, id); e != nil {
			t.Fatal(e)
		}
		status = call("GET", "/api/model-access/status", nil, "")
		requireHTTP(t, status, 200)
		if bytes.Contains(status.Body.Bytes(), []byte("\"status\":\"applied\"")) {
			t.Fatal("stale report displayed applied")
		}
		var unforced int
		if e := admin.QueryRow(ctx, `SELECT count(*) FROM pg_class WHERE relname='model_enforcement' AND NOT(relrowsecurity AND relforcerowsecurity)`).Scan(&unforced); e != nil || unforced != 0 {
			t.Fatal("enforcement RLS missing", e)
		}
		var hidden int
		if e := a.db.QueryRow(ctx, `SELECT count(*) FROM model_enforcement`).Scan(&hidden); e != nil || hidden != 0 {
			t.Fatal("unscoped report disclosure", e)
		}
	})
	cfg = getConfig()

	now := time.Now().UTC()
	event := V2Event{ID: "22222222-2222-4222-8222-222222222222", Kind: "prompt", OccurredAt: now, Provider: "claude.ai", Source: "browser", Tool: "chrome", ConversationID: "synthetic-conversation", CorrelationID: "synthetic-prompt", Action: "observed", Characters: 12, Labels: []string{"iban"}, PolicyRevision: cfg.Revision}
	batch := func(events ...V2Event) *httptest.ResponseRecorder {
		return call("POST", "/v2/events", map[string]any{"events": events}, credential)
	}
	// A prompt is recorded before it is sent, so what the request itself says — the
	// conversation it created, the model, the effort — arrives afterwards. It may fill
	// what is empty and nothing else: a device must never be able to revise an event
	// already written, reach another device's events, or invent one.
	t.Run("a completion fills an empty field and never revises a written one", func(t *testing.T) {
		blank := event
		blank.ID = "33333333-aaaa-4333-8333-333333333333"
		blank.ConversationID = ""
		blank.CorrelationID = ""
		blank.Detector = "dom"
		written := event
		written.ID = "44444444-aaaa-4444-8444-444444444444"
		written.ConversationID = "recorded-conversation"
		written.Model = "recorded-model"
		requireHTTP(t, batch(blank, written), 200)
		t.Cleanup(func() {
			_, _ = admin.Exec(ctx, "DELETE FROM shadow_events WHERE id=ANY($1::uuid[])", []string{blank.ID, written.ID})
		})
		complete := func(credential string, completions ...map[string]any) *httptest.ResponseRecorder {
			return call("POST", "/v2/events/complete", map[string]any{"completions": completions}, credential)
		}
		requireHTTP(t, complete(randomToken(), map[string]any{"id": blank.ID, "model": "observed-model"}), 401)
		w := complete(credential,
			map[string]any{"id": blank.ID, "model": "observed-model", "effort": "high", "conversation_id": "observed-conversation", "body_bytes": 4096},
			map[string]any{"id": written.ID, "model": "other-model", "conversation_id": "other-conversation"},
			map[string]any{"id": "55555555-aaaa-4555-8555-555555555555", "model": "unknown-event"})
		requireHTTP(t, w, 200)
		var applied struct {
			IDs []string `json:"applied_ids"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &applied); err != nil {
			t.Fatal(err)
		}
		// An identity that names no event applies to nothing: a completion never
		// creates an event, only fills one.
		if len(applied.IDs) != 2 || applied.IDs[0] != blank.ID || applied.IDs[1] != written.ID {
			t.Fatal("completion applied to the wrong events", w.Body.String())
		}
		var count int
		if e := admin.QueryRow(ctx, "SELECT count(*) FROM shadow_events WHERE id='55555555-aaaa-4555-8555-555555555555'").Scan(&count); e != nil || count != 0 {
			t.Fatal("completion created an event", e)
		}
		var model, effort, conversation, detector string
		var bodyBytes *int64
		if e := admin.QueryRow(ctx, "SELECT model,effort,conversation_id,detector,body_bytes FROM shadow_events WHERE id=$1", blank.ID).Scan(&model, &effort, &conversation, &detector, &bodyBytes); e != nil {
			t.Fatal(e)
		}
		if model != "observed-model" || effort != "high" || conversation != "observed-conversation" || detector != "both" || bodyBytes == nil || *bodyBytes != 4096 {
			t.Fatal("completion did not fill the empty fields", model, effort, conversation, detector)
		}
		if e := admin.QueryRow(ctx, "SELECT model,conversation_id FROM shadow_events WHERE id=$1", written.ID).Scan(&model, &conversation); e != nil {
			t.Fatal(e)
		}
		if model != "recorded-model" || conversation != "recorded-conversation" {
			t.Fatal("a completion revised a written value", model, conversation)
		}
		// Replayed with other values, it changes nothing: the first answer about an
		// exchange is the one kept.
		requireHTTP(t, complete(credential, map[string]any{"id": blank.ID, "model": "replayed-model", "conversation_id": "replayed-conversation", "body_bytes": 1}), 200)
		if e := admin.QueryRow(ctx, "SELECT model,conversation_id,body_bytes FROM shadow_events WHERE id=$1", blank.ID).Scan(&model, &conversation, &bodyBytes); e != nil {
			t.Fatal(e)
		}
		if model != "observed-model" || conversation != "observed-conversation" || bodyBytes == nil || *bodyBytes != 4096 {
			t.Fatal("a replay revised the exchange", model, conversation)
		}
		// Nothing outside the completion's own vocabulary is writable, and a batch is
		// bounded exactly like an ingestion.
		requireHTTP(t, complete(credential, map[string]any{"id": blank.ID, "characters": 99, "action": "blocked"}), 400)
		requireHTTP(t, complete(credential, map[string]any{"id": blank.ID}), 400)
		requireHTTP(t, complete(credential, map[string]any{"id": blank.ID, "model": "a"}, map[string]any{"id": blank.ID, "model": "b"}), 400)
		requireHTTP(t, complete(credential, map[string]any{"id": "not-a-uuid", "model": "a"}), 400)
		oversized := make([]map[string]any, 101)
		for i := range oversized {
			oversized[i] = map[string]any{"id": fmt.Sprintf("77777777-aaaa-4777-8777-%012d", i), "model": "m"}
		}
		requireHTTP(t, complete(credential, oversized...), 400)
		var characters int
		var action string
		if e := admin.QueryRow(ctx, "SELECT characters,action FROM shadow_events WHERE id=$1", blank.ID).Scan(&characters, &action); e != nil || characters != blank.Characters || action != "observed" {
			t.Fatal("a completion reached a field outside its vocabulary", characters, action, e)
		}
		// Another device's credential reaches nothing: the update is scoped to the
		// authenticated installation inside its organization's transaction.
		w = call("POST", "/api/enrollments", map[string]string{"label": "Synthetic second browser"}, "")
		requireHTTP(t, w, 201)
		var provision map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &provision)
		w = call("POST", "/v2/enroll", map[string]any{"token": provision["token"], "hostname": "second-browser", "platform": "windows", "version": "0.2.0", "kind": "browser"}, "")
		requireHTTP(t, w, 201)
		var second map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &second)
		requireHTTP(t, call("POST", "/api/devices/"+second["device_id"]+"/approve", map[string]any{}, ""), 200)
		empty := event
		empty.ID = "66666666-aaaa-4666-8666-666666666666"
		empty.ConversationID = ""
		requireHTTP(t, batch(empty), 200)
		t.Cleanup(func() { _, _ = admin.Exec(ctx, "DELETE FROM shadow_events WHERE id=$1", empty.ID) })
		w = complete(second["credential"], map[string]any{"id": empty.ID, "conversation_id": "stolen-conversation"})
		requireHTTP(t, w, 200)
		_ = json.Unmarshal(w.Body.Bytes(), &applied)
		if len(applied.IDs) != 0 {
			t.Fatal("a device completed another device's event", w.Body.String())
		}
		if e := admin.QueryRow(ctx, "SELECT conversation_id FROM shadow_events WHERE id=$1", empty.ID).Scan(&conversation); e != nil || conversation != "" {
			t.Fatal("foreign completion reached the event", conversation, e)
		}
	})
	t.Run("invalid event isolation is authenticated atomic and precise", func(t *testing.T) {
		valid, invalid := event, event
		valid.ID = "11111111-aaaa-4111-8111-111111111111"
		invalid.ID = "22222222-aaaa-4222-8222-222222222222"
		invalid.User = "invalid\u0007profile"
		body := map[string]any{"events": []V2Event{valid, invalid}}
		unauthorized := call("POST", "/v2/events", body, randomToken())
		requireHTTP(t, unauthorized, 401)
		if strings.Contains(unauthorized.Body.String(), "rejected_ids") {
			t.Fatal("unauthenticated rejection can delete queue entries")
		}
		w := batch(valid, invalid)
		requireHTTP(t, w, 400)
		var rejected struct {
			Error string
			IDs   []string `json:"rejected_ids"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &rejected); err != nil {
			t.Fatal(err)
		}
		if rejected.Error != "invalid_event" || len(rejected.IDs) != 1 || rejected.IDs[0] != invalid.ID {
			t.Fatal("imprecise rejection", w.Body.String())
		}
		var count int
		if e := admin.QueryRow(ctx, "SELECT count(*) FROM shadow_events WHERE id=ANY($1::uuid[])", []string{valid.ID, invalid.ID}).Scan(&count); e != nil || count != 0 {
			t.Fatal("partial batch committed", e)
		}
		requireHTTP(t, batch(valid), 200)
		t.Cleanup(func() { _, _ = admin.Exec(ctx, "DELETE FROM shadow_events WHERE id=$1", valid.ID) })
		if e := admin.QueryRow(ctx, "SELECT count(*) FROM shadow_events WHERE id=$1", valid.ID).Scan(&count); e != nil || count != 1 {
			t.Fatal("valid event did not recover", e)
		}
		invalid.User = ""
		invalid.Model = " leading-space"
		w = batch(invalid)
		requireHTTP(t, w, 400)
		if !strings.Contains(w.Body.String(), "invalid_event") {
			t.Fatal("metadata poison not identified")
		}
	})

	// Which model answered is inventory and is kept in every edition: an administrator
	// has to see what is actually used before deciding anything about it. Only the
	// decision - the platform a rule was evaluated for, and why it refused - is
	// Proprietary. Clearing the model alongside it left every Community record blank
	// while the agent and the extension already reported it, and nothing said so.
	t.Run("an observed model is stored in every edition, a decision is not", func(t *testing.T) {
		v := event
		v.ID = "44444444-aaaa-4444-8444-444444444444"
		v.Model = "claude-haiku-4-5-20251001"
		v.PlatformID = "claude"
		v.DecisionReason = "model_denied"
		v.Action = "blocked"
		v.Kind = "prompt"
		requireHTTP(t, batch(v), 200)
		t.Cleanup(func() { _, _ = admin.Exec(ctx, "DELETE FROM shadow_events WHERE id=$1", v.ID) })
		var model, platform, reason string
		if e := admin.QueryRow(ctx, "SELECT model,platform_id,decision_reason FROM shadow_events WHERE id=$1", v.ID).Scan(&model, &platform, &reason); e != nil {
			t.Fatal(e)
		}
		if model != v.Model {
			t.Fatalf("the observed model must survive ingestion, got %q", model)
		}
		if Edition == "community" && (platform != "" || reason != "") {
			t.Fatalf("Community must keep no decision, got platform %q reason %q", platform, reason)
		}
		if Edition != "community" && (platform != "claude" || reason != "model_denied") {
			t.Fatalf("the decision must survive outside Community, got platform %q reason %q", platform, reason)
		}
	})

	t.Run("file names require current collection permission", func(t *testing.T) {
		current := getConfig()
		original := current.Config
		current.Config.Collection.StoreFileNames = false
		w := call("PUT", "/api/shadow/settings", map[string]any{"revision": current.Revision, "config": current.Config, "inherit_sections": []string{}}, "")
		requireHTTP(t, w, 200)
		current = getConfig()
		v := event
		v.ID = "33333333-aaaa-4333-8333-333333333333"
		v.Files = []string{"synthetic-private.txt"}
		v.PolicyRevision = current.Revision
		requireHTTP(t, batch(v), 409)
		current.Config.Collection.StoreFileNames = true
		requireHTTP(t, call("PUT", "/api/shadow/settings", map[string]any{"revision": current.Revision, "config": current.Config, "inherit_sections": []string{}}, ""), 200)
		current = getConfig()
		requireHTTP(t, batch(v), 409)
		v.PolicyRevision = current.Revision
		requireHTTP(t, batch(v), 200)
		var files string
		if err := admin.QueryRow(ctx, "SELECT files::text FROM shadow_events WHERE id=$1", v.ID).Scan(&files); err != nil || !strings.Contains(files, "synthetic-private.txt") {
			t.Fatal("authorized file name was not stored", err)
		}
		t.Cleanup(func() { _, _ = admin.Exec(ctx, "DELETE FROM shadow_events WHERE id=$1", v.ID) })
		requireHTTP(t, call("PUT", "/api/shadow/settings", map[string]any{"revision": current.Revision, "config": original, "inherit_sections": []string{}}, ""), 200)
		cfg = getConfig()
	})
	t.Run("shadow disabled content rejected and metadata idempotent", func(t *testing.T) {
		v := event
		body := "synthetic content"
		v.Prompt = &body
		requireHTTP(t, batch(v), 409)
		requireHTTP(t, batch(event), 200)
		requireHTTP(t, batch(event), 200)
		w := call("GET", "/api/shadow/cartography?tool=chrome&tool=firefox", nil, "")
		requireHTTP(t, w, 200)
		var graph struct {
			Totals struct {
				Requests    int `json:"requests"`
				Navigations int `json:"navigations"`
			} `json:"totals"`
			Flows []any `json:"flows"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &graph)
		if graph.Totals.Requests != 1 || len(graph.Flows) != 1 || graph.Totals.Navigations != 0 {
			t.Fatalf("graph totals mismatch: %s", w.Body.String())
		}
		nav := event
		nav.ID = "33333333-3333-4333-8333-333333333333"
		nav.Kind = "navigation"
		nav.Labels = []string{}
		requireHTTP(t, batch(nav), 200)
		w = call("GET", "/api/shadow/events?kind=prompt&tool=chrome&tool=firefox", nil, "")
		requireHTTP(t, w, 200)
		var list struct {
			Items []ShadowEventView `json:"items"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &list)
		// Community reports no usage sensitivity at all; Enterprise still derives it.
		wantSensitivity := ""
		if Edition == "commercial" {
			wantSensitivity = "sensitive"
		}
		if len(list.Items) != 1 || list.Items[0].Sensitivity != wantSensitivity {
			t.Fatalf("filter mismatch %s", w.Body.String())
		}
		if Edition != "commercial" {
			if strings.Contains(w.Body.String(), `"sensitivity"`) {
				t.Fatal("community response still carries a sensitivity field")
			}
			requireHTTP(t, call("GET", "/api/shadow/events?sensitivity=sensitive", nil, ""), 409)
		}
	})
	// Without a verified association the journal named a person by the OS account of
	// the record while the map answered "unattributed" for everyone, because the
	// account is sealed per event and an aggregate cannot group ciphertexts. The
	// groupable digest is what closes that gap, and it has to survive the two
	// spellings one person's machines report.
	t.Run("the map groups and names people by the OS account when no association is verified", func(t *testing.T) {
		// Registered first so the tenant context outlives the cleanups below: a
		// delete on a table under FORCE row level security without it matches no
		// row and still reports success.
		setTenant(t, admin, org)
		accounts := []struct{ id, account string }{
			{"55555555-5555-4555-8555-555555555551", "corp\\analyst-one"},
			{"55555555-5555-4555-8555-555555555552", "CORP\\analyst-one"},
			{"55555555-5555-4555-8555-555555555553", "CORP\\analyst-two"},
		}
		// Past timestamps: the default period ends at the moment of the read, so an
		// event stamped a second ahead would fall outside the map it is meant to fill.
		for i, row := range accounts {
			v := event
			v.ID, v.User = row.id, row.account
			v.OccurredAt = now.Add(time.Duration(i-len(accounts)) * time.Second)
			v.ConversationID = "synthetic-os-" + row.id
			v.CorrelationID = "synthetic-os-" + row.id
			requireHTTP(t, batch(v), 200)
		}
		t.Cleanup(func() {
			for _, row := range accounts {
				_, _ = admin.Exec(ctx, "DELETE FROM shadow_events WHERE id=$1", row.id)
			}
		})
		type flow struct {
			ActorID   string `json:"actor_id"`
			ActorName string `json:"actor_name"`
			Count     int    `json:"count"`
		}
		graph := func(query string) []flow {
			w := call("GET", "/api/shadow/cartography?"+query, nil, "")
			requireHTTP(t, w, 200)
			var out struct {
				Flows  []flow `json:"flows"`
				Totals struct {
					Actors int `json:"actors"`
				} `json:"totals"`
			}
			if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
				t.Fatal(e)
			}
			people := []flow{}
			for _, f := range out.Flows {
				if strings.HasPrefix(f.ActorID, "os:") {
					people = append(people, f)
				}
			}
			if len(people) > 0 && out.Totals.Actors < len(people) {
				t.Fatalf("named %d people but counted %d actors: %s", len(people), out.Totals.Actors, w.Body.String())
			}
			return people
		}
		// A pseudonymous organization is the default, and it withholds the account
		// exactly as the journal does — while still telling the two people apart.
		pseudonymous := graph("kind=prompt")
		if len(pseudonymous) != 2 {
			t.Fatalf("two OS accounts expected, got %d: %+v", len(pseudonymous), pseudonymous)
		}
		for _, f := range pseudonymous {
			if !strings.HasPrefix(f.ActorName, "Account ") || strings.Contains(f.ActorName, "analyst") {
				t.Fatalf("a pseudonymous map names an account: %+v", f)
			}
		}
		if pseudonymous[0].ActorName == pseudonymous[1].ActorName {
			t.Fatalf("two accounts share one alias: %+v", pseudonymous)
		}
		if _, e := admin.Exec(ctx, `INSERT INTO privacy_settings(organization_id,configuration) VALUES($1,jsonb_build_object('pseudonymous',false))
			ON CONFLICT(organization_id) DO UPDATE SET configuration=privacy_settings.configuration||jsonb_build_object('pseudonymous',false),revision=privacy_settings.revision+1`, org); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() {
			if _, e := admin.Exec(ctx, `UPDATE privacy_settings SET configuration=configuration||jsonb_build_object('pseudonymous',true),revision=revision+1 WHERE organization_id=$1`, org); e != nil {
				t.Errorf("could not restore pseudonymity: %v", e)
			}
		})
		people := graph("kind=prompt")
		if len(people) != 2 {
			t.Fatalf("two OS accounts expected, got %d: %+v", len(people), people)
		}
		byName := map[string]flow{}
		for _, f := range people {
			byName[f.ActorName] = f
		}
		// The most recent spelling names the person; both records are counted as one.
		one, two := byName["CORP\\analyst-one"], byName["CORP\\analyst-two"]
		if one.Count != 2 {
			t.Fatalf("the two spellings of one account did not merge: %+v", people)
		}
		if two.Count != 1 || one.ActorID == two.ActorID {
			t.Fatalf("two accounts did not separate: %+v", people)
		}
		// The bucket is what the map hands the journal when a person is clicked.
		narrowed := graph("kind=prompt&actor_id=" + url.QueryEscape(one.ActorID))
		if len(narrowed) != 1 || narrowed[0].ActorID != one.ActorID || narrowed[0].Count != 2 {
			t.Fatalf("the map's own selection did not narrow: %+v", narrowed)
		}
		w := call("GET", "/api/shadow/events?kind=prompt&actor_id="+url.QueryEscape(one.ActorID), nil, "")
		requireHTTP(t, w, 200)
		var list struct {
			Items []ShadowEventView `json:"items"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &list)
		if len(list.Items) != 2 {
			t.Fatalf("the journal does not accept the map's person: %s", w.Body.String())
		}
		// An aliased read names nobody, and still tells the two people apart.
		aliased := graph("kind=prompt&identity=aliases")
		if len(aliased) != 2 {
			t.Fatalf("aliases lost the people: %+v", aliased)
		}
		for _, f := range aliased {
			if !strings.HasPrefix(f.ActorName, "Account ") || strings.Contains(f.ActorName, "analyst") {
				t.Fatalf("an aliased map still names an account: %+v", f)
			}
		}
		if aliased[0].ActorName == aliased[1].ActorName {
			t.Fatalf("two accounts share one alias: %+v", aliased)
		}
	})
	t.Run("shadow MFA activation ciphertext explicit grants purge", func(t *testing.T) {
		cfg = getConfig()
		cfg.Config.Collection.StoreContent = true
		w := call("PUT", "/api/shadow/settings", map[string]any{"revision": cfg.Revision, "config": cfg.Config, "inherit_sections": []string{}}, "")
		requireHTTP(t, w, 403)
		// A second factor from a sign-in an hour ago is not enough to switch retention on.
		if _, e := admin.Exec(ctx, `UPDATE sessions SET mfa=true,mfa_verified_at=now()-interval '1 hour' WHERE token_hash=$1`, hash(cookie.Value)); e != nil {
			t.Fatal(e)
		}
		requireHTTP(t, call("PUT", "/api/shadow/settings", map[string]any{"revision": cfg.Revision, "config": cfg.Config, "inherit_sections": []string{}}, ""), 403)
		if _, e := admin.Exec(ctx, `UPDATE sessions SET mfa=true,mfa_verified_at=now() WHERE token_hash=$1`, hash(cookie.Value)); e != nil {
			t.Fatal(e)
		}
		w = call("PUT", "/api/shadow/settings", map[string]any{"revision": cfg.Revision, "config": cfg.Config, "inherit_sections": []string{}}, "")
		requireHTTP(t, w, 200)
		// Back to a sign-in-time factor: the purge below must see a stale one.
		if _, e := admin.Exec(ctx, `UPDATE sessions SET mfa_verified_at=NULL WHERE token_hash=$1`, hash(cookie.Value)); e != nil {
			t.Fatal(e)
		}
		cfg = getConfig()
		if cfg.Revision <= event.PolicyRevision {
			t.Fatal("revision failed to advance")
		}
		v := event
		v.ID = "44444444-4444-4444-8444-444444444444"
		text := "Synthetic private conversation body"
		v.Prompt = &text
		v.PolicyRevision = cfg.Revision
		requireHTTP(t, batch(v), 200)
		var encrypted []byte
		if e := admin.QueryRow(ctx, `SELECT encrypted FROM shadow_content WHERE event_id=$1`, v.ID).Scan(&encrypted); e != nil {
			t.Fatal(e)
		}
		if bytes.Contains(encrypted, []byte(text)) {
			t.Fatal("plaintext in content storage")
		}
		path := "/api/shadow/events/" + v.ID + "?device_id=" + id
		w = call("GET", path, nil, "")
		requireHTTP(t, w, 200)
		// The owner now holds content.read through their role (product decision,
		// 2026-09-15), and it still buys nothing here: the actor's identity was never
		// revealed, and pseudonymity is checked before the right to read.
		if strings.Contains(w.Body.String(), text) {
			t.Fatal("content permission bypassed pseudonymous identity protection")
		}
		// A role without content.read reads nothing either, whatever else it may do.
		if _, e := admin.Exec(ctx, `UPDATE memberships SET role='viewer' WHERE organization_id=$1 AND user_id=$2`, org, user); e != nil {
			t.Fatal(e)
		}
		w = call("GET", path, nil, "")
		if strings.Contains(w.Body.String(), text) {
			t.Fatal("a role without content.read still reads")
		}
		if _, e := admin.Exec(ctx, `UPDATE memberships SET role='owner' WHERE organization_id=$1 AND user_id=$2`, org, user); e != nil {
			t.Fatal(e)
		}
		// Purging demands a FRESH second factor, not merely one presented at sign-in.
		// This session carries mfa=true and has never re-verified, which is what an
		// eight-hour-old session looks like: it must be refused. Until 2026-09-21 the
		// handler checked s.MFA alone and answered 200 here.
		requireHTTP(t, call("POST", "/api/shadow/content/purge", map[string]any{"before": time.Now().UTC()}, ""), 403)
		if _, e := admin.Exec(ctx, `UPDATE sessions SET mfa_verified_at=clock_timestamp() WHERE token_hash=$1`, hash(cookie.Value)); e != nil {
			t.Fatal(e)
		}
		requireHTTP(t, call("POST", "/api/shadow/content/purge", map[string]any{"before": time.Now().UTC()}, ""), 200)
		var count int
		if e := admin.QueryRow(ctx, `SELECT count(*) FROM shadow_content`).Scan(&count); e != nil || count != 0 {
			t.Fatal("content purge failed", e)
		}
		cfg = getConfig()
		cfg.Config.Collection.StoreContent = false
		requireHTTP(t, call("PUT", "/api/shadow/settings", map[string]any{"revision": cfg.Revision, "config": cfg.Config, "inherit_sections": []string{}}, ""), 200)
		v.ID = "55555555-5555-4555-8555-555555555555"
		requireHTTP(t, batch(v), 409)
		if _, e := admin.Exec(ctx, `UPDATE sessions SET mfa=false WHERE token_hash=$1`, hash(cookie.Value)); e != nil {
			t.Fatal(e)
		}
		cfg = getConfig()
	})
	t.Run("shadow saved filters metadata exports and unsupported operations", func(t *testing.T) {
		w := call("POST", "/api/shadow/filters", map[string]any{"name": "Synthetic browsers", "shared": false, "criteria": map[string]any{"tool": []string{"chrome", "firefox"}, "kind": "prompt"}}, "")
		requireHTTP(t, w, 201)
		requireHTTP(t, call("GET", "/api/shadow/filters", nil, ""), 200)
		for _, format := range []string{"json", "csv"} {
			w = call("GET", "/api/shadow/export?format="+format+"&kind=prompt", nil, "")
			requireHTTP(t, w, 200)
			if strings.Contains(w.Body.String(), "Synthetic private conversation body") {
				t.Fatal("metadata export leaked content")
			}
		}
		// The printed report is the console's, built from the cartography aggregates
		// and printed by the browser (product decision, 2026-09-17). `pdf` is therefore an
		// unknown format like any other, and the one-page Helvetica summary is gone.
		requireHTTP(t, call("GET", "/api/shadow/export?format=pdf&kind=prompt", nil, ""), 400)
		// Enabling the update channel with no delivery chain configured is stored,
		// not refused. `enabled` is an intent and availability is a capability: the
		// two are resolved separately, and applicableUpdate requires both, so the
		// stored intent delivers nothing. Refusing the save would make a deployment
		// without a release directory unable to save any Shadow AI setting at all,
		// because Enterprise now defaults this channel on and every round-trip of
		// its own configuration would come back 409.
		cfg = getConfig()
		cfg.Config.Operations.Updates.Enabled = true
		// Both editions persist this choice; delivery still requires a signed release.
		requireHTTP(t, call("PUT", "/api/shadow/settings", map[string]any{"revision": cfg.Revision, "config": cfg.Config, "inherit_sections": []string{}}, ""), 200)
		cfg = getConfig()
		if !cfg.Config.Operations.Updates.Enabled {
			t.Fatal("the stored intent was silently dropped")
		}
		if cfg.Capabilities["signed_updates"] {
			t.Fatal("no delivery chain is configured, so the capability must be false")
		}
		// And the channel stays inert: the server still reports it unavailable.
		operations := call("GET", "/api/shadow/operations", nil, "")
		requireHTTP(t, operations, 200)
		if strings.Contains(operations.Body.String(), `"available":true`) {
			t.Fatalf("an intent without a chain was reported as available: %s", operations.Body.String())
		}
		cfg.Config.Operations.Updates.Enabled = false
		requireHTTP(t, call("PUT", "/api/shadow/settings", map[string]any{"revision": cfg.Revision, "config": cfg.Config, "inherit_sections": []string{}}, ""), 200)
		cfg = getConfig()
		if cfg.Config.Operations.Updates.Enabled {
			t.Fatal("the update opt-out was not persisted")
		}
	})
	t.Run("shadow Community rejects native composition", func(t *testing.T) {
		v := event
		v.ID = "66666666-6666-4666-8666-666666666666"
		v.Source = "native"
		v.Tool = "claude-code"
		v.PolicyRevision = cfg.Revision
		requireHTTP(t, batch(v), 403)
	})
	t.Run("shadow endpoint overrides and Enterprise inheritance", func(t *testing.T) {
		if getConfig().Capabilities["organization_inheritance"] {
			t.Fatal("organization without a parent advertised inheritance")
		}
		w := call("GET", "/api/devices/"+id+"/shadow", nil, "")
		requireHTTP(t, w, 200)
		var effective ShadowSettings
		_ = json.Unmarshal(w.Body.Bytes(), &effective)
		p := effective.Config.Protection
		p.BlockUploads = true
		requireHTTP(t, call("PUT", "/api/devices/"+id+"/shadow", map[string]any{"revision": effective.Revision, "config": map[string]any{"protection": p}, "inherit_sections": []string{}}, ""), 200)
		w = call("GET", "/api/devices/"+id+"/shadow", nil, "")
		requireHTTP(t, w, 200)
		_ = json.Unmarshal(w.Body.Bytes(), &effective)
		if !effective.Config.Protection.BlockUploads {
			t.Fatal("device override not effective")
		}
		requireHTTP(t, call("PUT", "/api/devices/"+id+"/shadow", map[string]any{"revision": effective.Revision, "config": map[string]any{}, "inherit_sections": []string{"protection"}}, ""), 200)
		if Edition == "community" {
			cfg = getConfig()
			requireHTTP(t, call("PUT", "/api/shadow/settings", map[string]any{"revision": cfg.Revision, "config": cfg.Config, "inherit_sections": []string{"protection"}}, ""), 400)
			return
		}
		cfg = getConfig()
		cfg.Config.Protection.Message = "Synthetic parent policy"
		requireHTTP(t, call("PUT", "/api/shadow/settings", map[string]any{"revision": cfg.Revision, "config": cfg.Config, "inherit_sections": []string{}}, ""), 200)
		w = call("POST", "/api/organizations", map[string]any{"name": "Synthetic child", "parent_id": org}, "")
		requireHTTP(t, w, 201)
		var child Organization
		_ = json.Unmarshal(w.Body.Bytes(), &child)
		requireHTTP(t, call("POST", "/api/session/organization", map[string]string{"organization_id": child.ID}, ""), 200)
		cfg = getConfig()
		if !cfg.Capabilities["organization_inheritance"] || len(cfg.InheritSections) != 0 {
			t.Fatal("new child must advertise inheritance before any section is inherited")
		}
		requireHTTP(t, call("PUT", "/api/shadow/settings", map[string]any{"revision": cfg.Revision, "config": cfg.Config, "inherit_sections": []string{"protection"}}, ""), 200)
		cfg = getConfig()
		if cfg.Config.Protection.Message != "Synthetic parent policy" || cfg.InheritedFrom["protection"].OrganizationID != org {
			t.Fatal("parent policy not resolved")
		}
		// Inheriting a parent that enables content still requires MFA at the child.
		requireHTTP(t, call("POST", "/api/session/organization", map[string]string{"organization_id": org}, ""), 200)
		if _, e := admin.Exec(ctx, `UPDATE sessions SET mfa=true,mfa_verified_at=now() WHERE token_hash=$1`, hash(cookie.Value)); e != nil {
			t.Fatal(e)
		}
		parentConfig := getConfig()
		parentConfig.Config.Collection.StoreContent = true
		requireHTTP(t, call("PUT", "/api/shadow/settings", map[string]any{"revision": parentConfig.Revision, "config": parentConfig.Config, "inherit_sections": []string{}}, ""), 200)
		if _, e := admin.Exec(ctx, `UPDATE sessions SET mfa=false WHERE token_hash=$1`, hash(cookie.Value)); e != nil {
			t.Fatal(e)
		}
		requireHTTP(t, call("POST", "/api/session/organization", map[string]string{"organization_id": child.ID}, ""), 200)
		cfg = getConfig()
		requireHTTP(t, call("PUT", "/api/shadow/settings", map[string]any{"revision": cfg.Revision, "config": cfg.Config, "inherit_sections": []string{"protection", "collection"}}, ""), 403)
		requireHTTP(t, call("POST", "/api/session/organization", map[string]string{"organization_id": org}, ""), 200)
		parentConfig = getConfig()
		parentConfig.Config.Collection.StoreContent = false
		requireHTTP(t, call("PUT", "/api/shadow/settings", map[string]any{"revision": parentConfig.Revision, "config": parentConfig.Config, "inherit_sections": []string{}}, ""), 200)
		requireHTTP(t, call("POST", "/api/session/organization", map[string]string{"organization_id": child.ID}, ""), 200)
		cfg = getConfig()
		w = call("GET", "/api/shadow/events", nil, "")
		requireHTTP(t, w, 200)
		var list struct {
			Items []ShadowEventView `json:"items"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &list)
		if len(list.Items) != 0 {
			t.Fatal("child read parent events")
		}
		w = call("POST", "/api/enrollments", map[string]string{"label": "Synthetic native"}, "")
		requireHTTP(t, w, 201)
		var prov map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &prov)
		w = call("POST", "/v2/enroll", map[string]any{"token": prov["token"], "hostname": "native-test", "platform": "linux", "version": "0.2.0", "kind": "native", "capabilities": []string{"native.conversations"}}, "")
		requireHTTP(t, w, 201)
		var native map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &native)
		requireHTTP(t, call("POST", "/api/devices/"+native["device_id"]+"/approve", map[string]any{}, ""), 200)
		v := event
		v.ID = "88888888-8888-4888-8888-888888888888"
		v.Source = "native"
		v.Tool = "claude-code"
		v.PolicyRevision = cfg.Revision
		requireHTTP(t, call("POST", "/v2/events", map[string]any{"events": []V2Event{v}}, native["credential"]), 200)
		// A device of the parent organization cannot complete an event of the child:
		// the update runs in the authenticated installation's own tenant transaction
		// and is pinned to its organization and its device.
		crossing := call("POST", "/v2/events/complete", map[string]any{"completions": []map[string]any{{"id": v.ID, "model": "crossed-model"}}}, credential)
		requireHTTP(t, crossing, 200)
		if !strings.Contains(crossing.Body.String(), `"applied_ids":[]`) {
			t.Fatal("a completion crossed an organization", crossing.Body.String())
		}
		var crossed string
		childTx, e := tenantTx(ctx, a.db, child.ID)
		if e != nil {
			t.Fatal(e)
		}
		e = childTx.QueryRow(ctx, "SELECT model FROM shadow_events WHERE id=$1", v.ID).Scan(&crossed)
		childTx.Rollback(ctx)
		if e != nil || crossed != "" {
			t.Fatal("cross-organization completion reached the event", crossed, e)
		}
		// Parent authority remains valid without a direct child membership.
		tx, err := tenantTx(ctx, a.db, child.ID)
		if err != nil {
			t.Fatal(err)
		}
		tag, err := tx.Exec(ctx, "DELETE FROM memberships WHERE organization_id=$1 AND user_id=$2", child.ID, user)
		if err != nil || tag.RowsAffected() != 1 {
			tx.Rollback(ctx)
			t.Fatal("direct child membership fixture absent", err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, e := admin.Exec(ctx, "UPDATE sessions SET organization_id=$1 WHERE token_hash=$2", org, hash(cookie.Value))
			if e != nil {
				t.Error(e)
			}
		})
		w = call("GET", "/api/shadow/events/"+v.ID+"?device_id="+native["device_id"], nil, "")
		requireHTTP(t, w, 200)
		var detail struct {
			CanReadContent bool            `json:"can_read_content"`
			Event          ShadowEventView `json:"event"`
		}
		if err = json.Unmarshal(w.Body.Bytes(), &detail); err != nil || detail.CanReadContent || !strings.Contains(w.Body.String(), v.ID) {
			t.Fatal("inherited metadata access failed or granted content", err, w.Body.String())
		}
		tx, err = tenantTx(ctx, a.db, child.ID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, "INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')", child.ID, user); err != nil {
			tx.Rollback(ctx)
			t.Fatal(err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		requireHTTP(t, call("POST", "/api/session/organization", map[string]string{"organization_id": org}, ""), 200)
		cfg = getConfig()
		w = call("GET", "/api/shadow/events?tool=claude-code", nil, "")
		requireHTTP(t, w, 200)
		_ = json.Unmarshal(w.Body.Bytes(), &list)
		if len(list.Items) != 0 {
			t.Fatal("parent read child native events")
		}
	})
	t.Run("shadow signed release offer artifact and kill switch", func(t *testing.T) {
		// Exercise the signed delivery chain in both editions.
		oldKey := a.config.UpdatePublicKey
		defer func() { a.config.UpdatePublicKey = oldKey }()
		dir := t.TempDir()
		t.Setenv("MILVAGO_INSTALLER_DIRECTORY", dir)
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
		a.config.UpdatePublicKey = key.Public().(ed25519.PublicKey)
		// The update artifact is the installer the console serves, located through the
		// unsigned install manifest and authorized by the signed one.
		artifact := []byte("synthetic signed artifact fixture")
		digest := sha256.Sum256(artifact)
		sha := hex.EncodeToString(digest[:])
		// The server picks the release edition from the *device kind*, not from the build
		// (applicableUpdate: a native device maps to commercial, everything else to
		// community). A fixture naming one edition therefore only ever satisfies one of
		// the two runs, which is why this subtest failed under -tags commercial. Both are
		// published instead, so the assertion tests the offer rather than the fixture.
		name := "milvago-release-0.2.1-linux.tar.gz"
		if e := os.WriteFile(filepath.Join(dir, name), artifact, 0600); e != nil {
			t.Fatal(e)
		}
		install, _ := json.Marshal(InstallerBundle{Version: "0.2.1", Artifact: name, SHA256: sha, Size: int64(len(artifact))})
		var manifest UpdateManifest
		for _, release := range []string{"community", "commercial"} {
			if e := os.WriteFile(filepath.Join(dir, release+"-linux.json"), install, 0600); e != nil {
				t.Fatal(e)
			}
			manifest = UpdateManifest{Version: "0.2.1", Edition: release, Platform: "linux", Protocol: 2, SHA256: sha, Size: int64(len(artifact)), ExpiresAt: time.Now().Add(time.Hour), Artifact: "/v2/update/artifact/" + sha, RollbackFrom: []string{}}
			payload, _ := json.Marshal(manifest)
			envelope := signedEnvelope{base64.StdEncoding.EncodeToString(payload), base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload))}
			raw, _ := json.Marshal(envelope)
			if e := os.WriteFile(filepath.Join(dir, release+"-linux-update.json"), raw, 0600); e != nil {
				t.Fatal(e)
			}
		}
		// The successor trust anchor is published only when it verifies against the
		// anchor already configured; anything else is silently absent, never guessed.
		requireHTTP(t, call("GET", "/v2/update/anchor", nil, credential), 204)
		successor := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, 32)).Public().(ed25519.PublicKey)
		anchorPayload, _ := json.Marshal(map[string]any{"next_public_key": base64.StdEncoding.EncodeToString(successor), "expires_at": time.Now().Add(time.Hour)})
		anchor, _ := json.Marshal(signedEnvelope{base64.StdEncoding.EncodeToString(anchorPayload), base64.StdEncoding.EncodeToString(ed25519.Sign(key, anchorPayload))})
		if e := os.WriteFile(filepath.Join(dir, "anchor.json"), anchor, 0600); e != nil {
			t.Fatal(e)
		}
		requireHTTP(t, call("GET", "/v2/update/anchor", nil, credential), 200)
		forged, _ := json.Marshal(signedEnvelope{base64.StdEncoding.EncodeToString(anchorPayload), base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{12}, 32)), anchorPayload))})
		if e := os.WriteFile(filepath.Join(dir, "anchor.json"), forged, 0600); e != nil {
			t.Fatal(e)
		}
		requireHTTP(t, call("GET", "/v2/update/anchor", nil, credential), 204)
		if e := os.Remove(filepath.Join(dir, "anchor.json")); e != nil {
			t.Fatal(e)
		}
		if _, e := admin.Exec(ctx, `UPDATE devices SET platform='linux' WHERE id=$1`, id); e != nil {
			t.Fatal(e)
		}
		cfg = getConfig()
		cfg.Config.Operations.Updates.Enabled = true
		cfg.Config.Operations.Updates.Percentage = 100
		requireHTTP(t, call("PUT", "/api/shadow/settings", map[string]any{"revision": cfg.Revision, "config": cfg.Config, "inherit_sections": []string{}}, ""), 200)
		requireHTTP(t, call("GET", "/v2/update", nil, credential), 200)
		var previousVersion, reportedVersion, reportedStatus string
		if e := admin.QueryRow(ctx, `SELECT version FROM devices WHERE id=$1`, id).Scan(&previousVersion); e != nil {
			t.Fatal(e)
		}
		requireHTTP(t, call("POST", "/v2/update/status", map[string]any{"version": "0.2.1", "status": "reboot_required"}, credential), 200)
		if e := admin.QueryRow(ctx, `SELECT version,update_status FROM devices WHERE id=$1`, id).Scan(&reportedVersion, &reportedStatus); e != nil || reportedVersion != previousVersion || reportedStatus != "reboot_required" {
			t.Fatal("pending reboot must preserve installed version", e)
		}
		w := call("GET", manifest.Artifact, nil, credential)
		requireHTTP(t, w, 200)
		if !bytes.Equal(w.Body.Bytes(), artifact) {
			t.Fatal("artifact changed")
		}
		// Same length, different bytes: only the digest check can catch this. The
		// release stops being offered at all, so the artifact route reports that no
		// authorized release matches rather than serving anything.
		if e := os.WriteFile(filepath.Join(dir, name), bytes.Repeat([]byte{'x'}, len(artifact)), 0600); e != nil {
			t.Fatal(e)
		}
		requireHTTP(t, call("GET", "/v2/update", nil, credential), 204)
		requireHTTP(t, call("GET", manifest.Artifact, nil, credential), 404)
		if e := os.WriteFile(filepath.Join(dir, name), artifact, 0600); e != nil {
			t.Fatal(e)
		}
		cfg = getConfig()
		cfg.Config.Operations.Updates.PausedVersions = []string{"0.2.1"}
		requireHTTP(t, call("PUT", "/api/shadow/settings", map[string]any{"revision": cfg.Revision, "config": cfg.Config, "inherit_sections": []string{}}, ""), 200)
		requireHTTP(t, call("GET", "/v2/update", nil, credential), 204)
		cfg = getConfig()
		// Remove the pause and prove an offer exists before testing the kill switch.
		cfg.Config.Operations.Updates.PausedVersions = []string{}
		requireHTTP(t, call("PUT", "/api/shadow/settings", map[string]any{"revision": cfg.Revision, "config": cfg.Config, "inherit_sections": []string{}}, ""), 200)
		requireHTTP(t, call("GET", "/v2/update", nil, credential), 200)
		cfg = getConfig()
		cfg.Config.Operations.Updates.Enabled = false
		requireHTTP(t, call("PUT", "/api/shadow/settings", map[string]any{"revision": cfg.Revision, "config": cfg.Config, "inherit_sections": []string{}}, ""), 200)
		requireHTTP(t, call("GET", "/v2/update", nil, credential), 204)
		cfg = getConfig()
	})
	t.Run("update routes carry a per-device budget", func(t *testing.T) {
		// A second device, so the shared one keeps its untouched budget.
		enrollment := call("POST", "/api/enrollments", map[string]string{"label": "Budget device"}, "")
		requireHTTP(t, enrollment, 201)
		var provision map[string]string
		_ = json.Unmarshal(enrollment.Body.Bytes(), &provision)
		enrolled := call("POST", "/v2/enroll", map[string]any{"token": provision["token"], "hostname": "budget-device", "platform": "test", "version": "0.2.0", "kind": "browser", "capabilities": []string{"browser.navigation"}}, "")
		requireHTTP(t, enrolled, 201)
		var device map[string]string
		_ = json.Unmarshal(enrolled.Body.Bytes(), &device)
		budgetCredential, budgetID := device["credential"], device["device_id"]
		requireHTTP(t, call("POST", "/api/devices/"+budgetID+"/approve", map[string]any{}, ""), 200)
		// Twelve manifest polls a minute is far above the agent's one per minute;
		// the thirteenth is refused in deviceTx, before any release work.
		for i := 0; i < 12; i++ {
			requireHTTP(t, call("GET", "/v2/update", nil, budgetCredential), 204)
		}
		requireHTTP(t, call("GET", "/v2/update", nil, budgetCredential), 429)
		// The artifact path carries the release digest, so the budget map could
		// never match it literally: every spelling shares the one artifact
		// budget, which is what the normalization proves — six misspellings pass,
		// the seventh is refused.
		for i := 0; i < 6; i++ {
			requireHTTP(t, call("GET", "/v2/update/artifact/"+strings.Repeat(string(rune('a'+i)), 64), nil, budgetCredential), 404)
		}
		requireHTTP(t, call("GET", "/v2/update/artifact/"+strings.Repeat("f", 64), nil, budgetCredential), 429)
	})
	t.Run("heartbeat", func(t *testing.T) {
		requireHTTP(t, call("POST", "/v2/heartbeat", map[string]any{"os_user": "poste-user"}, ""), 401)
		var auditBefore, auditAfter int
		if e := admin.QueryRow(ctx, `SELECT count(*) FROM audit WHERE action LIKE 'device.%' OR action='update.report'`).Scan(&auditBefore); e != nil {
			t.Fatal(e)
		}
		var previousVersion, previousStatus, previousHostname string
		if e := admin.QueryRow(ctx, `SELECT version,update_status,hostname FROM devices WHERE id=$1`, id).Scan(&previousVersion, &previousStatus, &previousHostname); e != nil {
			t.Fatal(e)
		}
		requireHTTP(t, call("POST", "/v2/heartbeat", map[string]any{"os_user": "poste-user"}, credential), 200)
		var osUser string
		var lastSeen *time.Time
		if e := admin.QueryRow(ctx, `SELECT os_user,last_seen FROM devices WHERE id=$1`, id).Scan(&osUser, &lastSeen); e != nil || osUser == "poste-user" || osUser == "" || lastSeen == nil {
			t.Fatal("heartbeat did not persist os_user or last_seen", e)
		}
		w := call("GET", "/api/devices", nil, "")
		requireHTTP(t, w, 200)
		if strings.Contains(w.Body.String(), "poste-user") {
			t.Fatal("console disclosed an OS identity in pseudonymous mode")
		}
		plainUser, e := a.openIdentity(org, "device-user:"+id, osUser)
		if e != nil || plainUser != "poste-user" {
			t.Fatal("sealed OS user did not round trip", e)
		}
		requireHTTP(t, call("POST", "/v2/heartbeat", map[string]any{"os_user": "x", "status": "approved"}, credential), 400)
		requireHTTP(t, call("POST", "/v2/heartbeat", map[string]any{"os_user": "ab"}, credential), 400)
		requireHTTP(t, call("POST", "/v2/heartbeat", map[string]any{"os_user": strings.Repeat("a", 129)}, credential), 400)
		requireHTTP(t, call("POST", "/v2/heartbeat", map[string]any{"os_user": "  spaced  "}, credential), 200)
		if e := admin.QueryRow(ctx, `SELECT os_user FROM devices WHERE id=$1`, id).Scan(&osUser); e != nil {
			t.Fatal(e)
		}
		plainUser, e = a.openIdentity(org, "device-user:"+id, osUser)
		if e != nil || plainUser != "spaced" {
			t.Fatal("heartbeat did not trim and seal OS user", e)
		}
		var version, updateStatus, hostname string
		if e := admin.QueryRow(ctx, `SELECT version,update_status,hostname FROM devices WHERE id=$1`, id).Scan(&version, &updateStatus, &hostname); e != nil || version != previousVersion || updateStatus != previousStatus || hostname != previousHostname {
			t.Fatal("heartbeat changed unrelated device fields", e)
		}
		if e := admin.QueryRow(ctx, `SELECT count(*) FROM audit WHERE action LIKE 'device.%' OR action='update.report'`).Scan(&auditAfter); e != nil {
			t.Fatal(e)
		}
		if auditAfter != auditBefore {
			t.Fatal("heartbeat added an audit row")
		}
	})
	t.Run("heartbeat accepts every state the collector writes", func(t *testing.T) {
		// A state the server refused turned the whole heartbeat into a 400, and the agent
		// then fell back to os_user alone: browsers and collector health froze.
		for _, state := range []string{"unexpected_metrics", "throttled"} {
			body := map[string]any{"os_user": "poste-user", "collector_health": []map[string]any{{"tool": "otlp", "state": state}}}
			if Edition != "commercial" {
				requireHTTP(t, call("POST", "/v2/heartbeat", body, credential), 400)
				continue
			}
			requireHTTP(t, call("POST", "/v2/heartbeat", body, credential), 200)
			var stored string
			if e := admin.QueryRow(ctx, `SELECT collector_health::text FROM devices WHERE id=$1`, id).Scan(&stored); e != nil || !strings.Contains(stored, state) {
				t.Fatal("collector state not recorded", state, stored, e)
			}
		}
		unknown := map[string]any{"os_user": "poste-user", "collector_health": []map[string]any{{"tool": "otlp", "state": "invented"}}}
		requireHTTP(t, call("POST", "/v2/heartbeat", unknown, credential), 400)
	})
	t.Run("shadow OIDC association without console membership", func(t *testing.T) {
		w := call("POST", "/v2/identity/start", nil, credential)
		requireHTTP(t, w, 200)
		var link struct {
			URL string `json:"verification_url"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &link)
		u, _ := url.Parse(link.URL)
		w = call("GET", u.RequestURI(), nil, "")
		requireHTTP(t, w, 200)
		var confirm *http.Cookie
		for _, c := range w.Result().Cookies() {
			if c.Name == cookieName("association") {
				confirm = c
			}
		}
		if confirm == nil {
			t.Fatal("missing confirmation binding")
		}
		form := url.Values{"token": {u.Query().Get("token")}, "confirmation": {confirm.Value}}
		r := httptest.NewRequest("POST", "/auth/device", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", a.config.AppURL)
		r.AddCookie(confirm)
		w = httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		requireHTTP(t, w, 302)
		authorize, _ := url.Parse(w.Header().Get("Location"))
		p.nonce = authorize.Query().Get("nonce")
		p.challenge = authorize.Query().Get("code_challenge")
		oldSubject, oldEmail := p.subject, p.email
		p.subject = "synthetic-collaborator"
		p.email = "collaborator@example.test"
		defer func() { p.subject = oldSubject; p.email = oldEmail }()
		var loginCookie *http.Cookie
		for _, c := range w.Result().Cookies() {
			if c.Name == cookieName("login") {
				loginCookie = c
			}
		}
		r = httptest.NewRequest("GET", "/auth/callback?code=test-code&state="+url.QueryEscape(authorize.Query().Get("state")), nil)
		r.AddCookie(loginCookie)
		w = httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		requireHTTP(t, w, 200)
		var count int
		if e := admin.QueryRow(ctx, `SELECT count(*) FROM memberships m JOIN users u ON u.id=m.user_id WHERE u.subject='synthetic-collaborator'`).Scan(&count); e != nil || count != 0 {
			t.Fatal("association created membership", e)
		}
		v := event
		v.ID = "77777777-7777-4777-8777-777777777777"
		v.OccurredAt = time.Now().UTC()
		v.PolicyRevision = cfg.Revision
		requireHTTP(t, batch(v), 200)
		var actor *string
		if e := admin.QueryRow(ctx, `SELECT collaborator_id FROM shadow_events WHERE id=$1`, v.ID).Scan(&actor); e != nil || actor == nil {
			t.Fatal("verified actor absent", e)
		}
		requireHTTP(t, call("DELETE", "/v2/identity", nil, credential), 200)
	})
	requireHTTP(t, call("POST", "/api/devices/"+id+"/revoke", map[string]any{}, ""), 200)
	requireHTTP(t, batch(event), 401)
}
