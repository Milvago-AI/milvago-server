package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// addThreadEvent writes one record straight into the tables, so a test can build
// the exact shape a browser produces -- including the opening prompt that carries
// no conversation identifier because the tab was still on /new when the gesture
// was captured. A non empty text is sealed the way ingestion seals it.
type threadEvent struct {
	at                                            time.Time
	kind, conversation, correlation, action, text string
}

func addThreadEvent(t *testing.T, f *observabilityFixture, subject, device string, event threadEvent) string {
	t.Helper()
	at, kind, conversation, correlation, action, text := event.at, event.kind, event.conversation, event.correlation, event.action, event.text
	ctx := context.Background()
	var id string
	e := f.admin.QueryRow(ctx, `INSERT INTO shadow_events(organization_id,device_id,id,occurred_at,kind,provider,tool,source,action,policy_revision,characters,sensitivity,collaborator_id,conversation_id,correlation_id)
		VALUES($1,$2,gen_random_uuid(),$3,$4,'claude.ai','chrome','browser',$5,1,42,'unknown',$6,$7,$8) RETURNING id`,
		f.org, device, at, kind, action, subject, conversation, correlation).Scan(&id)
	if e != nil {
		t.Fatal(e)
	}
	if text == "" {
		return id
	}
	field := "response"
	if kind == "prompt" {
		field = "prompt"
	}
	plain, _ := json.Marshal(map[string]*string{field: &text})
	sealed, e := f.a.sealShadow(f.org, "event:"+device+":"+id, plain)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.admin.Exec(ctx, `INSERT INTO shadow_content(organization_id,device_id,event_id,encrypted,expires_at) VALUES($1,$2,$3,$4,now()+interval '7 days')`, f.org, device, id, []byte(sealed)); e != nil {
		t.Fatal(e)
	}
	return id
}

// setModel names the model on one record. The value is the label the site
// displays -- capitals and spaces -- not a provider identifier.
func setModel(t *testing.T, f *observabilityFixture, id, model, effort string) {
	t.Helper()
	tag, e := f.admin.Exec(context.Background(), `UPDATE shadow_events SET model=$1,effort=$2 WHERE id=$3`, model, effort, id)
	if e != nil || tag.RowsAffected() != 1 {
		t.Fatal("model not set", e)
	}
}

func readConversations(t *testing.T, f *observabilityFixture, query string) []ConversationView {
	t.Helper()
	w := f.call("GET", "/api/shadow/conversations"+query, nil, "")
	requireHTTP(t, w, 200)
	var out struct {
		Items      []ConversationView `json:"items"`
		NextCursor string             `json:"next_cursor"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
		t.Fatal(e)
	}
	return out.Items
}

// readConversationPage also returns how many conversations the filter matches, which is
// what turns a page size into a number of pages.
func readConversationPage(t *testing.T, f *observabilityFixture, query string) ([]ConversationView, int) {
	t.Helper()
	w := f.call("GET", "/api/shadow/conversations"+query, nil, "")
	requireHTTP(t, w, 200)
	var out struct {
		Items []ConversationView `json:"items"`
		Total *int               `json:"total"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
		t.Fatal(e)
	}
	if out.Total == nil {
		t.Fatal("a page asked by offset carries no total", w.Body.String())
	}
	return out.Items, *out.Total
}

func readThread(t *testing.T, f *observabilityFixture, key, device, cursor string) (items []ThreadMessage, older string) {
	t.Helper()
	path := "/api/shadow/conversation?key=" + key + "&device_id=" + device
	if cursor != "" {
		path += "&cursor=" + cursor
	}
	w := f.call("GET", path, nil, "")
	requireHTTP(t, w, 200)
	var out struct {
		Items       []ThreadMessage `json:"items"`
		OlderCursor string          `json:"older_cursor"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
		t.Fatal(e)
	}
	return out.Items, out.OlderCursor
}

func TestShadowConversations(t *testing.T) {
	base := time.Now().UTC().Add(-time.Hour)
	t.Run("groups a thread, recovers the opening prompt and hides a bare navigation", func(t *testing.T) {
		f, subject, device := privacyFixture(t)
		// The opening prompt has no conversation identifier: only the correlation it
		// shares with the navigation that followed the URL assignment links it.
		opening := addThreadEvent(t, f, subject, device, threadEvent{base, "prompt", "", "correlation-1", "observed", ""})
		addThreadEvent(t, f, subject, device, threadEvent{base.Add(time.Second), "navigation", "thread-a", "correlation-1", "observed", ""})
		addThreadEvent(t, f, subject, device, threadEvent{base.Add(2 * time.Second), "response", "thread-a", "correlation-1", "observed", ""})
		// An exchange where nothing ever carried a conversation identifier, which is
		// what real captures look like today: the correlation alone holds it together.
		addThreadEvent(t, f, subject, device, threadEvent{base.Add(3 * time.Second), "prompt", "", "correlation-2", "observed", ""})
		addThreadEvent(t, f, subject, device, threadEvent{base.Add(4 * time.Second), "response", "", "correlation-2", "observed", ""})
		addThreadEvent(t, f, subject, device, threadEvent{base.Add(5 * time.Second), "navigation", "", "correlation-2", "observed", ""})
		// A site opened without a word typed is not a conversation.
		addThreadEvent(t, f, subject, device, threadEvent{base.Add(6 * time.Second), "navigation", "", "", "observed", ""})
		addThreadEvent(t, f, subject, device, threadEvent{base.Add(7 * time.Second), "navigation", "thread-empty", "", "observed", ""})
		items := readConversations(t, f, "?from="+base.Add(-time.Minute).Format(time.RFC3339Nano)+"&to="+base.Add(time.Minute).Format(time.RFC3339Nano))
		byKey := map[string]ConversationView{}
		for _, item := range items {
			byKey[item.Key] = item
		}
		if len(items) != 2 {
			t.Fatalf("expected the two exchanges only, got %d: %v", len(items), byKey)
		}
		thread, ok := byKey["conv:thread-a"]
		if !ok {
			t.Fatal("thread not grouped under its conversation identifier")
		}
		if thread.Prompts != 1 || thread.Responses != 1 || thread.Navigations != 1 {
			t.Fatalf("opening prompt not attached by correlation: %+v", thread)
		}
		correlated, ok := byKey["corr:correlation-2"]
		if !ok {
			t.Fatal("an exchange without any conversation identifier must group on its correlation")
		}
		if correlated.Prompts != 1 || correlated.Responses != 1 || correlated.Navigations != 1 {
			t.Fatalf("correlated exchange not grouped whole: %+v", correlated)
		}
		// The thread reports the last record that names a model, not the model of its
		// last record: the navigation that closes this exchange carries none.
		setModel(t, f, opening, "claude-fable-5-1", "medium")
		named := readConversations(t, f, "?from="+base.Add(-time.Minute).Format(time.RFC3339Nano)+"&to="+base.Add(time.Minute).Format(time.RFC3339Nano))
		for _, item := range named {
			if item.Key != "conv:thread-a" {
				continue
			}
			// The reasoning effort is a setting of its own, never folded into the model:
			// merging them would split one model into as many entries as it has levels.
			if item.Model != "claude-fable-5-1" || item.Effort != "medium" {
				t.Fatalf("model and effort not carried apart: %q / %q", item.Model, item.Effort)
			}
		}
		messages, older := readThread(t, f, "conv:thread-a", device, "")
		if older != "" || len(messages) != 3 {
			t.Fatalf("expected the whole thread in one page, got %d older=%q", len(messages), older)
		}
		// Oldest first, the way the exchange happened, and the orphan is in it.
		if messages[0].ID != opening || !messages[0].OccurredAt.Before(messages[2].OccurredAt) {
			t.Fatalf("thread is not ordered oldest first: %s", messages[0].ID)
		}
		// The list hides bare navigations; an opened thread still shows its own.
		correlatedMessages, _ := readThread(t, f, "corr%3Acorrelation-2", device, "")
		if len(correlatedMessages) != 3 {
			t.Fatalf("the correlated thread lost records: %d", len(correlatedMessages))
		}
	})
	t.Run("numbered pages read by offset and report the matching total", func(t *testing.T) {
		// Numbered pages need to jump, which a keyset cursor cannot do. The offset names
		// the position and the total names how many pages exist; the two have to describe
		// the same set, whatever page is being read.
		f, subject, device := privacyFixture(t)
		for i := 0; i < 7; i++ {
			at := base.Add(time.Duration(i) * time.Second)
			addThreadEvent(t, f, subject, device, threadEvent{at, "prompt", fmt.Sprintf("thread-%d", i), "", "observed", ""})
			addThreadEvent(t, f, subject, device, threadEvent{at.Add(500 * time.Millisecond), "response", fmt.Sprintf("thread-%d", i), "", "observed", ""})
		}
		period := "?from=" + base.Add(-time.Minute).Format(time.RFC3339Nano) + "&to=" + base.Add(time.Minute).Format(time.RFC3339Nano)
		first, total := readConversationPage(t, f, period+"&limit=3&offset=0")
		if total != 7 || len(first) != 3 {
			t.Fatalf("first page of seven: %d items, total %d", len(first), total)
		}
		last, lastTotal := readConversationPage(t, f, period+"&limit=3&offset=6")
		if lastTotal != 7 || len(last) != 1 {
			t.Fatalf("last page of seven: %d items, total %d", len(last), lastTotal)
		}
		// The total counts what the filter matches, not what the page returned: a page
		// past the end must still say how far back the reader can step.
		beyond, beyondTotal := readConversationPage(t, f, period+"&limit=3&offset=99")
		if beyondTotal != 7 || len(beyond) != 0 {
			t.Fatalf("page past the end: %d items, total %d", len(beyond), beyondTotal)
		}
		// Pages must not overlap, and together they must cover the whole list.
		seen := map[string]bool{}
		for _, offset := range []int{0, 3, 6} {
			page, _ := readConversationPage(t, f, fmt.Sprintf("%s&limit=3&offset=%d", period, offset))
			for _, item := range page {
				if seen[item.Key] {
					t.Fatalf("conversation %q served on two pages", item.Key)
				}
				seen[item.Key] = true
			}
		}
		if len(seen) != 7 {
			t.Fatalf("the pages do not cover the list: %d of 7", len(seen))
		}
		requireHTTP(t, f.call("GET", "/api/shadow/conversations"+period+"&limit=201", nil, ""), 400)
		requireHTTP(t, f.call("GET", "/api/shadow/conversations"+period+"&offset=-1", nil, ""), 400)
		// One position at a time: a cursor and an offset name it two different ways.
		requireHTTP(t, f.call("GET", "/api/shadow/conversations"+period+"&offset=3&cursor=abc", nil, ""), 400)
	})
	t.Run("a thread whose identifier only appears on the second exchange stays whole", func(t *testing.T) {
		f, subject, device := privacyFixture(t)
		// The exact shape chatgpt.com produces, measured on the real site on
		// 2026-09-14: the first exchange carries no conversation identifier at all --
		// the request body names only parent_message_id "client-created-root" -- and the
		// identifier appears from the second exchange on. What keeps the thread whole is
		// the navigation emitted once the URL is assigned, which carries the new
		// identifier and the correlation of the exchange that just happened.
		first := addThreadEvent(t, f, subject, device, threadEvent{base, "prompt", "", "corr-first", "observed", ""})
		addThreadEvent(t, f, subject, device, threadEvent{base.Add(time.Second), "response", "", "corr-first", "observed", ""})
		addThreadEvent(t, f, subject, device, threadEvent{base.Add(2 * time.Second), "navigation", "chatgpt-thread", "corr-first", "observed", ""})
		addThreadEvent(t, f, subject, device, threadEvent{base.Add(3 * time.Second), "prompt", "chatgpt-thread", "corr-second", "observed", ""})
		addThreadEvent(t, f, subject, device, threadEvent{base.Add(4 * time.Second), "response", "chatgpt-thread", "corr-second", "observed", ""})
		items := readConversations(t, f, "?from="+base.Add(-time.Minute).Format(time.RFC3339Nano)+"&to="+base.Add(time.Minute).Format(time.RFC3339Nano))
		if len(items) != 1 {
			keys := []string{}
			for _, item := range items {
				keys = append(keys, item.Key)
			}
			t.Fatalf("the thread split instead of staying whole: %v", keys)
		}
		if items[0].Key != "conv:chatgpt-thread" || items[0].Prompts != 2 || items[0].Responses != 2 {
			t.Fatalf("the first exchange was not attached to the thread: %+v", items[0])
		}
		// And the opening prompt really is inside it, not merely counted.
		messages, _ := readThread(t, f, "conv:chatgpt-thread", device, "")
		if len(messages) != 5 || messages[0].ID != first {
			t.Fatalf("the opening prompt is missing from the thread: %d", len(messages))
		}
	})
	t.Run("returns ten messages by default and reaches further back by cursor", func(t *testing.T) {
		f, subject, device := privacyFixture(t)
		for i := 0; i < 25; i++ {
			addThreadEvent(t, f, subject, device, threadEvent{base.Add(time.Duration(i) * time.Second), "prompt", "thread-long", "", "observed", ""})
		}
		first, older := readThread(t, f, "conv:thread-long", device, "")
		if len(first) != 10 || older == "" {
			t.Fatalf("expected ten messages and more history, got %d older=%q", len(first), older)
		}
		second, stillOlder := readThread(t, f, "conv:thread-long", device, older)
		if len(second) != 10 || stillOlder == "" {
			t.Fatalf("second page wrong: %d older=%q", len(second), stillOlder)
		}
		if !second[len(second)-1].OccurredAt.Before(first[0].OccurredAt) {
			t.Fatal("the earlier page is not earlier")
		}
		third, exhausted := readThread(t, f, "conv:thread-long", device, stillOlder)
		if len(third) != 5 || exhausted != "" {
			t.Fatalf("last page wrong: %d older=%q", len(third), exhausted)
		}
		requireHTTP(t, f.call("GET", "/api/shadow/conversation?key=conv:thread-long&device_id="+device+"&limit=51", nil, ""), 400)
	})
	t.Run("names each reason a text is withheld and audits every text it decrypts", func(t *testing.T) {
		f, subject, device := privacyFixture(t)
		ctx := context.Background()
		withText := addThreadEvent(t, f, subject, device, threadEvent{base, "prompt", "thread-b", "", "observed", "Synthetic thread request"})
		addThreadEvent(t, f, subject, device, threadEvent{base.Add(time.Second), "response", "thread-b", "", "observed", ""})
		// Pseudonymous by default and no live reveal: the identity barrier answers
		// before the content grant is even consulted.
		messages, _ := readThread(t, f, "conv:thread-b", device, "")
		if len(messages) != 2 || messages[0].ContentState != contentIdentity {
			t.Fatalf("identity barrier not reported: %+v", messages)
		}
		requireHTTP(t, f.call("POST", "/api/subjects/"+subject+"/reveal", map[string]string{"reason": "Synthetic incident investigation"}, f.csrf), 200)
		// Revealed, but the role does not carry content.read. Reaching contentDenied
		// now takes a role that may lift an identity and still not read the text —
		// the two rights are distinct, and the order of the gates says so.
		requireHTTP(t, f.call("POST", "/api/roles", map[string]any{"name": "revealer", "permissions": []string{"overview.read", "events.read", "identity.reveal"}}, f.csrf), 201)
		setRole := func(role string) {
			t.Helper()
			if _, e := f.admin.Exec(ctx, `UPDATE memberships SET role=$1 WHERE organization_id=$2 AND user_id=$3`, role, f.org, f.user); e != nil {
				t.Fatal(e)
			}
		}
		setRole("revealer")
		t.Cleanup(func() { setRole("owner") })
		messages, _ = readThread(t, f, "conv:thread-b", device, "")
		if messages[0].ContentState != contentDenied {
			t.Fatalf("missing content right not reported: %q", messages[0].ContentState)
		}
		if strings.Contains(f.call("GET", "/api/shadow/conversation?key=conv:thread-b&device_id="+device, nil, "").Body.String(), "Synthetic thread request") {
			t.Fatal("text disclosed without the content right")
		}
		setRole("owner")
		messages, _ = readThread(t, f, "conv:thread-b", device, "")
		if messages[0].ContentState != contentAvailable || messages[0].Content["prompt"] == nil || *messages[0].Content["prompt"] != "Synthetic thread request" {
			t.Fatalf("granted text not returned: %+v", messages[0])
		}
		// A record whose text was never kept is not the same statement as a refusal.
		if messages[1].ContentState != contentNotRetained || messages[1].Content != nil {
			t.Fatalf("absent text reported as a refusal: %+v", messages[1])
		}
		// One audit line per text actually decrypted, with the same action and target
		// shape as the single event detail: reading a thread is never cheaper to
		// account for than reading its messages one by one.
		var lines int
		if e := f.admin.QueryRow(ctx, `SELECT count(*) FROM audit WHERE action='shadow.content.read' AND target=$1`, device+":"+withText).Scan(&lines); e != nil {
			t.Fatal(e)
		}
		if lines != 1 {
			t.Fatalf("expected exactly one content read line, got %d", lines)
		}
	})
	t.Run("refuses a malformed key and never crosses an organization", func(t *testing.T) {
		f, subject, device := privacyFixture(t)
		addThreadEvent(t, f, subject, device, threadEvent{base, "prompt", "thread-c", "", "observed", ""})
		for _, key := range []string{"thread-c", "conv:", "event:not-a-uuid", "conv:" + strings.Repeat("x", 201)} {
			requireHTTP(t, f.call("GET", "/api/shadow/conversation?key="+key+"&device_id="+device, nil, ""), 400)
		}
		// A second tenant in the same database, not a second fixture: the fixture
		// drops the public schema, so building one here would destroy this test's
		// own rows. The insert runs under its own tenant setting, restored by
		// setTenant when the nested subtest ends.
		ctx := context.Background()
		var otherOrg, otherDevice string
		t.Run("seed another organization", func(t *testing.T) {
			// Enterprise refuses an organization without an existing parent, and
			// Community has the same nullable column: naming one satisfies both.
			// A child is enough for this proof -- a session stays on one
			// organization, so row level security must hide the child's rows.
			if e := f.admin.QueryRow(ctx, `INSERT INTO organizations(name,parent_id) VALUES('Synthetic neighbour',$1) RETURNING id`, f.org).Scan(&otherOrg); e != nil {
				t.Fatal(e)
			}
			setTenant(t, f.admin, otherOrg)
			if e := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status) VALUES($1,$2,'','test','0.5.0','approved') RETURNING id`, otherOrg, hash(randomToken())).Scan(&otherDevice); e != nil {
				t.Fatal(e)
			}
			if _, e := f.admin.Exec(ctx, `INSERT INTO shadow_events(organization_id,device_id,id,occurred_at,kind,provider,tool,source,action,policy_revision,characters,sensitivity,conversation_id,correlation_id)
				VALUES($1,$2,gen_random_uuid(),$3,'prompt','claude.ai','chrome','browser','observed',1,42,'unknown','thread-c','')`, otherOrg, otherDevice, base); e != nil {
				t.Fatal(e)
			}
		})
		// Same conversation identifier, another tenant: row level security must make
		// it invisible rather than merely unlisted.
		requireHTTP(t, f.call("GET", "/api/shadow/conversation?key=conv:thread-c&device_id="+otherDevice, nil, ""), 404)
		for _, item := range readConversations(t, f, "") {
			if item.Latest.DeviceID == otherDevice {
				t.Fatal("a conversation of another organization was listed")
			}
		}
	})
	// Reading prompt text does NOT travel down a hierarchy, unlike every other
	// permission. A parent's owner holds no membership in the child, and the column
	// this replaced was read on the organization at hand, so the answer was no.
	// Resolving the right through effective_access reopened that path: measured on
	// 2026-09-15 against a real parent/child pair, the parent owner was granted the
	// child's text. This pins the exception so it cannot be lost again by writing the
	// "obvious" query.
	t.Run("the right to read text does not reach down into a child organization", func(t *testing.T) {
		f, _, _ := privacyFixture(t)
		ctx := context.Background()
		var child string
		if e := f.admin.QueryRow(ctx, `INSERT INTO organizations(name,parent_id) VALUES('Content inheritance child',$1) RETURNING id`, f.org).Scan(&child); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _, _ = f.admin.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, child) })
		var inherited bool
		if e := f.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM effective_access($1,$2) WHERE 'content.read'=ANY(permissions))`, f.user, child).Scan(&inherited); e != nil {
			t.Fatal(e)
		}
		if !inherited {
			t.Fatal("fixture broken: the parent owner must inherit permissions on the child, or this proves nothing")
		}
		setTenant(t, f.admin, child)
		tx, e := f.admin.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		allowed, e := contentAccessAvailable(ctx, tx, child, f.user)
		if e != nil {
			t.Fatal(e)
		}
		if allowed {
			t.Fatal("a parent owner with no membership in the child was granted its retained text")
		}
	})
}
