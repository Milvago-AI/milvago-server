package app

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// A submission accompanied by a file leaves TWO records under the same correlation: the
// file leaves for the provider as soon as it is attached, so it is recorded before the
// text. The counters used to announce two requests where the console, since 2026-09-15,
// shows only one bubble -- the screen and the figure contradicted each other.
//
// The criterion is NOT the presence of file names: when their reporting is disabled, the
// attachment record carries none. It is a zero-character prompt sharing its correlation
// with a prompt carrying text.
func addAttachmentRecord(t *testing.T, f *observabilityFixture, subject, device string, at time.Time, correlation string, files []string) {
	t.Helper()
	names, e := json.Marshal(files)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.admin.Exec(context.Background(), `INSERT INTO shadow_events(organization_id,device_id,id,occurred_at,kind,provider,tool,source,action,policy_revision,characters,sensitivity,collaborator_id,conversation_id,correlation_id,files)
		VALUES($1,$2,gen_random_uuid(),$3,'prompt','claude.ai','chrome','browser','observed',1,0,'unknown',$4,'',$5,$6)`,
		f.org, device, at, subject, correlation, names); e != nil {
		t.Fatal(e)
	}
}

func TestAttachmentRecordCountsWithItsSend(t *testing.T) {
	base := time.Now().UTC().Add(-time.Hour)
	window := "?from=" + base.Add(-time.Minute).Format(time.RFC3339Nano) + "&to=" + base.Add(time.Minute).Format(time.RFC3339Nano)

	t.Run("a conversation announces one request per send, attachment included", func(t *testing.T) {
		f, subject, device := privacyFixture(t)
		// The attachment first, the text next, under the same correlation: the real order.
		addAttachmentRecord(t, f, subject, device, base, "correlation-file", []string{"schema-synthetique.png"})
		addThreadEvent(t, f, subject, device, threadEvent{base.Add(time.Second), "prompt", "", "correlation-file", "observed", "Analyse ce document."})
		addThreadEvent(t, f, subject, device, threadEvent{base.Add(2 * time.Second), "response", "", "correlation-file", "observed", "Réponse de test."})
		// The same exchange with no name reporting: the attachment record carries no
		// files, and must still be recognized.
		addAttachmentRecord(t, f, subject, device, base.Add(3*time.Second), "correlation-silent", nil)
		addThreadEvent(t, f, subject, device, threadEvent{base.Add(4 * time.Second), "prompt", "", "correlation-silent", "observed", "Et celui-ci ?"})

		items := readConversations(t, f, window)
		byKey := map[string]ConversationView{}
		for _, item := range items {
			byKey[item.Key] = item
		}
		with, ok := byKey["corr:correlation-file"]
		if !ok {
			t.Fatalf("exchange not grouped on its correlation: %v", byKey)
		}
		if with.Prompts != 1 || with.Responses != 1 {
			t.Fatalf("an attachment is part of its send, not a second one: %+v", with)
		}
		silent, ok := byKey["corr:correlation-silent"]
		if !ok {
			t.Fatalf("exchange not grouped on its correlation: %v", byKey)
		}
		if silent.Prompts != 1 {
			t.Fatalf("file names are off: the attachment record carries none and must still count with its send: %+v", silent)
		}
	})

	t.Run("an attachment with no send that follows keeps its own count", func(t *testing.T) {
		f, subject, device := privacyFixture(t)
		// Attached then abandoned: there is no submission to attach it to, and this
		// record then describes exactly what happened.
		addAttachmentRecord(t, f, subject, device, base, "correlation-lonely", []string{"schema-synthetique.png"})
		items := readConversations(t, f, window)
		if len(items) != 1 || items[0].Prompts != 1 {
			t.Fatalf("a lone attachment must remain visible and counted: %+v", items)
		}
	})

	t.Run("the 24-hour counters stay additive and drop the attachment record", func(t *testing.T) {
		f, subject, device := privacyFixture(t)
		recent := time.Now().UTC().Add(-time.Minute)
		addAttachmentRecord(t, f, subject, device, recent, "correlation-metrics", []string{"schema-synthetique.png"})
		addThreadEvent(t, f, subject, device, threadEvent{recent.Add(time.Second), "prompt", "", "correlation-metrics", "observed", "Analyse ce document."})
		addThreadEvent(t, f, subject, device, threadEvent{recent.Add(2 * time.Second), "response", "", "correlation-metrics", "observed", "Réponse de test."})
		addThreadEvent(t, f, subject, device, threadEvent{recent.Add(3 * time.Second), "navigation", "", "correlation-metrics", "observed", ""})

		// The route is gated by MILVAGO_SHADOW_METRICS, which the harness leaves closed.
		f.a.config.ShadowMetrics = true
		w := f.call("GET", "/api/shadow/metrics", nil, "")
		requireHTTP(t, w, 200)
		var out struct {
			Events      int `json:"events"`
			Prompts     int `json:"prompts"`
			Responses   int `json:"responses"`
			Navigations int `json:"navigations"`
		}
		if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
			t.Fatal(e)
		}
		if out.Prompts != 1 || out.Responses != 1 || out.Navigations != 1 {
			t.Fatalf("one send, one request: %+v", out)
		}
		// The total remains the sum of the kinds: excluding the record from one counter
		// and not the other would make the page that adds them up lie.
		if out.Events != out.Prompts+out.Responses+out.Navigations {
			t.Fatalf("counters no longer add up: %+v", out)
		}
	})
}
