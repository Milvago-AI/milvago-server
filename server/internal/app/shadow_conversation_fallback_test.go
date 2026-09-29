package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func addBrowserThreadEvent(t *testing.T, f *observabilityFixture, subject, device, provider, browser string, event threadEvent) string {
	t.Helper()
	id := addThreadEvent(t, f, subject, device, event)
	tag, err := f.admin.Exec(context.Background(), `UPDATE shadow_events SET provider=$1,tool=$2 WHERE id=$3`, provider, browser, id)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatal("event scope not set", err)
	}
	return id
}

func TestChatGPTConversationFallback(t *testing.T) {
	t.Run("joins the preceding exchange without a correlation bridge", func(t *testing.T) {
		f, subject, device := privacyFixture(t)
		base := time.Now().UTC().Add(-time.Hour)
		first := addBrowserThreadEvent(t, f, subject, device, "chatgpt.com", "chrome", threadEvent{base, "prompt", "", "opening", "observed", ""})
		addBrowserThreadEvent(t, f, subject, device, "chatgpt.com", "chrome", threadEvent{base.Add(time.Second), "response", "", "opening", "observed", ""})
		addBrowserThreadEvent(t, f, subject, device, "chatgpt.com", "chrome", threadEvent{base.Add(2 * time.Second), "prompt", "chat-thread", "next", "observed", ""})
		addBrowserThreadEvent(t, f, subject, device, "chatgpt.com", "chrome", threadEvent{base.Add(3 * time.Second), "response", "chat-thread", "next", "observed", ""})
		list := readConversations(t, f, "")
		if len(list) != 1 || list[0].Key != "conv:chat-thread" || list[0].Prompts != 2 || list[0].Responses != 2 {
			t.Fatalf("split thread: %+v", list)
		}
		items, _ := readThread(t, f, "conv:chat-thread", device, "")
		if len(items) != 4 || items[0].ID != first {
			t.Fatalf("opening missing from detail: %+v", items)
		}
		// Filtering out the later exchange cannot change the identity of the thread.
		list = readConversations(t, f, "?to="+base.Add(time.Second).Format(time.RFC3339Nano))
		if len(list) != 1 || list[0].Key != "conv:chat-thread" || list[0].Prompts != 1 {
			t.Fatalf("filter changed linkage: %+v", list)
		}
	})
	for _, scope := range []string{"browser", "service", "device", "existing-id", "only-nearest"} {
		t.Run(scope, func(t *testing.T) {
			f, subject, device := privacyFixture(t)
			base := time.Now().UTC().Add(-time.Hour)
			previousID := ""
			if scope == "existing-id" {
				previousID = "previous-thread"
			}
			first := addBrowserThreadEvent(t, f, subject, device, "chatgpt.com", "chrome", threadEvent{base, "prompt", previousID, "opening", "observed", ""})
			provider, browser, targetDevice := "chatgpt.com", "chrome", device
			switch scope {
			case "browser":
				browser = "firefox"
			case "service":
				provider = "claude.ai"
			case "device":
				if err := f.admin.QueryRow(context.Background(), `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status) VALUES($1,$2,'','test','0.6.2','approved') RETURNING id`, f.org, hash(randomToken())).Scan(&targetDevice); err != nil {
					t.Fatal(err)
				}
			case "only-nearest":
				addBrowserThreadEvent(t, f, subject, device, "chatgpt.com", "chrome", threadEvent{base.Add(time.Second), "prompt", "", "nearest", "observed", ""})
			}
			addBrowserThreadEvent(t, f, subject, targetDevice, provider, browser, threadEvent{base.Add(2 * time.Second), "prompt", "new-thread", "new", "observed", ""})
			list := readConversations(t, f, "")
			if len(list) != 2 {
				t.Fatalf("unexpected merge: %+v", list)
			}
			items, _ := readThread(t, f, "conv:new-thread", targetDevice, "")
			for _, item := range items {
				if item.ID == first {
					t.Fatal("unrelated preceding exchange joined")
				}
			}
			expected := 1
			if scope == "only-nearest" {
				expected = 2
			}
			if len(items) != expected {
				t.Fatalf("detail has %d messages, want %d", len(items), expected)
			}
		})
	}
}

func TestConversationRetainedFileNames(t *testing.T) {
	f, subject, device := privacyFixture(t)
	id := addThreadEvent(t, f, subject, device, threadEvent{time.Now().UTC().Add(-time.Minute), "prompt", "files-thread", "files-send", "observed", ""})
	tag, err := f.admin.Exec(context.Background(), `UPDATE shadow_events SET files='["synthetic-document.pdf"]'::jsonb WHERE id=$1`, id)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatal("file fixture missing", err)
	}
	list := readConversations(t, f, "")
	if len(list) != 1 || !list[0].HasAttachment {
		t.Fatal("attachment indicator missing")
	}
	for _, path := range []string{"/api/shadow/conversation?key=conv:files-thread&device_id=" + device, "/api/shadow/events/" + id + "?device_id=" + device} {
		w := f.call("GET", path, nil, "")
		requireHTTP(t, w, 200)
		if !strings.Contains(w.Body.String(), "synthetic-document.pdf") {
			t.Fatal("retained name missing without retained text", w.Body.String())
		}
		var body struct {
			Items   []ThreadMessage    `json:"items"`
			Event   ShadowEventView    `json:"event"`
			Content map[string]*string `json:"content"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if len(body.Content) != 0 || body.Event.User != "" || body.Event.IdentityExpiresAt != nil {
			t.Fatal("file names must not reveal text or personal identity")
		}
		for _, item := range body.Items {
			if len(item.Content) != 0 || item.User != "" || item.IdentityExpiresAt != nil {
				t.Fatal("file names must not reveal text or personal identity")
			}
		}
		w = f.call("GET", path+"&identity=aliases", nil, "")
		requireHTTP(t, w, 200)
		if strings.Contains(w.Body.String(), "synthetic-document.pdf") {
			t.Fatal("explicit alias projection leaked filename")
		}
	}
	// Disabling name collection cannot manufacture a missing name from the text.
	tag, err = f.admin.Exec(context.Background(), `UPDATE shadow_events SET files='[]'::jsonb WHERE id=$1`, id)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatal("empty file fixture missing", err)
	}
	items, _ := readThread(t, f, "conv:files-thread", device, "")
	if len(items) != 1 || len(items[0].Files) != 0 {
		t.Fatal("invented retained file name")
	}
}
