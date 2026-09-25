package app

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// FuzzValidateV2 exercises validateV2 (shadow_endpoint.go), the sole gate a /v2/events
// record passes through after JSON decoding. A record here comes from an enrolled but
// potentially compromised device or extension: policy_revision, timestamps, detector
// channel and every string field are attacker-controlled inputs the endpoint has no
// other reason to trust.
//
// Invariants checked when validateV2 accepts a record: every bound it is documented to
// enforce (label count, prompt/response size, file count, URL scheme) actually held.
func FuzzValidateV2(f *testing.F) {
	seeds := []string{
		`{"id":"11111111-1111-4111-8111-111111111111","kind":"prompt","occurred_at":"2026-09-24T00:00:00Z","provider":"chatgpt.com","source":"browser","tool":"chrome","action":"observed","characters":10,"labels":[],"policy_revision":1,"url":"https://chatgpt.com/c/abc"}`,
		`{"id":"11111111-1111-4111-8111-111111111111","kind":"navigation","occurred_at":"2026-09-24T00:00:00Z","provider":"chatgpt.com","source":"native","tool":"codex","action":"observed","characters":0,"labels":[],"policy_revision":1,"detector":"otlp"}`,
		`{}`,
		`{"id":"not-a-uuid"}`,
		`{"labels":null}`,
		`{"prompt":"hello","kind":"prompt"}`,
		`{"files":["a.txt","b‮.exe"]}`,
		`{"detector":"presence","source":"browser","platform_id":"gemini"}`,
		`{"decision_reason":"model_denied","action":"blocked","kind":"prompt","platform_id":"x"}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		var v V2Event
		if json.Unmarshal(raw, &v) != nil {
			return // malformed JSON is decode()'s job (see FuzzDecode), not validateV2's
		}
		now := time.Now().UTC()
		err := validateV2(&v, now)
		if err != nil {
			return
		}
		if len(v.Labels) > 16 {
			t.Fatalf("accepted event with %d labels", len(v.Labels))
		}
		if v.Prompt != nil && len(*v.Prompt) > 32768 {
			t.Fatalf("accepted oversized prompt: %d bytes", len(*v.Prompt))
		}
		if v.Response != nil && len(*v.Response) > 32768 {
			t.Fatalf("accepted oversized response: %d bytes", len(*v.Response))
		}
		if len(v.Files) > 20 {
			t.Fatalf("accepted %d file names", len(v.Files))
		}
		if v.URL != "" && !strings.HasPrefix(v.URL, "https://") {
			t.Fatalf("accepted a non-https URL: %q", v.URL)
		}
		if v.Source == "native" && v.URL != "" {
			t.Fatalf("accepted a browser URL on a native record")
		}
	})
}

// FuzzNormalizeEventURL exercises normalizeEventURL standalone: the one path inside
// validateV2 that reparses an attacker-controlled string with net/url and rewrites it,
// on every browser-sourced /v2/events record.
func FuzzNormalizeEventURL(f *testing.F) {
	f.Add("https://chatgpt.com/c/abc", "chatgpt.com")
	f.Add("", "chatgpt.com")
	f.Add("http://chatgpt.com/", "chatgpt.com")
	f.Add("https://evil.test/c/abc", "chatgpt.com")
	f.Add("https://CHATGPT.com:443/c/x", "chatgpt.com")
	f.Add("https://user:pass@chatgpt.com/c/x", "chatgpt.com")
	f.Add("not a url at all \x00", "chatgpt.com")
	f.Add("https://chatgpt.com/"+strings.Repeat("a", 3000), "chatgpt.com")
	f.Add("https:// chatgpt.com/c/x", "chatgpt.com")

	f.Fuzz(func(t *testing.T, raw, provider string) {
		out, err := normalizeEventURL(raw, provider)
		if err != nil {
			if out != "" {
				t.Fatalf("error case returned non-empty URL: %q", out)
			}
			return
		}
		if out == "" {
			return // empty input, empty output: the one documented no-op case
		}
		if !strings.HasPrefix(out, "https://") {
			t.Fatalf("normalized to a non-https URL: %q", out)
		}
	})
}
