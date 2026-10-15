package app

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func modelSourceCatalog(rule string) []byte {
	return []byte(`{"providers":[{"id":"p","label":"p","domains":["example.test"],"aliases":[],` +
		`"conversation_path":"/c/*","conversation_segment":1,` +
		`"dom":{"editor":"","send":"","response":""},` +
		`"network":[{"method":"POST","host":"example.test","path":"/*_/rpc/Generate","text_path":"1.0.0",` +
		`"model_path":"4","effort_path":"","conversation_path":""` + rule + `}],` +
		`"qualified_at":"2026-09-11T00:00:00Z"}],"native_tools":[],"heuristics":{"keys":[],"mime_types":[]}}`)
}

// A rule may read its prompt from one JSON form field and its model from a JSON request
// header, mapped to canonical names (Gemini, measured on 2026-10-15). The server bounds
// these fields as the agent and the extension do, and omits them when empty: the agent
// refuses unknown fields, so a catalogue that does not use them keeps its bytes.
func TestDetectionNetworkModelSource(t *testing.T) {
	for _, tc := range []struct {
		name, rule string
		ok         bool
	}{
		{"absent", ``, true},
		{"named", `,"form_field":"f.req","json_fields":["1"],"model_header":"x-synthetic-ext-jspb","model_map":{"0123456789abcdef":"synthetic-fast"}`, true},
		{"form field with a space", `,"form_field":"f req"`, false},
		{"form field reaching the prototype", `,"form_field":"__proto__"`, false},
		{"form field too long", `,"form_field":"` + strings.Repeat("f", 65) + `"`, false},
		{"header in upper case", `,"model_header":"X-Synthetic"`, false},
		{"header with an underscore", `,"model_header":"x_synthetic"`, false},
		{"map key reaching the prototype", `,"model_map":{"__proto__":"x"}`, false},
		{"map key with a space", `,"model_map":{"a b":"x"}`, false},
		{"mapped name in the fallback form", `,"model_map":{"k":"p:x"}`, false},
		{"mapped name empty", `,"model_map":{"k":""}`, false},
		{"mapped name with a leading dash", `,"model_map":{"k":"-x"}`, false},
		{"map not an object", `,"model_map":["k"]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, e := decodeDetection(modelSourceCatalog(tc.rule))
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
			for _, key := range []string{"form_field", "model_header", "model_map"} {
				if bytes.Contains(out, []byte(key)) != strings.Contains(tc.rule, key) {
					t.Fatalf("%s must travel exactly when named: %s", key, out)
				}
			}
		})
	}
	t.Run("a header needs the path that reads it", func(t *testing.T) {
		raw := bytes.Replace(modelSourceCatalog(`,"model_header":"x-synthetic-ext-jspb"`), []byte(`"model_path":"4"`), []byte(`"model_path":""`), 1)
		if _, e := decodeDetection(raw); e == nil {
			t.Fatal("a model header without a model path was accepted")
		}
	})
	t.Run("the map is bounded", func(t *testing.T) {
		entries := make([]string, 33)
		for i := range entries {
			entries[i] = `"id` + strings.Repeat("x", i) + `":"n"`
		}
		if _, e := decodeDetection(modelSourceCatalog(`,"model_map":{` + strings.Join(entries, ",") + `}`)); e == nil {
			t.Fatal("a map of 33 entries was accepted")
		}
	})
}

// The memo hands out deep copies: a map is shared by a struct copy exactly like the
// *int of conversation_url_segment was until 2026-09-21.
func TestDetectionModelMapIsNotSharedThroughCopies(t *testing.T) {
	raw := modelSourceCatalog(`,"model_header":"x-synthetic-ext-jspb","model_map":{"0123456789abcdef":"synthetic-fast"}`)
	first, e := decodedDetection(raw)
	if e != nil {
		t.Fatal(e)
	}
	first.Providers[0].Network[0].ModelMap["0123456789abcdef"] = "written-through-a-copy"
	again, e := decodedDetection(raw)
	if e != nil {
		t.Fatal(e)
	}
	if got := again.Providers[0].Network[0].ModelMap["0123456789abcdef"]; got != "synthetic-fast" {
		t.Fatalf("a write through a copy reached the memo: %q", got)
	}
}
