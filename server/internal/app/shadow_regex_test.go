package app

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestShadowRegexValidation(t *testing.T) {
	for _, value := range []string{"chatgpt", "(chatgpt|claude)", `^gpt-5\.[0-9]+$`, "[[:alpha:]]+", "a{2,3}", "café", "device-[0-9]+", "' OR TRUE --"} {
		if err := validateShadowRegex(value); err != nil {
			t.Errorf("valid expression %q: %v", value, err)
		}
	}
	for _, value := range []string{"", "[", "(", `(?=a)`, `(a)\1`, `(?i)chatgpt`, "a{256}", "((a{100}){100}){100}", "a\nb", "a\x00b", strings.Repeat("a", 201), "[[.x.]]", "[[=x=]]", string([]byte{0xff})} {
		if err := validateShadowRegex(value); err == nil {
			t.Errorf("accepted invalid/expansive expression %q", value)
		}
	}
}

func TestShadowRegexFiltersAreExplicitAndParameterized(t *testing.T) {
	plain, err := parseShadowFilter(url.Values{"provider": {"chatgpt.com"}, "device_id": {"11111111-1111-4111-8111-111111111111"}})
	if err != nil || !strings.Contains(plain.Where, " = ANY(") || strings.Contains(plain.Where, "~*") || !strings.Contains(plain.Where, "::uuid[]") {
		t.Fatalf("literal API filter changed: %v / %s", err, plain.Where)
	}
	pattern := "(chatgpt|claude)"
	f, err := parseShadowFilter(url.Values{"provider": {pattern}, "model": {`^gpt-5\.`}, "device_id": {"1111"}, "query": {"chrome|firefox"}, "regex": {"provider", "model", "device_id", "query"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.Where, pattern) || !strings.Contains(f.EventWhere, "e.provider ~* ANY(") || !strings.Contains(f.EventWhere, "e.device_id::text ~* ANY(") || !strings.Contains(f.JoinWhere, "d.hostname ~*") {
		t.Fatalf("regex escaped its parameter or predicate stage: %s / %s", f.EventWhere, f.JoinWhere)
	}
	if !reflect.DeepEqual(f.Criteria["regex"], []string{"provider", "model", "device_id", "query"}) {
		t.Fatalf("unstable regex metadata: %#v", f.Criteria)
	}
}

func TestShadowRegexRejectsUnavailableModesAndMalformedValues(t *testing.T) {
	for _, query := range []url.Values{
		{"regex": {"not_a_field"}, "action": {"blocked"}},
		{"regex": {"actor_id"}, "actor_id": {"["}},
		{"regex": {"provider"}},
		{"regex": {"provider", "provider"}, "provider": {"chatgpt"}},
		{"regex": {"provider"}, "provider": {"["}},
		{"regex": {"device_id"}, "device_id": {"(?=x)"}},
		{"regex": {"query"}, "query": {strings.Repeat("a", 101)}},
		{"regex": {"provider"}, "provider": {strings.Repeat("a", 201)}},
		{"regex": {"provider"}, "provider": make([]string, 21)},
	} {
		if _, err := parseShadowFilter(query); err == nil {
			t.Errorf("accepted malformed regex criteria %#v", query)
		}
	}
}

func TestShadowRegexSavedCriteriaRoundTrip(t *testing.T) {
	criteria := map[string]json.RawMessage{"provider": json.RawMessage(`["chatgpt"]`), "regex": json.RawMessage(`["provider"]`)}
	query, err := criteriaValues(criteria)
	if err != nil {
		t.Fatal(err)
	}
	f, err := parseShadowFilter(query)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.Criteria["provider"], []string{"chatgpt"}) || !reflect.DeepEqual(f.Criteria["regex"], []string{"provider"}) {
		t.Fatalf("saved regex lost: %#v", f.Criteria)
	}
	criteria["regex"] = json.RawMessage(`{"provider":true}`)
	if _, err = criteriaValues(criteria); err == nil {
		t.Fatal("object accepted as regex selection")
	}
}

func TestShadowRegexReadDeadline(t *testing.T) {
	for _, path := range []string{"/api/shadow/events?provider=chatgpt&regex=provider", "/api/shadow/conversations?provider=chatgpt&regex=provider", "/api/shadow/export?provider=chatgpt&regex=provider"} {
		r, cancel := dataReadRequest(httptest.NewRequest("GET", path, nil))
		deadline, ok := r.Context().Deadline()
		cancel()
		if !ok || time.Until(deadline) > regexReadBudget || time.Until(deadline) < regexReadBudget-time.Second {
			t.Fatal("regex read has no five-second deadline")
		}
	}
	r, cancel := dataReadRequest(httptest.NewRequest("POST", "/api/shadow/filters?regex=provider", nil))
	defer cancel()
	if _, ok := r.Context().Deadline(); ok {
		t.Fatal("saved-view mutation acquired a read deadline")
	}
}
