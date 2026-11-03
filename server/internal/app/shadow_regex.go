package app

import (
	"net/url"
	"regexp/syntax"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Existing API links and saved views retain literal filters. Only fields named
// explicitly by the structured search use regular expressions.
var shadowRegexFields = []string{"provider", "model", "device_name", "device_id", "actor_id", "tool", "action", "kind", "attachment", "sensitivity", "dlp_rule", "dlp_mode", "dlp_consequence", "dlp_outcome", "query"}

func invalidShadowRegex() error {
	return apiError{400, "invalid_search_regex", "Use a valid, bounded extended regular expression."}
}

func validateShadowRegex(value string) error {
	if value == "" || len(value) > 200 || !utf8.ValidString(value) || strings.Contains(value, "[[.") || strings.Contains(value, "[[=") {
		return invalidShadowRegex()
	}
	for _, ch := range value {
		if unicode.IsControl(ch) {
			return invalidShadowRegex()
		}
	}
	// POSIX ERE excludes backreferences, lookarounds and embedded options. The
	// same subset is accepted by PostgreSQL without changing its interpretation.
	tree, err := syntax.Parse(value, syntax.POSIX)
	if err != nil || shadowRegexCost(tree) > 512 {
		return invalidShadowRegex()
	}
	return nil
}

// Estimate expansion before Simplify/Compile: nested counted repetitions must
// never allocate a huge program while validating an otherwise short pattern.
func shadowRegexCost(tree *syntax.Regexp) int {
	if tree == nil {
		return 513
	}
	cost := 1 + len(tree.Rune)
	for _, child := range tree.Sub {
		cost += shadowRegexCost(child)
		if cost > 512 {
			return 513
		}
	}
	if tree.Op == syntax.OpRepeat {
		if tree.Min > 255 || tree.Max > 255 {
			return 513
		}
		count := tree.Max
		if count < 0 {
			count = tree.Min + 1
		}
		cost *= count + 1
	}
	if cost > 512 {
		return 513
	}
	return cost
}

func shadowRegexSelection(q url.Values) (map[string]bool, error) {
	out := map[string]bool{}
	if len(q["regex"]) > len(shadowRegexFields) {
		return nil, invalidShadowRegex()
	}
	for _, key := range q["regex"] {
		if !slices.Contains(shadowRegexFields, key) || out[key] || q.Get(key) == "" {
			return nil, invalidShadowRegex()
		}
		out[key] = true
	}
	return out, nil
}

func shadowRegexValues(values []string) ([]string, error) {
	if len(values) > 20 {
		return nil, invalidShadowRegex()
	}
	out := []string{}
	for _, value := range values {
		if err := validateShadowRegex(value); err != nil {
			return nil, err
		}
		if !slices.Contains(out, value) {
			out = append(out, value)
		}
	}
	return out, nil
}
