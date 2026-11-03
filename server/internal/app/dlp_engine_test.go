package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestDLPEngineCanonicalLanguageAndSimulation(t *testing.T) {
	var compiled struct {
		Rule   DLPRule `json:"rule"`
		Source string  `json:"source"`
	}
	err := dlpEngine(context.Background(), map[string]any{"op": "parse", "source": "WHEN prompt CONTAINS \"Tomate\"\nSCOPE channel = \"browser\"\nTHEN REPLACE \"Tomate\" WITH \"Carotte\""}, &compiled)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Rule.Mode != "simulation" || !strings.Contains(compiled.Source, "REPLACE") {
		t.Fatalf("unexpected compilation: %#v", compiled)
	}
	policy := defaultDLP("endpoint")
	policy.Inspection = true
	policy.Rules = []DLPRule{compiled.Rule}
	var result struct {
		Result DLPOutput `json:"result"`
	}
	input := DLPInput{Policy: policy, Texts: map[string][]string{"prompt": {"Tomate"}}, Facts: map[string]string{"channel": "browser"}}
	if err = dlpEngine(context.Background(), map[string]any{"op": "evaluate", "input": input}, &result); err != nil {
		t.Fatal(err)
	}
	if result.Result.Action != "observe" || result.Result.Texts["prompt"][0] != "Tomate" || len(result.Result.Decisions) != 1 {
		t.Fatalf("simulation changed content: %#v", result.Result)
	}
	input.Policy.Rules[0].Mode = "active"
	if err = dlpEngine(context.Background(), map[string]any{"op": "evaluate", "input": input}, &result); err != nil {
		t.Fatal(err)
	}
	if result.Result.Texts["prompt"][0] != "Carotte" || result.Result.Action != "transform" {
		t.Fatalf("replacement not applied: %#v", result.Result)
	}
}

func TestDLPEngineRejectsHostileShapesAndDoesNotLeakPreviousMemory(t *testing.T) {
	for _, request := range []any{
		map[string]any{"op": "parse", "source": map[string]string{"image": "fixture"}},
		map[string]any{"op": "parse", "source": "WHEN TRUE SCOPE TRUE THEN EXECUTE \"fixture\""},
		map[string]any{"op": "parse", "source": strings.Repeat("x", 20000)},
		map[string]any{"op": "parse", "source": "WHEN TRUE SCOPE TRUE THEN OBSERVE", "unknown": "fixture"},
	} {
		if err := dlpEngine(context.Background(), request, nil); err == nil {
			t.Fatal("hostile shape was accepted")
		}
	}
	for i := 0; i < 3; i++ {
		var output json.RawMessage
		if err := dlpEngine(context.Background(), map[string]any{"op": "parse", "source": "WHEN TRUE SCOPE TRUE THEN OBSERVE"}, &output); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(output), "fixture") {
			t.Fatal("previous request leaked")
		}
	}
}
