package app

import (
	"strings"
	"testing"
	"time"
)

func TestModelAccessValidation(t *testing.T) {
	base := ModelAccessRule{"chatgpt", "browser", "denylist", []string{"Astra6"}}
	if e := validateModelAccess([]ModelAccessRule{base}); e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"off", "allowlist", "denylist"} {
		r := base
		r.Mode = mode
		r.Models = []string{}
		if e := validateModelAccess([]ModelAccessRule{r}); e != nil {
			t.Fatal(e)
		}
	}
	for _, model := range []string{"", "*", "astra 6", "../astra", "astrá", "a\n", "a?", strings.Repeat("a", 201)} {
		r := base
		r.Models = []string{model}
		if validateModelAccess([]ModelAccessRule{r}) == nil {
			t.Fatalf("accepted invalid model %q", model)
		}
	}
	r := base
	r.Models = []string{"Astra6", "Astra6"}
	if validateModelAccess([]ModelAccessRule{r}) == nil {
		t.Fatal("accepted duplicate model")
	}
	if validateModelAccess([]ModelAccessRule{base, base}) == nil {
		t.Fatal("accepted duplicate rule")
	}
	r = base
	r.Channel = "native"
	if validateModelAccess([]ModelAccessRule{r}) == nil {
		t.Fatal("accepted cross-channel platform")
	}
	r = ModelAccessRule{"codex", "native", "denylist", []string{"Astra6"}}
	if (validateModelAccess([]ModelAccessRule{r}) == nil) != (Edition == "commercial") {
		t.Fatal("edition boundary")
	}
	for _, entry := range modelCatalog() {
		if Edition == "community" && entry.Channel != "browser" {
			t.Fatal("Enterprise catalog leaked")
		}
	}
	cfg := defaultShadowConfig()
	cfg.ModelAccess = []ModelAccessRule{base}
	legacy := legacyModelConfig(cfg)
	if legacy.Services[0].Mode != "block" || !legacy.Services[0].Enabled || cfg.Services[0].Mode != "observe" {
		t.Fatal("legacy projection failed or mutated original")
	}
	if legacy.Services[1].Mode != "observe" {
		t.Fatal("unrelated service restricted")
	}
}
func TestEnforcementFreshness(t *testing.T) {
	now := time.Now()
	old := now.Add(-4 * time.Minute)
	future := now.Add(time.Minute)
	// A report stamped slightly ahead of the reading clock is clock disagreement
	// between the server and the database, not a stale device: it must stay fresh.
	// A strict future check turned a few milliseconds of skew into "unavailable"
	// for a device that had just reported "applied", which is also what made the
	// integration subtest fail intermittently.
	skewed := now.Add(2 * time.Second)
	cases := []struct {
		version string
		rev     int64
		status  string
		at      *time.Time
		want    string
	}{
		{"0.3.9", 0, "", nil, "needs_update"}, {"0.4.0", 0, "", nil, "pending"},
		{"0.4.0", 3, "applied", &now, "applied"}, {"0.4.0", 2, "applied", &now, "pending"},
		{"0.4.0", 3, "applied", &old, "unavailable"}, {"0.4.0", 3, "applied", &future, "unavailable"},
		{"0.4.0", 3, "applied", &skewed, "applied"},
		{"0.4.0", 3, "unavailable", &now, "unavailable"},
	}
	for _, c := range cases {
		if got := enforcementState(c.version, 3, c.rev, c.status, c.at, now); got != c.want {
			t.Fatalf("%+v got %s", c, got)
		}
	}
	report := enforcementReport{3, "chatgpt", "browser", "applied", "", "browser-request"}
	if !validEnforcementReport(report) {
		t.Fatal("valid report rejected")
	}
	report.Mechanism = "local-proxy"
	if validEnforcementReport(report) {
		t.Fatal("mechanism mismatch allowed")
	}
	report.Mechanism = "browser-request"
	report.Reason = "secret token"
	if validEnforcementReport(report) {
		t.Fatal("free-text report reason allowed")
	}
}
