package app

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	msgInvalidHeartbeat = "Invalid heartbeat."
)

// The browsers whose extension can report. Shared with event ingestion so the two
// vocabularies cannot drift apart.
var browserTools = []string{"chrome", "edge", "firefox", "chromium", "brave"}

// The native tools and states a collector health report may name.
var collectorHealthTools = []string{"claude-code", "codex", "claude-desktop", "otlp"}
var collectorHealthStates = []string{"ok", "unqualified_version", "format_error", "disabled", "config_unavailable", "attribution_failed", "listening", "waiting", "metadata_only", "error", "unexpected_metrics", "throttled"}

// deviceHeartbeat records the interactive OS user reported by an approved
// device on each synchronization pass. The value is informational only: it
// never grants authority, is never logged, and is not audited (one report per
// minute per device would flood the append-only audit).
func (a *App) deviceHeartbeat(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OSUser          *string           `json:"os_user"`
		Version         *string           `json:"version"`
		DetectorHealth  []DetectorBatch   `json:"detector_health"`
		CollectorHealth []CollectorHealth `json:"collector_health"`
		// Browsers whose extension talked to the local agent recently. Without it a
		// user who disables the extension simply disappears from the console, with
		// nothing distinguishing "no AI use" from "no longer supervised".
		Browsers []struct {
			Tool     string    `json:"tool"`
			LastSeen time.Time `json:"last_seen"`
		} `json:"browsers"`
	}
	if e := decode(w, r, &body); e != nil {
		a.fail(w, e)
		return
	}
	user := ""
	if body.OSUser != nil {
		user = strings.TrimSpace(*body.OSUser)
	}
	if !validOSUser(user) {
		a.fail(w, bad(msgInvalidHeartbeat))
		return
	}
	if body.Version != nil && !validHeartbeatVersion(*body.Version) {
		a.fail(w, bad("Invalid heartbeat version."))
		return
	}
	now := time.Now().UTC()
	browsers := map[string]time.Time{}
	if len(body.Browsers) > len(browserTools) {
		a.fail(w, bad(msgInvalidHeartbeat))
		return
	}
	for _, reported := range body.Browsers {
		// The device reports what its own extensions did; the server still bounds the
		// vocabulary and refuses a future timestamp, so a compromised device cannot
		// invent a browser or hold one alive indefinitely.
		if !slices.Contains(browserTools, reported.Tool) || reported.LastSeen.After(now.Add(5*time.Minute)) || reported.LastSeen.Before(now.Add(-24*time.Hour)) {
			a.fail(w, bad(msgInvalidHeartbeat))
			return
		}
		browsers[reported.Tool] = reported.LastSeen.UTC()
	}
	var encoded []byte
	var e error
	if body.Browsers != nil {
		encoded, e = json.Marshal(browsers)
	}
	if e != nil {
		a.fail(w, e)
		return
	}
	tx, org, device, e := a.deviceTx(r)
	if e != nil {
		a.fail(w, e)
		return
	}
	defer tx.Rollback(r.Context())
	accepted, e := a.acceptDetectorHealth(r, tx, org, device, body.DetectorHealth)
	if e != nil {
		a.fail(w, e)
		return
	}
	if body.OSUser != nil {
		user, e = a.sealIdentity(org, "device-user:"+device, user)
		if e != nil {
			a.fail(w, e)
			return
		}
	}
	// Omitted presence preserves the last report; an explicit empty list clears it.
	var sealedUser *string
	if body.OSUser != nil {
		sealedUser = &user
	}
	_, e = tx.Exec(r.Context(), `UPDATE devices SET os_user=coalesce($1,os_user),browsers=coalesce($2::jsonb,browsers),version=coalesce($3,version),last_seen=now() WHERE id=$4`, sealedUser, encoded, body.Version, device)
	if e == nil && body.CollectorHealth != nil {
		if Edition != "commercial" || len(body.CollectorHealth) > 32 {
			a.fail(w, bad("Invalid collector health."))
			return
		}
		for _, h := range body.CollectorHealth {
			if !slices.Contains(collectorHealthTools, h.Tool) || !slices.Contains(collectorHealthStates, h.State) || (h.Version != "" && !validMetadata(h.Version, 64)) || h.SkippedTrees < 0 || h.Tampered < 0 {
				a.fail(w, bad("Invalid collector health."))
				return
			}
		}
		raw, _ := json.Marshal(body.CollectorHealth)
		_, e = tx.Exec(r.Context(), "UPDATE devices SET collector_health=$1 WHERE id=$2", raw, device)
	}
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		a.fail(w, e)
		return
	}
	reply(w, 200, map[string]any{"ok": true, "accepted_health_ids": accepted})
}

// validOSUser bounds a reported user name: valid UTF-8, at most 128 bytes and
// no control characters (line breaks, tabs, escape sequences).
func validOSUser(value string) bool {
	if len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) || r == '\u2028' || r == '\u2029' {
			return false
		}
	}
	return true
}

// Reported version is diagnostic input, never authorization.
func validHeartbeatVersion(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '+') {
			return false
		}
	}
	return true
}
