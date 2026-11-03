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

type heartbeatBrowser struct {
	Tool     string    `json:"tool"`
	LastSeen time.Time `json:"last_seen"`
}

// deviceHeartbeat records the interactive OS user reported by an approved
// device on each synchronization pass. The value is informational only: it
// never grants authority, is never logged, and is not audited (one report per
// minute per device would flood the append-only audit).
func (a *App) deviceHeartbeat(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DiscoveryEngine *int              `json:"discovery_engine"`
		DLPEngine       *int              `json:"dlp_engine"`
		OSUser          *string           `json:"os_user"`
		Version         *string           `json:"version"`
		DetectorHealth  []DetectorBatch   `json:"detector_health"`
		CollectorHealth []CollectorHealth `json:"collector_health"`
		// Browsers whose extension talked to the local agent recently. Without it a
		// user who disables the extension simply disappears from the console, with
		// nothing distinguishing "no AI use" from "no longer supervised".
		Browsers []heartbeatBrowser `json:"browsers"`
	}
	if e := decode(w, r, &body); e != nil {
		a.fail(w, e)
		return
	}
	if body.DLPEngine != nil && (*body.DLPEngine < 0 || *body.DLPEngine > 3) {
		a.fail(w, bad(msgInvalidHeartbeat))
		return
	}
	if body.DiscoveryEngine != nil && (*body.DiscoveryEngine < 0 || *body.DiscoveryEngine > 1) {
		a.fail(w, bad(msgInvalidHeartbeat))
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
	encoded, e := encodeHeartbeatBrowsers(body.Browsers, time.Now().UTC())
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
		a.failTransaction(w, r, tx, e)
		return
	}
	if body.OSUser != nil {
		user, e = a.sealIdentity(org, "device-user:"+device, user)
		if e != nil {
			a.failTransaction(w, r, tx, e)
			return
		}
	}
	// Omitted presence preserves the last report; an explicit empty list clears it.
	var sealedUser *string
	if body.OSUser != nil {
		sealedUser = &user
	}
	var collector []byte
	if body.CollectorHealth != nil {
		if !validCollectorHealth(body.CollectorHealth) {
			a.failTransaction(w, r, tx, bad("Invalid collector health."))
			return
		}
		collector, _ = json.Marshal(body.CollectorHealth)
	}
	var capabilities []string
	e = tx.QueryRow(r.Context(), `UPDATE devices SET os_user=coalesce($1,os_user),browsers=coalesce($2::jsonb,browsers),version=coalesce($3,version),last_seen=now(),collector_health=coalesce($5::jsonb,collector_health) WHERE id=$4 RETURNING capabilities`, sealedUser, encoded, body.Version, device, collector).Scan(&capabilities)
	if e == nil {
		next := heartbeatCapabilities(capabilities, body.Version != nil, body.DLPEngine, body.DiscoveryEngine)
		if !slices.Equal(next, capabilities) {
			raw, _ := json.Marshal(next)
			_, e = tx.Exec(r.Context(), "UPDATE devices SET capabilities=$1 WHERE id=$2", raw, device)
		}
	}
	if e == nil {
		e = tx.Commit(r.Context())
	}
	if e != nil {
		a.failTransaction(w, r, tx, e)
		return
	}
	reply(w, 200, map[string]any{"ok": true, "accepted_health_ids": accepted})
}

// A normal heartbeat already updates last_seen. Avoid further row versions and
// round trips when its negotiated capabilities have not changed.
func heartbeatCapabilities(existing []string, versionReported bool, dlp, discovery *int) []string {
	next := slices.Clone(existing)
	set := func(name string, enabled bool) {
		if enabled {
			if !slices.Contains(next, name) {
				next = append(next, name)
			}
		} else {
			next = slices.DeleteFunc(next, func(value string) bool { return value == name })
		}
	}
	if versionReported || dlp != nil {
		for index, name := range []string{"dlp-v1", "dlp-confirm-v1", "dlp-contextual-v1"} {
			set(name, dlp != nil && *dlp >= index+1)
		}
	}
	if versionReported || discovery != nil {
		set("discovery-v1", discovery != nil && *discovery == 1)
	}
	return next
}

func encodeHeartbeatBrowsers(reported []heartbeatBrowser, now time.Time) ([]byte, error) {
	if reported == nil {
		return nil, nil
	}
	if len(reported) > len(browserTools) {
		return nil, bad(msgInvalidHeartbeat)
	}
	browsers := map[string]time.Time{}
	for _, browser := range reported {
		// A report cannot invent a browser or keep one active indefinitely.
		if !slices.Contains(browserTools, browser.Tool) || browser.LastSeen.After(now.Add(5*time.Minute)) || browser.LastSeen.Before(now.Add(-24*time.Hour)) {
			return nil, bad(msgInvalidHeartbeat)
		}
		browsers[browser.Tool] = browser.LastSeen.UTC()
	}
	return json.Marshal(browsers)
}

func validCollectorHealth(reported []CollectorHealth) bool {
	if Edition != "commercial" || len(reported) > 32 {
		return false
	}
	for _, h := range reported {
		if !slices.Contains(collectorHealthTools, h.Tool) || !slices.Contains(collectorHealthStates, h.State) || (h.Version != "" && !validMetadata(h.Version, 64)) || h.SkippedTrees < 0 || h.Tampered < 0 {
			return false
		}
	}
	return true
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
