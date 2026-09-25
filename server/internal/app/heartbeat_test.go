package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHeartbeatVersionAndPresence(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	credential := randomToken()
	var device string
	if e := f.admin.QueryRow(ctx, "INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status) VALUES($1,$2,'test-device','windows','0.5.5','approved') RETURNING id", f.org, hash(credential)).Scan(&device); e != nil {
		t.Fatal(e)
	}
	call := func(body any) *httptest.ResponseRecorder {
		raw, e := json.Marshal(body)
		if e != nil {
			t.Fatal(e)
		}
		req := httptest.NewRequest("POST", "/v2/heartbeat", bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+credential)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.a.Handler().ServeHTTP(w, req)
		return w
	}
	read := func(t *testing.T) (string, map[string]time.Time) {
		t.Helper()
		var version string
		var raw []byte
		if e := f.admin.QueryRow(ctx, "SELECT version,browsers FROM devices WHERE id=$1", device).Scan(&version, &raw); e != nil {
			t.Fatal(e)
		}
		var browsers map[string]time.Time
		if e := json.Unmarshal(raw, &browsers); e != nil {
			t.Fatal(e)
		}
		return version, browsers
	}
	version, browsers := read(t)
	if version != "0.5.5" || len(browsers) != 0 {
		t.Fatal("fixture not obtained", version, browsers)
	}
	seen := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	requireHTTP(t, call(map[string]any{"browsers": []any{map[string]any{"tool": "chrome", "last_seen": seen}}}), 200)
	version, browsers = read(t)
	if version != "0.5.5" || len(browsers) != 1 || !browsers["chrome"].Equal(seen) {
		t.Fatal("presence without OS user not persisted", version, browsers)
	}
	requireHTTP(t, call(map[string]any{"version": "0.5.14", "browsers": []any{map[string]any{"tool": "chrome", "last_seen": seen}}}), 200)
	version, browsers = read(t)
	if version != "0.5.14" || len(browsers) != 1 || !browsers["chrome"].Equal(seen) {
		t.Fatal("runtime version or presence not persisted without OS user", version, browsers)
	}
	requireHTTP(t, call(map[string]any{"os_user": "synthetic-user"}), 200)
	version, browsers = read(t)
	if version != "0.5.14" || len(browsers) != 1 {
		t.Fatal("legacy heartbeat erased runtime diagnostics", version, browsers)
	}
	requireHTTP(t, call(map[string]any{"browsers": []any{}}), 200)
	version, browsers = read(t)
	if version != "0.5.14" || len(browsers) != 0 {
		t.Fatal("explicit absence not persisted", version, browsers)
	}
	for _, invalid := range []string{"", strings.Repeat("x", 65), "0.5.14\n", "0.5.14 ", "<version>"} {
		requireHTTP(t, call(map[string]any{"version": invalid}), 400)
	}
	version, _ = read(t)
	if version != "0.5.14" {
		t.Fatal("invalid version changed persisted value", version)
	}
}

func TestHeartbeatVersionValidation(t *testing.T) {
	for _, value := range []string{"0.5.14", "1.0.0-rc.1+build.2", strings.Repeat("a", 64)} {
		if !validHeartbeatVersion(value) {
			t.Fatal("valid version rejected", value)
		}
	}
	for _, value := range []string{"", strings.Repeat("a", 65), "0.5.14\n", "0.5.14 ", "<version>", "vérsion"} {
		if validHeartbeatVersion(value) {
			t.Fatal("invalid version accepted", value)
		}
	}
}
