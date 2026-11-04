package app

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func TestMachineNameRequiresEffectiveDevicePermission(t *testing.T) {
	a := &App{}
	const device = "33333333-3333-4333-8333-333333333333"
	for _, permissions := range [][]string{nil, {permEventsRead}, {permPolicyManage}} {
		r := httptest.NewRequest("GET", "/api/shadow/events", nil)
		r = r.WithContext(context.WithValue(r.Context(), privacyContextKey{}, &privacyRequest{session: &Session{Permissions: permissions}}))
		// Invalid ciphertext must never be opened by a reader outside the ceiling.
		got, err := a.machineName(r, "synthetic-org", device, "invalid-ciphertext")
		if err != nil || got != deviceAlias(device) {
			t.Fatalf("permissions %v: name=%q err=%v", permissions, got, err)
		}
	}
	for _, privacy := range []*privacyRequest{nil, {}} {
		r := httptest.NewRequest("GET", "/api/shadow/events", nil)
		r = r.WithContext(context.WithValue(r.Context(), privacyContextKey{}, privacy))
		if _, err := a.machineName(r, "synthetic-org", device, ""); err == nil {
			t.Fatal("missing authority context accepted")
		}
	}
}

func TestEventsReadKeyCannotReadOrSearchMachineNames(t *testing.T) {
	p := newProjectionFixture(t)
	mint := func(permissions []string) string {
		t.Helper()
		w := p.call("POST", "/api/profile/api-keys", map[string]any{
			"name": "Synthetic machine ceiling", "expires_in_days": 30,
			"permissions": permissions, "content_access": false,
		}, p.csrf)
		requireHTTP(t, w, 201)
		var key struct{ Secret string `json:"secret"` }
		if err := json.Unmarshal(w.Body.Bytes(), &key); err != nil || key.Secret == "" {
			t.Fatal("synthetic key missing", err)
		}
		return key.Secret
	}
	for _, devices := range []bool{false, true} {
		permissions := []string{permEventsRead}
		if devices {
			permissions = append(permissions, permDevicesRead)
		}
		key := mint(permissions)
		get := func(path string) *httptest.ResponseRecorder {
			return p.callAs("GET", path, nil, nil, "", key)
		}
		w := get("/api/session")
		requireHTTP(t, w, 200)
		var session struct{ Permissions []string `json:"permissions"` }
		if err := json.Unmarshal(w.Body.Bytes(), &session); err != nil || len(session.Permissions) != len(permissions) {
			t.Fatal("unexpected effective ceiling", err)
		}
		for _, permission := range permissions {
			if !slices.Contains(session.Permissions, permission) {
				t.Fatal("permission missing", permission)
			}
		}
		wantName := deviceAlias(p.device)
		if devices {
			wantName = p.s.host
		} else {
			requireHTTP(t, get("/api/devices"), 403)
		}
		base := "/api/shadow/events?device_id=" + p.device
		w = get(base)
		requireHTTP(t, w, 200)
		var page struct{ Items []ShadowEventView `json:"items"` }
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || len(page.Items) != 1 || page.Items[0].Hostname != wantName {
			t.Fatal("wrong machine projection", err)
		}
		w = get(base + "&identity=aliases")
		requireHTTP(t, w, 200)
		if strings.Contains(w.Body.String(), p.s.host) {
			t.Fatal("explicit alias exposed machine name")
		}
		for _, field := range []string{"device_name", "query"} {
			q := url.Values{"device_id": {p.device}, field: {p.s.host}}
			if field == "query" {
				q.Set("regex", "query")
			}
			w = get("/api/shadow/events?" + q.Encode())
			requireHTTP(t, w, 200)
			if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
				t.Fatal(err)
			}
			wantCount := 0
			if devices {
				wantCount = 1
			}
			if len(page.Items) != wantCount {
				t.Fatalf("%s devices.read=%v: got %d rows", field, devices, len(page.Items))
			}
		}
	}
}
