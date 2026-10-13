package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCloseAccountConsole: the account-console client is disabled and manage-account
// leaves the default roles; nothing else is touched, and a second pass changes nothing.
func TestCloseAccountConsole(t *testing.T) {
	enabled, composite := true, true
	var writes []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.RequestURI() {
		case "GET /clients?clientId=account-console":
			// Keycloak's clientId filter is exact; a looser answer must not disable others.
			reply(w, 200, []map[string]any{{"id": "c-other", "clientId": "milvago-console", "enabled": true}, {"id": "c-account", "clientId": "account-console", "enabled": enabled}})
		case "PUT /clients/c-account":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			enabled = body["enabled"] != false
			writes = append(writes, "client")
			w.WriteHeader(204)
		case "GET /":
			reply(w, 200, map[string]any{"defaultRole": map[string]any{"id": "role-default"}})
		case "GET /roles-by-id/role-default/composites":
			roles := []map[string]any{{"id": "r-offline", "name": "offline_access", "clientRole": false}, {"id": "r-view", "name": "view-profile", "clientRole": true}}
			if composite {
				roles = append(roles, map[string]any{"id": "r-manage", "name": "manage-account", "clientRole": true})
			}
			reply(w, 200, roles)
		case "DELETE /roles-by-id/role-default/composites":
			var body []map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if len(body) != 1 || body[0]["id"] != "r-manage" {
				t.Errorf("only manage-account may leave the default roles: %v", body)
			}
			composite = false
			writes = append(writes, "role")
			w.WriteHeader(204)
		default:
			t.Errorf("unexpected identity request: %s %s", r.Method, r.URL.RequestURI())
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	admin := identityAdmin{client: server.Client(), token: "synthetic-token", base: server.URL}
	for range 2 {
		if e := closeAccountConsole(context.Background(), &admin); e != nil {
			t.Fatal(e)
		}
	}
	if enabled || composite || len(writes) != 2 {
		t.Fatalf("account console still open: client enabled=%v, manage-account=%v, writes=%v", enabled, composite, writes)
	}
}

func TestIdentityAdminHasOTP(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		body      string
		want      bool
		wantError bool
	}{
		{name: "enrolled", status: 200, body: `[{"type":"password"},{"type":"otp"}]`, want: true},
		{name: "not enrolled", status: 200, body: `[{"type":"password"}]`},
		{name: "null list", status: 200, body: "null", wantError: true},
		{name: "unavailable", status: 503, body: `{"error":"unavailable"}`, wantError: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/users/synthetic-user/credentials" {
					t.Errorf("unexpected identity request: %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			admin := identityAdmin{client: server.Client(), token: "synthetic-token", base: server.URL}
			got, err := admin.hasOTP(context.Background(), "synthetic-user")
			if got != tc.want || (err != nil) != tc.wantError {
				t.Fatalf("hasOTP = %v, error = %v; want %v, error %v", got, err, tc.want, tc.wantError)
			}
		})
	}
}
