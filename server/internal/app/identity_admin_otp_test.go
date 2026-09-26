package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
