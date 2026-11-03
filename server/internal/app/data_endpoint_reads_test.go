package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Exercise actual HTTP authorization/tenant/projection paths on the large event
// and fleet fixture, rather than timing SQL with a privileged database role.
func verifyLargeDataReadEndpoints(t *testing.T, f *observabilityFixture) {
	t.Helper()
	paths := []string{"/api/overview", "/api/devices?limit=100", "/api/groups", "/api/detection/candidates", "/api/detection/platforms", "/api/shadow/cartography", "/api/shadow/conversations?limit=25", "/api/shadow/conversations?view=browser&limit=25", "/api/shadow/events?limit=100", "/api/discovery/summary", "/api/discovery/applications?limit=50", "/api/discovery/environments?limit=50", "/api/discovery/coverage?limit=50", "/api/dlp/status", "/api/shadow/cartography?identity=revealed"}
	for _, path := range paths {
		t.Run("large_read_"+path, func(t *testing.T) {
			if path == "/api/shadow/cartography?identity=revealed" {
				if _, err := f.admin.Exec(context.Background(), `INSERT INTO privacy_settings(organization_id,configuration) VALUES($1,'{"pseudonymous":false}') ON CONFLICT(organization_id) DO UPDATE SET configuration=privacy_settings.configuration||excluded.configuration`, f.org); err != nil {
					t.Fatal(err)
				}
			}
			var trace *dataReadTrace
			if strings.HasPrefix(path, "/api/shadow/cartography") {
				var cleanup func()
				trace, cleanup = traceDataReadFixture(t, f)
				defer cleanup()
			}
			start := time.Now()
			w := f.callAs("GET", path, nil, f.owner, f.csrf, "")
			elapsed := time.Since(start)
			requireHTTP(t, w, 200)
			if trace != nil && elapsed > time.Second {
				trace.explainSlow(t, f)
			}
			if elapsed > 5*time.Second {
				t.Fatalf("bounded fixture read took %s", elapsed)
			}
			if w.Body.Len() > 16<<20 || !json.Valid(w.Body.Bytes()) {
				t.Fatal("unbounded or invalid JSON read")
			}
			var result struct {
				Items    []json.RawMessage `json:"items"`
				Flows    []json.RawMessage `json:"flows"`
				Timeline []json.RawMessage `json:"timeline"`
				Devices  int               `json:"devices"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(path, "/api/devices?") && len(result.Items) != 100 {
				t.Fatal("device page dropped rows")
			}
			if path == "/api/overview" && (result.Devices != 10000 || len(result.Timeline) != 24) {
				t.Fatal("overview totals or hourly series changed")
			}
			if strings.Contains(path, "limit=50") && len(result.Items) > 50 {
				t.Fatal("discovery page exceeded requested size")
			}
			t.Logf("HTTP %s: %s, %d bytes", path, elapsed, w.Body.Len())
		})
	}
}
