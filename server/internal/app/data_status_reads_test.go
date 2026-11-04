package app

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDataReadDeploymentPagesAreComplete(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	if _, err := f.admin.Exec(ctx, `INSERT INTO devices(organization_id,id,credential_hash,hostname,platform,version,status)
 SELECT $1,('00000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,decode(md5('status-secret-'||n)||md5('status-secret-'||n),'hex'),'Synthetic','test','0.7.28','approved' FROM generate_series(1,205)n`, f.org); err != nil {
		t.Fatal(err)
	}
	f.a.console("GET /api/read-status-test", permOverviewRead, f.a.modelAccessStatus)
	path := "/api/read-status-test"
	seen := map[string]bool{}
	for page := 0; page < 3; page++ {
		w := f.callAs("GET", path, nil, f.owner, f.csrf, "")
		requireHTTP(t, w, 200)
		var result struct {
			Items []modelStatusItem `json:"items"`
			Next  string            `json:"next"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		// Even a page containing no active rules has a continuation to the next
		// devices. Empty policy rows must not silently terminate the fleet listing.
		if page < 2 && result.Next == "" {
			t.Fatal("deployment page lost its continuation")
		}
		if page == 2 && result.Next != "" {
			t.Fatal("final page did not terminate")
		}
		if result.Next != "" {
			if seen[result.Next] {
				t.Fatal("cursor repeated")
			}
			seen[result.Next] = true
			path = "/api/read-status-test?after=" + result.Next
		}
	}
	requireHTTP(t, f.callAs("GET", "/api/read-status-test?after=%27%20OR%201%3D1", nil, f.owner, f.csrf, ""), 400)
	if _, err := f.admin.Exec(ctx, `INSERT INTO privacy_settings(organization_id,configuration) VALUES($1,'{"aggregate_only":true,"k_anonymity":5}') ON CONFLICT(organization_id) DO UPDATE SET configuration=privacy_settings.configuration||excluded.configuration`, f.org); err != nil {
		t.Fatal(err)
	}
	w := f.callAs("GET", "/api/read-status-test", nil, f.owner, f.csrf, "")
	requireHTTP(t, w, 200)
	var result map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if string(result["items"]) != "[]" || result["next"] != nil || strings.Contains(w.Body.String(), "Synthetic") {
		t.Fatal("aggregate deployment leaked a device or cursor")
	}
	for cursor := range seen {
		requireHTTP(t, f.callAs("GET", "/api/read-status-test?after="+cursor, nil, f.owner, f.csrf, ""), 400)
		break
	}
}

func TestDataReadModelReportsUseOneBatch(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	if _, err := f.admin.Exec(ctx, `INSERT INTO devices(organization_id,id,credential_hash,hostname,platform,version,status)
 SELECT $1,md5('report-device-'||n)::uuid,decode(md5('report-secret-'||n)||md5('report-secret-'||n),'hex'),'Synthetic','test','0.7.28','approved' FROM generate_series(1,100)n`, f.org); err != nil {
		t.Fatal(err)
	}
	tx, err := tenantTx(ctx, f.a.db, f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT id,version,platform,kind,status FROM devices ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	devices := []modelStatusDevice{}
	for rows.Next() {
		var d modelStatusDevice
		if err = rows.Scan(&d.id, &d.version, &d.platform, &d.kind, &d.status); err != nil {
			t.Fatal(err)
		}
		devices = append(devices, d)
	}
	rows.Close()
	if rows.Err() != nil {
		t.Fatal(rows.Err())
	}
	counted := &policyCountingTx{Tx: tx}
	_, err = f.a.modelStatusItems(httptest.NewRequest("GET", "/api/read-status-test", nil), counted, &Session{OrganizationID: f.org}, devices)
	if err != nil {
		t.Fatal(err)
	}
	if counted.calls > 22 {
		t.Fatalf("100-device deployment used %d SQL reads", counted.calls)
	}
	t.Logf("100-device deployment uses %d SQL reads including policies and reports", counted.calls)
}
