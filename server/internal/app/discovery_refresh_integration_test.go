package app

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func seedDiscoveryRefresh(t *testing.T, f *observabilityFixture) {
	t.Helper()
	ctx := context.Background()
	const device = "00000000-0000-4000-8000-000000000001"
	for n, query := range []string{
		`INSERT INTO devices(organization_id,id,credential_hash,hostname,platform,version,status) VALUES($1,$2,$3,'Synthetic refresh host','test','0.7.0','approved')`,
		`INSERT INTO discovery_entities(organization_id,device_id,scope,id,kind,sequence) VALUES($1,$2,'endpoint','process/1','process',1)`,
		`INSERT INTO discovery_identifications(organization_id,device_id,scope,entity_id,application_id,signature_id,signature_revision,state,evidence,sequence) VALUES($1,$2,'endpoint','process/1','openclaw','fixture',1,'executed','[]',1)`,
	} {
		args := []any{f.org, device}
		if n == 0 {
			args = append(args, hash(randomToken()))
		}
		if _, err := f.admin.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDiscoveryRefreshIndependentTransactionIsTenantScopedAndReadOnly(t *testing.T) {
	f := newObservabilityFixture(t)
	seedDiscoveryRefresh(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	key := discoveryReadKey{f.org, "", "", 50, false}
	additional := discoveryAdditionalInventoryDevices(&Session{})
	value, err := f.a.refreshDiscoveryApplications(ctx, key, additional)
	if err != nil {
		t.Fatal(err)
	}
	var page struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if json.Unmarshal(value, &page) != nil || len(page.Items) != 1 || page.Items[0].ID != "openclaw" {
		t.Fatal("independent transaction lost the authorized aggregate")
	}
	key.organization = "11111111-1111-4111-8111-111111111111"
	value, err = f.a.refreshDiscoveryApplications(ctx, key, additional)
	if err != nil || json.Unmarshal(value, &page) != nil || len(page.Items) != 0 {
		t.Fatal("refresh crossed its tenant", err)
	}
	// An accidental write in a future inventory adapter must fail in this path.
	_, err = f.admin.Exec(ctx, `CREATE FUNCTION synthetic_refresh_write() RETURNS SETOF discovery_identifications LANGUAGE plpgsql AS $$ BEGIN INSERT INTO discovery_reviews(organization_id,application_id,status) VALUES(current_setting('milvago.organization_id')::uuid,'synthetic-write','review'); RETURN; END $$`)
	if err != nil {
		t.Fatal(err)
	}
	key.organization = f.org
	_, err = f.a.refreshDiscoveryApplications(ctx, key, `SELECT application_id,device_id,0::bigint instances,first_seen,last_seen,false executed,false indication,false installed,false interface FROM synthetic_refresh_write()`)
	if databaseError, ok := err.(*pgconn.PgError); !ok || databaseError.Code != "25006" {
		t.Fatal("background transaction was writable", err)
	}
	var writes int
	if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM discovery_reviews WHERE application_id='synthetic-write'`).Scan(&writes); err != nil || writes != 0 {
		t.Fatal("failed refresh changed inventory", err)
	}
	if f.a.db.Stat().AcquiredConns() != 0 {
		t.Fatal("refresh retained a database connection")
	}
}

func TestDiscoveryRefreshSurvivesForegroundTransactionCompletion(t *testing.T) {
	f := newObservabilityFixture(t)
	seedDiscoveryRefresh(t, f)
	path := "/api/discovery/applications?q=openclaw"
	requireHTTP(t, f.call("GET", path, nil, ""), 200)
	var key discoveryReadKey
	f.a.discoveryReads.Lock()
	for current := range f.a.discoveryReads.entries {
		if current.organization == f.org && current.query == "openclaw" {
			key = current
		}
	}
	f.a.discoveryReads.Unlock()
	if key.organization == "" {
		t.Fatal("aggregate not cached")
	}
	expireDiscoveryRead(t, &f.a.discoveryReads, key, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	locker, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Rollback(ctx)
	if _, err := locker.Exec(ctx, `LOCK TABLE discovery_identifications IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	// The old request transaction is committed by the HTTP wrapper before this
	// call returns. The independently blocked refresh must remain usable after it.
	requireHTTP(t, f.call("GET", path, nil, ""), 200)
	f.a.discoveryReads.Lock()
	flight := f.a.discoveryReads.entries[key]
	f.a.discoveryReads.Unlock()
	if flight.previous == nil {
		t.Fatal("background refresh was not admitted")
	}
	if _, err := locker.Exec(ctx, `UPDATE discovery_identifications SET state='installed' WHERE organization_id=$1`, f.org); err != nil {
		t.Fatal(err)
	}
	if err := locker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	awaitDiscoveryRefresh(t, flight.done)
	if flight.err != nil {
		t.Fatal("refresh reused a completed request transaction", flight.err)
	}
	var page struct {
		Items []struct {
			States []string `json:"states"`
		} `json:"items"`
	}
	if json.Unmarshal(flight.value, &page) != nil || len(page.Items) != 1 || len(page.Items[0].States) != 1 {
		t.Fatal("independent refresh failed to return inventory")
	}
	// A query waiting on a relation lock may already own an earlier MVCC snapshot.
	// The next hard-expired read must observe the completed update.
	expireDiscoveryRead(t, &f.a.discoveryReads, key, 3*time.Second)
	current := f.call("GET", path, nil, "")
	requireHTTP(t, current, 200)
	if json.Unmarshal(current.Body.Bytes(), &page) != nil || len(page.Items) != 1 || len(page.Items[0].States) != 1 || page.Items[0].States[0] != "installed" {
		t.Fatal("fresh read lost the committed inventory")
	}
}
