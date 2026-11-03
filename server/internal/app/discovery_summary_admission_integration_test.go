package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type summaryHTTPResult struct {
	response *httptest.ResponseRecorder
	done     chan struct{}
	cancel   context.CancelFunc
}

func startSummaryHTTPRequest(t *testing.T, f *observabilityFixture, credential string, writer *discoveryDeniedBlockingWriter) *summaryHTTPResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	request := httptest.NewRequest("GET", "/api/discovery/applications?limit=50", nil).WithContext(ctx)
	request.Header.Set("Origin", f.a.config.AppURL)
	request.Header.Set("X-CSRF-Token", f.csrf)
	if credential != "" {
		request.Header.Set("Authorization", "Bearer "+credential)
	} else {
		request.AddCookie(f.owner)
	}
	result := &summaryHTTPResult{response: httptest.NewRecorder(), done: make(chan struct{}), cancel: cancel}
	var output http.ResponseWriter = result.response
	if writer != nil {
		output, result.response = writer, writer.ResponseRecorder
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-result.done:
		case <-time.After(5 * time.Second):
			t.Error("summary HTTP worker did not stop")
		}
	})
	go func() { defer close(result.done); f.a.Handler().ServeHTTP(output, request) }()
	return result
}

func awaitSummaryHTTP(t *testing.T, result *summaryHTTPResult, status int) {
	t.Helper()
	select {
	case <-result.done:
	case <-time.After(5 * time.Second):
		t.Fatal("summary HTTP worker did not finish")
	}
	requireHTTP(t, result.response, status)
}

func holdSummaryReviews(t *testing.T, f *observabilityFixture) pgx.Tx {
	t.Helper()
	tx, err := f.admin.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(context.Background(), `LOCK TABLE discovery_reviews IN ACCESS EXCLUSIVE MODE`); err != nil {
		tx.Rollback(context.Background())
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	return tx
}

func awaitSummaryFlight(t *testing.T, f *observabilityFixture) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		pending := false
		f.a.discoveryReads.Lock()
		for key, entry := range f.a.discoveryReads.entries {
			if key.organization == f.org && key.query == "" && key.after == "" && key.limit == 50 {
				select {
				case <-entry.done:
				default:
					pending = true
				}
			}
		}
		f.a.discoveryReads.Unlock()
		if pending && f.a.db.Stat().AcquiredConns() == 1 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("real summary computation did not occupy exactly one connection")
}

func summaryReportFixture(t *testing.T, f *observabilityFixture) (string, func(context.Context, int64) *httptest.ResponseRecorder) {
	t.Helper()
	ctx := context.Background()
	credential := randomToken()
	var device string
	if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,kind,capabilities) VALUES($1,$2,'Synthetic summary concurrency device','test','0.7.0','approved','browser','["discovery-v1"]') RETURNING id`, f.org, hash(credential)).Scan(&device); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_settings(organization_id,revision,configuration) VALUES($1,700,'{"host":true,"interval_seconds":300}')`, f.org); err != nil {
		t.Fatal(err)
	}
	policyRequest := httptest.NewRequest("GET", "/v1/discovery/policy", nil)
	policyRequest.Header.Set("Authorization", "Bearer "+credential)
	policyResponse := httptest.NewRecorder()
	f.a.Handler().ServeHTTP(policyResponse, policyRequest)
	requireHTTP(t, policyResponse, 200)
	var envelope map[string]string
	if err := json.Unmarshal(policyResponse.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope["payload"])
	if err != nil {
		t.Fatal(err)
	}
	var authorization struct {
		Revision int64 `json:"revision"`
	}
	if err = json.Unmarshal(payload, &authorization); err != nil || authorization.Revision <= 0 {
		t.Fatal("missing discovery authorization", err)
	}
	return device, func(ctx context.Context, sequence int64) *httptest.ResponseRecorder {
		now := time.Now().Unix()
		report := map[string]any{
			"version": 1, "catalog_revision": discoveryFixtureCatalogRevision, "settings_revision": authorization.Revision, "run_id": nil,
			"scope": "endpoint", "sequence": sequence, "page": 0, "pages": 1, "observed_at": now, "complete": false,
			"entities": []any{map[string]string{"id": "process/summary", "kind": "process"}}, "relations": []any{}, "coverage": []any{},
			"result": map[string]any{"identifications": []any{map[string]any{"application_id": "openclaw", "signature_id": "openclaw.process", "signature_revision": 1, "entity_id": "process/summary", "state": "executed", "evidence": []any{map[string]any{"fact_id": "fact/summary", "source": "host_process", "observed_at": now, "fields": []string{"executable"}}}}}, "communications": []any{}, "evaluated_facts": 0, "unknown_conditions": 0},
		}
		raw, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest("POST", "/v1/discovery/reports", bytes.NewReader(raw)).WithContext(ctx)
		request.Header.Set("Authorization", "Bearer "+credential)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		f.a.Handler().ServeHTTP(response, request)
		return response
	}
}

func TestDiscoverySummaryAdmissionKeepsTenCacheWaitersOutsideTransactions(t *testing.T) {
	f := newObservabilityFixture(t)
	people := discoveryLoadReaders(t, f, 10)
	device, report := summaryReportFixture(t, f)
	requireHTTP(t, report(context.Background(), 100), 200)
	// Complete all credential/quota transactions before starting the blocked
	// two-second summary query. This avoids timing the setup against its budget.
	preparation := summaryTestAdmission(&f.a.discoverySummaries)
	defer preparation.close()
	if err := preparation.acquire(context.Background(), f.org); err != nil {
		t.Fatal(err)
	}
	locker := holdSummaryReviews(t, f)
	defer locker.Rollback(context.Background())
	requests := make([]*summaryHTTPResult, 0, len(people))
	for _, person := range people {
		requests = append(requests, startSummaryHTTPRequest(t, person, "", nil))
	}
	awaitSummaryTestRefs(t, &f.a.discoverySummaries, f.org, 11)
	preparation.close()
	awaitSummaryFlight(t, f)
	if refs, _, entry := summaryTestRefs(&f.a.discoverySummaries, f.org); refs != 10 || entry == nil || len(entry.permit) != 1 {
		t.Fatal("cache stampede did not retain one foreground owner", refs)
	}
	progress, cancel := context.WithTimeout(context.Background(), time.Second)
	response := report(progress, 101)
	cancel()
	requireHTTP(t, response, 200)
	for _, request := range requests {
		select {
		case <-request.done:
			t.Fatal("summary completed before its table lock was released")
		default:
		}
	}
	verify, err := tenantTx(context.Background(), f.a.db, f.org)
	if err != nil {
		t.Fatal(err)
	}
	var durable bool
	queryErr := verify.QueryRow(context.Background(), `SELECT sequence=101 AND finalized FROM discovery_scans WHERE organization_id=$1 AND device_id=$2 AND scope='endpoint'`, f.org, device).Scan(&durable)
	rollbackErr := verify.Rollback(context.Background())
	if queryErr != nil || rollbackErr != nil || !durable {
		t.Fatal("ingestion did not commit while summaries waited", queryErr, rollbackErr)
	}
	if err = locker.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, request := range requests {
		awaitSummaryHTTP(t, request, 200)
	}
	verifyDiscoveryLoadReaderAdmission(t, f, people)
	if _, entries, _ := summaryTestRefs(&f.a.discoverySummaries, f.org); entries != 0 || f.a.db.Stat().AcquiredConns() != 0 {
		t.Fatal("completed stampede retained resources")
	}
}

func summaryIndependentAdmin(t *testing.T, f *observabilityFixture) *pgxpool.Pool {
	t.Helper()
	configuration := f.admin.Config()
	configuration.MaxConns = 1
	admin, err := pgxpool.NewWithConfig(context.Background(), configuration)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	if _, err = admin.Exec(context.Background(), `SELECT set_config('milvago.organization_id',$1,false)`, f.org); err != nil {
		t.Fatal(err)
	}
	return admin
}

func TestDiscoverySummaryAdmissionRevalidatesQueuedBrowserSessions(t *testing.T) {
	for _, mode := range []string{"deleted", "expired", "identity_expired", "trusted_signin_expired", "mfa_changed"} {
		t.Run(mode, func(t *testing.T) {
			f := newObservabilityFixture(t)
			victim := discoveryLoadReaders(t, f, 1)[0]
			admin := summaryIndependentAdmin(t, f)
			if mode == "trusted_signin_expired" || mode == "mfa_changed" {
				if _, err := admin.Exec(context.Background(), `UPDATE settings SET require_mfa=true WHERE organization_id=$1`, f.org); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "trusted_signin_expired" {
				if _, err := admin.Exec(context.Background(), `UPDATE sessions SET mfa=false,login_trusted_until=now()+interval '1 hour' WHERE token_hash=$1`, hash(victim.owner.Value)); err != nil {
					t.Fatal(err)
				}
			}
			preparation := summaryTestAdmission(&f.a.discoverySummaries)
			defer preparation.close()
			if err := preparation.acquire(context.Background(), f.org); err != nil {
				t.Fatal(err)
			}
			locker := holdSummaryReviews(t, f)
			defer locker.Rollback(context.Background())
			owner := startSummaryHTTPRequest(t, f, "", nil)
			awaitSummaryTestRefs(t, &f.a.discoverySummaries, f.org, 2)
			preparation.close()
			awaitSummaryFlight(t, f)
			writer := &discoveryDeniedBlockingWriter{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), proceed: make(chan struct{})}
			var once sync.Once
			release := func() { once.Do(func() { close(writer.proceed) }) }
			t.Cleanup(release)
			queued := startSummaryHTTPRequest(t, victim, "", writer)
			// Ensure writer release runs before the HTTP worker cleanup on failure.
			t.Cleanup(release)
			awaitSummaryTestRefs(t, &f.a.discoverySummaries, f.org, 2)
			sql := `DELETE FROM sessions WHERE token_hash=$1`
			switch mode {
			case "expired":
				sql = `UPDATE sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE token_hash=$1`
			case "identity_expired":
				sql = `UPDATE sessions SET identity_expires_at=clock_timestamp()-interval '1 second' WHERE token_hash=$1`
			case "trusted_signin_expired":
				sql = `UPDATE sessions SET login_trusted_until=clock_timestamp()-interval '1 second' WHERE token_hash=$1`
			case "mfa_changed":
				sql = `UPDATE sessions SET mfa=false,login_trusted_until=NULL WHERE token_hash=$1`
			}
			if tag, err := admin.Exec(context.Background(), sql, hash(victim.owner.Value)); err != nil || tag.RowsAffected() != 1 {
				t.Fatal("queued session mutation did not commit", err)
			}
			if err := locker.Commit(context.Background()); err != nil {
				t.Fatal(err)
			}
			awaitSummaryHTTP(t, owner, 200)
			select {
			case <-writer.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("queued credential refusal did not reach response I/O")
			}
			if _, entries, _ := summaryTestRefs(&f.a.discoverySummaries, f.org); entries != 0 || f.a.db.Stat().AcquiredConns() != 0 {
				t.Fatal("credential refusal held resources during I/O")
			}
			release()
			want := 401
			if mode == "trusted_signin_expired" || mode == "mfa_changed" {
				want = 403
			}
			awaitSummaryHTTP(t, queued, want)
			var charged int
			if err := admin.QueryRow(context.Background(), `SELECT coalesce(sum(hits),0)::integer FROM rate_counters WHERE family=1 AND key_hash=$1`, hash("person "+victim.user)).Scan(&charged); err != nil || charged != 1 {
				t.Fatal("queued session changed durable quota", charged, err)
			}
		})
	}
}

func TestDiscoverySummaryAdmissionRevalidatesQueuedAPIKeys(t *testing.T) {
	for _, mode := range []string{"revoked", "cancelled_after_touch"} {
		t.Run(mode, func(t *testing.T) {
			f := newObservabilityFixture(t)
			admin := summaryIndependentAdmin(t, f)
			secret := apiKeyPrefix + randomToken()
			var keyID string
			if err := admin.QueryRow(context.Background(), `INSERT INTO api_keys(organization_id,user_id,name,secret_hash,permissions,expires_at) VALUES($1,$2,'Synthetic queued summary key',$3,ARRAY[$4]::text[],now()+interval '1 day') RETURNING id`, f.org, f.user, hash(secret), permDiscoveryRead).Scan(&keyID); err != nil {
				t.Fatal(err)
			}
			preparation := summaryTestAdmission(&f.a.discoverySummaries)
			defer preparation.close()
			if err := preparation.acquire(context.Background(), f.org); err != nil {
				t.Fatal(err)
			}
			queued := startSummaryHTTPRequest(t, f, secret, nil)
			awaitSummaryTestRefs(t, &f.a.discoverySummaries, f.org, 2)
			var touched bool
			if err := admin.QueryRow(context.Background(), `SELECT last_used_at IS NOT NULL FROM api_keys WHERE organization_id=$1 AND id=$2`, f.org, keyID).Scan(&touched); err != nil || !touched {
				t.Fatal("admission happened before the short key usage transaction", touched, err)
			}
			if mode == "revoked" {
				if _, err := admin.Exec(context.Background(), `UPDATE api_keys SET revoked_at=now() WHERE organization_id=$1 AND id=$2`, f.org, keyID); err != nil {
					t.Fatal(err)
				}
				preparation.close()
				awaitSummaryHTTP(t, queued, 401)
			} else {
				queued.cancel()
				select {
				case <-queued.done:
				case <-time.After(5 * time.Second):
					t.Fatal("cancelled key waiter did not stop")
				}
				if queued.response.Code == 200 {
					t.Fatal("cancelled waiter returned a summary")
				}
				awaitSummaryTestRefs(t, &f.a.discoverySummaries, f.org, 1)
				preparation.close()
			}
			var charged int
			if err := admin.QueryRow(context.Background(), `SELECT coalesce(sum(hits),0)::integer FROM rate_counters WHERE family=1 AND key_hash=$1`, hash("apikey "+keyID)).Scan(&charged); err != nil || charged != 1 {
				t.Fatal("key admission duplicated or refunded quota", charged, err)
			}
			if _, entries, _ := summaryTestRefs(&f.a.discoverySummaries, f.org); entries != 0 || f.a.db.Stat().AcquiredConns() != 0 {
				t.Fatal("key refusal retained summary ownership")
			}
		})
	}
}

func summaryChildFixture(t *testing.T, root *observabilityFixture) *observabilityFixture {
	t.Helper()
	ctx := context.Background()
	child := &observabilityFixture{a: root.a, admin: root.admin, user: root.user, csrf: randomToken()}
	var permissions []string
	if err := root.admin.QueryRow(ctx, `SELECT permissions FROM roles WHERE organization_id=$1 AND name='owner'`, root.org).Scan(&permissions); err != nil {
		t.Fatal(err)
	}
	if err := root.admin.QueryRow(ctx, `INSERT INTO organizations(name,parent_id) VALUES('Synthetic summary child',$1) RETURNING id`, root.org).Scan(&child.org); err != nil {
		t.Fatal(err)
	}
	tx, err := tenantTx(ctx, root.admin, child.org)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for _, sql := range []string{`INSERT INTO settings(organization_id) VALUES($1)`, `INSERT INTO policies(organization_id) VALUES($1)`, `INSERT INTO privacy_settings(organization_id) VALUES($1)`} {
		if _, err = tx.Exec(ctx, sql, child.org); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO roles(organization_id,name,permissions,builtin) VALUES($1,'owner',$2,true)`, child.org, permissions); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, child.org, child.user); err != nil {
		t.Fatal(err)
	}
	token := randomToken()
	child.owner = &http.Cookie{Name: cookieName("session"), Value: token}
	if _, err = tx.Exec(ctx, `INSERT INTO sessions(token_hash,user_id,organization_id,csrf_token,encrypted_tokens,mfa,expires_at,identity_expires_at) VALUES($1,$2,$3,$4,$5,true,$6,$6)`, hash(token), child.user, child.org, child.csrf, []byte("synthetic-session"), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return child
}

func TestDiscoverySummaryAdmissionChildBarrierDoesNotBlockRoot(t *testing.T) {
	f := newObservabilityFixture(t)
	child := summaryChildFixture(t, f)
	ctx := context.Background()
	locker, err := tenantTx(ctx, f.admin, child.org)
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Rollback(ctx)
	if err = sharedBarrier(ctx, locker, child.org, false); err != nil {
		t.Fatal(err)
	}
	if _, err = locker.Exec(ctx, `SELECT pg_advisory_xact_lock(`+barrierKeySQL+`)`, child.org); err != nil {
		t.Fatal(err)
	}
	blocked := startSummaryHTTPRequest(t, child, "", nil)
	awaitSummaryTestRefs(t, &f.a.discoverySummaries, child.org, 1)
	independent := startSummaryHTTPRequest(t, f, "", nil)
	awaitSummaryHTTP(t, independent, 200)
	select {
	case <-blocked.done:
		t.Fatal("child request escaped its still-held privacy barrier")
	default:
	}
	if err = locker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	awaitSummaryHTTP(t, blocked, 200)
	if _, entries, _ := summaryTestRefs(&f.a.discoverySummaries, f.org); entries != 0 {
		t.Fatal("tenant isolation test retained permits")
	}
}
