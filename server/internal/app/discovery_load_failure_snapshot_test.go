package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	discoveryLoadProfileLimit    = 32 << 10
	discoveryLoadActivityLimit   = 64
	discoveryLoadSnapshotTimeout = 500 * time.Millisecond
)

type discoveryLoadFailureSnapshot struct {
	once       sync.Once
	worker     sync.WaitGroup
	connection *pgxpool.Conn
}

func discoveryLoadDiagnosticHost(host string) bool {
	return host == "database" || host == "localhost" || host == "127.0.0.1"
}

// Match the disposable discovery-fixture command's guard, including the
// effective pgx target so URI query overrides or fallback hosts cannot escape it.
func discoveryLoadDiagnosticConfig(address string) (*pgxpool.Config, bool) {
	parsed, err := url.Parse(address)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.User == nil || parsed.User.Username() != "fixture_admin" || parsed.Path != "/milvago_test" || !discoveryLoadDiagnosticHost(parsed.Hostname()) {
		return nil, false
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil || parsed.Fragment != "" {
		return nil, false
	}
	for key, values := range query {
		if key != "sslmode" || len(values) != 1 || values[0] != "disable" {
			return nil, false
		}
	}
	config, err := pgxpool.ParseConfig(address)
	if err != nil || config.ConnConfig.User != "fixture_admin" || config.ConnConfig.Database != "milvago_test" || config.ConnConfig.Port != 5432 || !discoveryLoadDiagnosticHost(config.ConnConfig.Host) {
		return nil, false
	}
	for _, fallback := range config.ConnConfig.Fallbacks {
		if fallback == nil || fallback.Port != 5432 || !discoveryLoadDiagnosticHost(fallback.Host) {
			return nil, false
		}
	}
	config.MaxConns, config.MinConns, config.MinIdleConns = 1, 0, 0
	config.ConnConfig.ConnectTimeout = discoveryLoadSnapshotTimeout
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	// Do not inherit options/role/search_path from URL/environment runtime GUCs.
	config.ConnConfig.RuntimeParams = map[string]string{
		"default_transaction_read_only": "on",
		"statement_timeout":             "400ms",
		"lock_timeout":                  "100ms",
		"search_path":                   "pg_catalog",
		"application_name":              "milvago-discovery-failure-snapshot",
	}
	return config, true
}

func newDiscoveryLoadFailureSnapshot(t *testing.T) *discoveryLoadFailureSnapshot {
	t.Helper()
	snapshot := &discoveryLoadFailureSnapshot{}
	t.Cleanup(snapshot.wait)
	address := os.Getenv("DISCOVERY_FIXTURE_ADMIN_URL")
	if address == "" {
		t.Log("failure snapshot: database diagnostic not configured")
		return snapshot
	}
	config, allowed := discoveryLoadDiagnosticConfig(address)
	if !allowed {
		t.Log("failure snapshot: database diagnostic target rejected")
		return snapshot
	}
	ctx, cancel := context.WithTimeout(context.Background(), discoveryLoadSnapshotTimeout)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Log("failure snapshot: database diagnostic unavailable")
		return snapshot
	}
	connection, err := pool.Acquire(ctx)
	if err != nil {
		pool.Close()
		t.Log("failure snapshot: database diagnostic unavailable")
		return snapshot
	}
	snapshot.connection = connection
	// Cleanup is LIFO: stop/join capture before releasing its dedicated connection.
	t.Cleanup(func() { connection.Release(); pool.Close() })
	t.Cleanup(snapshot.wait)
	return snapshot
}

// The first slow response or first abort winner starts at most one owned worker.
// It runs after workload unlock and never changes abort/SLO/capacity decisions.
func (snapshot *discoveryLoadFailureSnapshot) trigger(t *testing.T, cause string) {
	snapshot.once.Do(func() {
		snapshot.worker.Add(1)
		go func() {
			defer snapshot.worker.Done()
			snapshot.capture(t, cause)
		}()
	})
}

func (snapshot *discoveryLoadFailureSnapshot) wait() {
	// Also closes admission on early cleanup. Once synchronizes a racing Add
	// before Wait, and subsequent producers cannot launch a late diagnostic.
	snapshot.once.Do(func() {})
	snapshot.worker.Wait()
}

type discoveryLoadProfileWriter struct {
	buffer    bytes.Buffer
	truncated bool
}

func (writer *discoveryLoadProfileWriter) Len() int       { return writer.buffer.Len() }
func (writer *discoveryLoadProfileWriter) String() string { return writer.buffer.String() }

func (writer *discoveryLoadProfileWriter) Write(raw []byte) (int, error) {
	remaining := discoveryLoadProfileLimit - writer.Len()
	if len(raw) > remaining {
		writer.truncated = true
		n, _ := writer.buffer.Write(raw[:remaining])
		return n, io.ErrShortWrite
	}
	return writer.buffer.Write(raw)
}

// Debug1 has counts and symbols without argument values. Drop labels, addresses
// and file paths too: only numeric group sizes and static function symbols leave.
func discoveryLoadStaticGoroutines(raw string) string {
	var output strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		text := ""
		if len(fields) == 4 && fields[0] == "goroutine" && fields[1] == "profile:" && fields[2] == "total" {
			if count, err := strconv.Atoi(fields[3]); err == nil && count >= 0 {
				text = fmt.Sprintf("total=%d\n", count)
			}
		} else if len(fields) >= 3 && fields[1] == "@" {
			if count, err := strconv.Atoi(fields[0]); err == nil && count >= 0 {
				text = fmt.Sprintf("group=%d\n", count)
			}
		} else if len(fields) >= 3 && fields[0] == "#" && strings.HasPrefix(fields[1], "0x") {
			symbol, _, _ := strings.Cut(fields[2], "+0x")
			valid := len(symbol) > 0 && len(symbol) <= 200
			for _, char := range symbol {
				if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || strings.ContainsRune("/._*()[]{}-,", char)) {
					valid = false
				}
			}
			if valid {
				text = symbol + "\n"
			}
		}
		if output.Len()+len(text) > discoveryLoadProfileLimit {
			break
		}
		output.WriteString(text)
	}
	return output.String()
}

func (snapshot *discoveryLoadFailureSnapshot) capture(t *testing.T, cause string) {
	started := time.Now()
	switch cause {
	case "admission", "http_failure", "slow_response":
	default:
		cause = "other"
	}
	var profile discoveryLoadProfileWriter
	// A truncation error is expected and deliberately does not fail the workload.
	_ = pprof.Lookup("goroutine").WriteTo(&profile, 1)
	t.Logf("first-event diagnostic cause=%s goroutines truncated=%t static profile:\n%s", cause, profile.truncated, discoveryLoadStaticGoroutines(profile.String()))
	if snapshot.connection == nil {
		t.Log("first-event database snapshot unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), discoveryLoadSnapshotTimeout)
	defer cancel()
	rows, err := snapshot.connection.Query(ctx, `SELECT pid,
 substring(pg_catalog.convert_to(COALESCE(query,''),'UTF8'),1,8192),
 left(COALESCE(state,''),80),left(COALESCE(wait_event_type,''),80),left(COALESCE(wait_event,''),80),
 ARRAY(SELECT blocker FROM pg_catalog.unnest(pg_catalog.pg_blocking_pids(pid)) blocker LIMIT 64)
 FROM pg_catalog.pg_stat_activity
 WHERE datname=pg_catalog.current_database() AND usename='milvago_runtime'
 ORDER BY pid LIMIT 64`)
	if err != nil {
		t.Log("first-event database snapshot unavailable")
		return
	}
	defer rows.Close()
	activity := make([]discoveryLoadActivity, 0, discoveryLoadActivityLimit)
	for rows.Next() {
		if len(activity) == discoveryLoadActivityLimit {
			break
		}
		var item discoveryLoadActivity
		var query []byte
		if err = rows.Scan(&item.pid, &query, &item.state, &item.waitType, &item.waitEvent, &item.blockers); err != nil {
			t.Log("first-event database snapshot unavailable")
			return
		}
		item.stage = discoveryLoadQueryClass(string(query))
		clear(query)
		item.state = discoveryLoadActivityState(item.state)
		item.waitType = discoveryLoadWaitType(item.waitType)
		item.waitEvent = discoveryLoadWaitEvent(item.waitEvent)
		activity = append(activity, item)
	}
	if rows.Err() != nil || ctx.Err() != nil {
		t.Log("first-event database snapshot unavailable")
		return
	}
	rows.Close()
	t.Logf("first-event database snapshot rows=%d at_limit=%t capture_elapsed=%s", len(activity), len(activity) == discoveryLoadActivityLimit, time.Since(started))
	for _, line := range discoveryLoadActivitySummary(activity) {
		t.Log(line)
	}
}

type discoveryLoadActivity struct {
	pid                               int32
	stage, state, waitType, waitEvent string
	blockers                          []int32
}

func discoveryLoadActivityState(value string) string {
	switch value {
	case "active", "idle", "disabled":
		return value
	case "idle in transaction":
		return "idle_in_transaction"
	case "idle in transaction (aborted)":
		return "idle_in_transaction_aborted"
	case "fastpath function call":
		return "fastpath"
	default:
		return "other"
	}
}

func discoveryLoadWaitType(value string) string {
	switch value {
	case "Activity", "BufferPin", "Client", "Extension", "IO", "IPC", "Lock", "LWLock", "Timeout":
		return value
	case "":
		return "none"
	default:
		return "other"
	}
}

func discoveryLoadWaitEvent(value string) string {
	switch value {
	case "relation", "extend", "frozenid", "page", "tuple", "transactionid", "virtualxid", "object", "userlock", "advisory", "spectoken", "applytransaction",
		"ClientRead", "ClientWrite", "DataFileRead", "DataFileWrite", "DataFileExtend", "DataFileSync", "WALWrite", "WALSync", "BufFileRead", "BufFileWrite",
		"BufferContent", "BufferMapping", "LockFastPath", "LockManager", "WALInsert", "XactSLRU", "ProcArray", "ProcArrayGroupUpdate", "XactGroupUpdate", "SyncRep", "MessageQueueReceive", "MessageQueueSend", "ParallelFinish", "PgSleep":
		return value
	case "":
		return "none"
	default:
		return "other"
	}
}

func discoveryLoadActivitySummary(activity []discoveryLoadActivity) []string {
	stages := make(map[int32]string, len(activity))
	counts, blockers := map[string]int{}, map[string]int{}
	for _, item := range activity {
		stages[item.pid] = item.stage
		counts[fmt.Sprintf("query_class=%s state=%s wait_type=%s wait_event=%s", item.stage, item.state, item.waitType, item.waitEvent)]++
	}
	for _, item := range activity {
		for _, pid := range item.blockers {
			stage, found := stages[pid]
			if !found {
				stage = "outside_sample"
			}
			blockers[fmt.Sprintf("blocked_class=%s blocker_class=%s", item.stage, stage)]++
		}
	}
	output := []string{}
	for _, group := range []struct {
		name   string
		counts map[string]int
	}{{"activity", counts}, {"blocker", blockers}} {
		keys := make([]string, 0, len(group.counts))
		for key := range group.counts {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys[:min(len(keys), discoveryLoadActivityLimit)] {
			output = append(output, fmt.Sprintf("database %s %s count=%d", group.name, key, group.counts[key]))
		}
		if len(keys) > discoveryLoadActivityLimit {
			output = append(output, "database "+group.name+" additional_groups_omitted")
		}
	}
	return output
}

func TestDiscoveryLoadDiagnosticTargetGuard(t *testing.T) {
	for _, address := range []string{
		"", "postgres://fixture_admin:synthetic@outside.example/milvago_test",
		"postgres://fixture_admin:synthetic@database/production", "postgres://milvago_runtime:synthetic@database/milvago_test",
		"postgres://fixture_admin:synthetic@database/milvago_test?host=outside.example",
		"postgres://fixture_admin:synthetic@database/milvago_test?host=database,outside.example",
		"postgres://fixture_admin:synthetic@database/milvago_test?user=postgres",
		"postgres://fixture_admin:synthetic@database:5433/milvago_test",
		"postgres://fixture_admin:synthetic@database/milvago_test?port=5433",
		"postgres://fixture_admin:synthetic@database/milvago_test?dbname=production",
		"postgres://fixture_admin:synthetic@database/milvago_test?options=-c%20default_transaction_read_only%3Doff",
		"postgres://fixture_admin:synthetic@database/milvago_test?sslmode=disable&sslmode=require",
	} {
		if _, allowed := discoveryLoadDiagnosticConfig(address); allowed {
			t.Fatal("non-fixture diagnostic target accepted")
		}
	}
	for _, host := range []string{"database", "localhost", "127.0.0.1"} {
		config, allowed := discoveryLoadDiagnosticConfig("postgres://fixture_admin:synthetic@" + host + "/milvago_test?sslmode=disable")
		if !allowed || config.MaxConns != 1 || config.MinConns != 0 || config.MinIdleConns != 0 || config.ConnConfig.ConnectTimeout != discoveryLoadSnapshotTimeout || config.ConnConfig.RuntimeParams["default_transaction_read_only"] != "on" || config.ConnConfig.RuntimeParams["options"] != "" {
			t.Fatal("fixture diagnostic configuration escaped bounds")
		}
	}
}

func TestDiscoveryLoadGoroutineProfileBoundsAndRedaction(t *testing.T) {
	var writer discoveryLoadProfileWriter
	written, err := writer.Write(bytes.Repeat([]byte{'a'}, discoveryLoadProfileLimit+1))
	if written != discoveryLoadProfileLimit || err != io.ErrShortWrite || !writer.truncated || writer.Len() != discoveryLoadProfileLimit {
		t.Fatal("profile writer exceeded bound")
	}
	if n, err := writer.Write([]byte("secret")); n != 0 || err != io.ErrShortWrite || writer.Len() != discoveryLoadProfileLimit {
		t.Fatal("full profile accepted more bytes")
	}
	profile := "goroutine profile: total 3\n2 @ 0x123 0x456\n# labels: {\"identity\":\"synthetic-secret\"}\n#\t0x123\tmilvago/server/internal/app.(*App).deviceTx+0x5\t/private/identity.go:77\n#\t0x456\truntime.gopark+0x4\t/runtime/proc.go:1\ngoroutine 9 [running]:\nfunction(synthetic-secret)\n"
	actual := discoveryLoadStaticGoroutines(profile)
	if actual != "total=3\ngroup=2\nmilvago/server/internal/app.(*App).deviceTx\nruntime.gopark\n" || strings.Contains(actual, "secret") || strings.Contains(actual, "0x") || strings.Contains(actual, ".go:") {
		t.Fatal("goroutine profile lost static frames or retained dynamic data")
	}
	if len(discoveryLoadStaticGoroutines(strings.Repeat(profile, 1000))) > discoveryLoadProfileLimit {
		t.Fatal("filtered profile output exceeded bound")
	}
}

func TestDiscoveryLoadActivitySummaryAggregatesWithoutPIDs(t *testing.T) {
	activity := []discoveryLoadActivity{
		{pid: 123451, stage: "rate", state: "active", waitType: "Lock", waitEvent: "transactionid", blockers: []int32{123452, 123499}},
		{pid: 123452, stage: "live_device", state: "idle_in_transaction", waitType: "Client", waitEvent: "ClientRead"},
		{pid: 123453, stage: "rate", state: "active", waitType: "Lock", waitEvent: "transactionid"},
	}
	actual := strings.Join(discoveryLoadActivitySummary(activity), "\n")
	for _, expected := range []string{"query_class=rate state=active wait_type=Lock wait_event=transactionid count=2", "blocked_class=rate blocker_class=live_device count=1", "blocked_class=rate blocker_class=outside_sample count=1"} {
		if !strings.Contains(actual, expected) {
			t.Fatal("database summary lost bounded aggregate")
		}
	}
	if strings.Contains(actual, "12345") || strings.Contains(actual, "123499") || discoveryLoadActivityState("synthetic-secret") != "other" || discoveryLoadWaitType("synthetic-secret") != "other" || discoveryLoadWaitEvent("synthetic-secret") != "other" {
		t.Fatal("database summary retained identity or dynamic labels")
	}
}
