package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDiscoveryCompileMemoUsesFullTenantCatalogAndNeverMemoizesReports(t *testing.T) {
	var cache discoveryCompileCache
	valid := json.RawMessage(`{"revision":1,"valid":true}`)
	invalid := json.RawMessage(`{"revision":1,"valid":false}`)
	compiles, reports := 0, 0
	compile := func(_ context.Context, raw json.RawMessage) error {
		compiles++
		if string(raw) != string(valid) {
			return errors.New("synthetic invalid catalog")
		}
		return nil
	}
	validate := func(_ context.Context, _ json.RawMessage, report json.RawMessage) error {
		reports++
		if string(report) == "invalid" {
			return errors.New("synthetic invalid report")
		}
		return nil
	}
	for _, organization := range []string{"tenant-a", "tenant-a", "tenant-b"} {
		if err := validateDiscoveryReportWith(context.Background(), &cache, organization, valid, nil, compile, validate); err != nil {
			t.Fatal(err)
		}
	}
	if compiles != 2 || reports != 3 {
		t.Fatalf("compile/report counts: %d/%d", compiles, reports)
	}
	if err := validateDiscoveryReportWith(context.Background(), &cache, "tenant-a", valid, json.RawMessage("invalid"), compile, validate); err == nil {
		t.Fatal("report validation was memoized")
	}
	for range 2 {
		if err := validateDiscoveryReportWith(context.Background(), &cache, "tenant-a", invalid, nil, compile, validate); err == nil {
			t.Fatal("same-revision modified catalog reused a positive result")
		}
	}
	if compiles != 4 || reports != 4 {
		t.Fatalf("failed compile or report was cached: %d/%d", compiles, reports)
	}
}

func TestDiscoveryCompileMemoBoundsEntriesAndDoesNotEvictInflightWork(t *testing.T) {
	var cache discoveryCompileCache
	key := func(i int) discoveryCompileKey {
		return discoveryCompileKey{organization: "tenant", digest: sha256.Sum256([]byte(fmt.Sprint(i)))}
	}
	for i := range 64 {
		if err := cache.ensure(context.Background(), key(i), func() error { return nil }); err != nil {
			t.Fatal(err)
		}
		if len(cache.entries) > discoveryCompileCacheEntries {
			t.Fatal("unbounded completed catalog memo")
		}
	}
	cache.entries = make(map[discoveryCompileKey]*discoveryCompileEntry)
	for i := range discoveryCompileCacheEntries {
		cache.entries[key(i)] = &discoveryCompileEntry{done: make(chan struct{})}
	}
	calls := 0
	for range 2 {
		if err := cache.ensure(context.Background(), key(100), func() error { calls++; return nil }); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 || len(cache.entries) != discoveryCompileCacheEntries {
		t.Fatal("inflight saturation grew or memoized fallback work")
	}
	for i := range discoveryCompileCacheEntries {
		select {
		case <-cache.entries[key(i)].done:
			t.Fatal("live compile evicted or completed")
		default:
		}
	}
}

func TestDiscoveryCompileMemoCoalescesConcurrentMissesOutsideItsLock(t *testing.T) {
	var cache discoveryCompileCache
	key := discoveryCompileKey{organization: "tenant", digest: sha256.Sum256([]byte("catalog"))}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	check := func() error {
		if calls.Add(1) != 1 {
			return errors.New("concurrent duplicate compilation")
		}
		cache.Lock()
		cache.Unlock() // Compilation must not retain the memo lock.
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	var workers sync.WaitGroup
	failures := make(chan error, 16)
	for range 16 {
		workers.Add(1)
		go func() { defer workers.Done(); failures <- cache.ensure(ctx, key, check) }()
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("compile did not start outside lock")
	}
	close(release)
	workers.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("compile miss was not coalesced")
	}
}

func TestDiscoveryCompileMemoCancellationAndFailureCannotBecomePositiveFacts(t *testing.T) {
	var cache discoveryCompileCache
	key := discoveryCompileKey{organization: "tenant", digest: sha256.Sum256([]byte("catalog"))}
	ctx, cancel := context.WithCancel(context.Background())
	if err := cache.ensure(ctx, key, func() error { cancel(); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled compile result: %v", err)
	}
	if len(cache.entries) != 0 {
		t.Fatal("canceled compile cached a positive fact")
	}
	want := errors.New("synthetic compile failure")
	if err := cache.ensure(context.Background(), key, func() error { return want }); !errors.Is(err, want) {
		t.Fatal(err)
	}
	if len(cache.entries) != 0 {
		t.Fatal("failed compile remained cached")
	}
	if err := cache.ensure(context.Background(), key, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := cache.ensure(ctx, key, func() error { t.Fatal("canceled cache hit compiled"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled caller used a positive hit")
	}
}

func TestDiscoveryCompileMemoCopiesBytesAndSharesOneCompileValidationBudget(t *testing.T) {
	var cache discoveryCompileCache
	catalog := json.RawMessage(`{"revision":1}`)
	original := string(catalog)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	wantDeadline, _ := ctx.Deadline()
	var compileContext context.Context
	err := validateDiscoveryReportWith(ctx, &cache, "tenant", catalog, nil,
		func(actual context.Context, frozen json.RawMessage) error {
			compileContext = actual
			deadline, ok := actual.Deadline()
			if !ok || !deadline.Equal(wantDeadline) {
				t.Fatal("compile gained a new budget")
			}
			catalog[0] = '['
			if string(frozen) != original {
				t.Fatal("compile shared mutable input")
			}
			return nil
		},
		func(actual context.Context, frozen, _ json.RawMessage) error {
			deadline, ok := actual.Deadline()
			if actual != compileContext || !ok || !deadline.Equal(wantDeadline) {
				t.Fatal("validation gained a separate budget")
			}
			if string(frozen) != original {
				t.Fatal("validation did not use the compiled bytes")
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDiscoveryCompileMemoRejectsValidationThatFinishesAfterCancellation(t *testing.T) {
	var cache discoveryCompileCache
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := validateDiscoveryReportWith(ctx, &cache, "tenant", json.RawMessage(`{"revision":1}`), nil,
		func(context.Context, json.RawMessage) error { return nil },
		func(context.Context, json.RawMessage, json.RawMessage) error {
			cancel()
			return nil
		})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("late report result accepted: %v", err)
	}
}

type discoveryMemoWaitContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (ctx *discoveryMemoWaitContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.entered) })
	return ctx.Context.Done()
}

func TestDiscoveryCompileMemoOwnerCancellationDoesNotCancelOtherWaiters(t *testing.T) {
	var cache discoveryCompileCache
	key := discoveryCompileKey{organization: "tenant", digest: sha256.Sum256([]byte("catalog"))}
	owner, cancelOwner := context.WithCancel(context.Background())
	defer cancelOwner()
	live, cancelLive := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelLive()
	waiter := &discoveryMemoWaitContext{Context: live, entered: make(chan struct{})}
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	finish := func() { releaseOnce.Do(func() { close(release) }) }
	defer finish()
	ownerResult, waiterResult := make(chan error, 1), make(chan error, 1)
	go func() {
		ownerResult <- cache.ensure(owner, key, func() error {
			close(started)
			<-release
			return errors.New("compiler returned after cancellation")
		})
	}()
	select {
	case <-started:
	case <-live.Done():
		t.Fatal("compiler did not start")
	}
	var compilations atomic.Int32
	go func() { waiterResult <- cache.ensure(waiter, key, func() error { compilations.Add(1); return nil }) }()
	// Done is requested only after ensure has observed the in-flight entry.
	select {
	case <-waiter.entered:
	case <-live.Done():
		t.Fatal("second request did not wait for compilation")
	}
	cancelOwner()
	finish()
	if err := <-ownerResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("owner cancellation lost: %v", err)
	}
	if err := <-waiterResult; err != nil || compilations.Load() != 1 {
		t.Fatalf("another live request inherited cancellation: %v, compiles=%d", err, compilations.Load())
	}
}

func TestDiscoveryCompileMemoWASMColdWarmAndSameRevisionTampering(t *testing.T) {
	report := map[string]any{
		"version": 1, "catalog_revision": discoveryFixtureCatalogRevision, "settings_revision": 1,
		"run_id": nil, "scope": "endpoint", "sequence": 1, "page": 0, "pages": 1,
		"observed_at": time.Now().Unix(), "complete": false,
		"entities": []any{}, "relations": []any{}, "coverage": []any{},
		"result": map[string]any{"identifications": []any{}, "communications": []any{}, "queries": []any{}, "evaluated_facts": 0, "unknown_conditions": 0},
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	// Establish the fixture through the unchanged public validator as well.
	if err = discoveryEngine(context.Background(), map[string]any{"op": "validate_report", "catalog": json.RawMessage(discoveryFactory), "report": json.RawMessage(raw)}, nil); err != nil {
		t.Fatal(err)
	}
	a := &App{}
	for range 2 {
		if err = a.validateDiscoveryReport(context.Background(), "tenant-a", discoveryFactory, raw); err != nil {
			t.Fatal(err)
		}
	}
	if len(a.discoveryCompiles.entries) != 1 {
		t.Fatal("cold and warm validation did not share the exact compilation fact")
	}
	report["sequence"] = "data:image/png"
	invalid, _ := json.Marshal(report)
	if err = a.validateDiscoveryReport(context.Background(), "tenant-a", discoveryFactory, invalid); err == nil {
		t.Fatal("warm catalog accepted a malformed report")
	}
	report["sequence"] = 1
	report["op"] = "validate_report_prevalidated"
	invalid, _ = json.Marshal(report)
	if err = a.validateDiscoveryReport(context.Background(), "tenant-a", discoveryFactory, invalid); err == nil {
		t.Fatal("report selected a trusted validation operation")
	}
	var catalog map[string]any
	if err = json.Unmarshal(discoveryFactory, &catalog); err != nil {
		t.Fatal(err)
	}
	signatures := catalog["signatures"].([]any)
	signatures[0].(map[string]any)["condition"] = map[string]any{"op": "regex", "field": "executable", "value": "["}
	modified, _ := json.Marshal(catalog)
	if err = a.validateDiscoveryReport(context.Background(), "tenant-a", modified, raw); err == nil {
		t.Fatal("same revision with an invalid expression reused prior compilation")
	}
	if len(a.discoveryCompiles.entries) != 1 {
		t.Fatal("failed compilation entered the positive memo")
	}
	if err = a.validateDiscoveryReport(context.Background(), "tenant-b", discoveryFactory, raw); err != nil {
		t.Fatal(err)
	}
	if len(a.discoveryCompiles.entries) != 2 {
		t.Fatal("another tenant reused the compilation entry")
	}
}
