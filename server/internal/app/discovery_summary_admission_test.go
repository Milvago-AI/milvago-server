package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

func summaryTestOrg(number int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012x", number) }
func summaryTestAdmission(registry *discoverySummaryRegistry) *discoverySummaryAdmission {
	return &discoverySummaryAdmission{registry: registry, done: make(chan struct{})}
}
func summaryTestRefs(registry *discoverySummaryRegistry, organization string) (int, int, *discoverySummaryEntry) {
	var org pgtype.UUID
	_ = org.Scan(organization)
	registry.mu.Lock()
	defer registry.mu.Unlock()
	entry := registry.entries[org.Bytes]
	if entry == nil {
		return 0, len(registry.entries), nil
	}
	return entry.refs, len(registry.entries), entry
}
func awaitSummaryTestRefs(t *testing.T, registry *discoverySummaryRegistry, org string, wanted int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		refs, _, _ := summaryTestRefs(registry, org)
		if refs == wanted {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("summary participants did not reach expected ownership", wanted)
}

func TestDiscoverySummaryAdmissionSeparatesOrganizationsAndRemovesIdleEntries(t *testing.T) {
	var registry discoverySummaryRegistry
	org := summaryTestOrg(10)
	owner := summaryTestAdmission(&registry)
	defer owner.close()
	if err := owner.acquire(context.Background(), org); err != nil {
		t.Fatal(err)
	}
	if err := owner.acquire(context.Background(), strings.ToUpper(org)); err != nil {
		t.Fatal(err)
	}
	_, _, original := summaryTestRefs(&registry, org)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waiter := summaryTestAdmission(&registry)
	defer waiter.close()
	result := make(chan error, 1)
	done := make(chan struct{})
	go func() { defer close(done); result <- waiter.acquire(ctx, org) }()
	t.Cleanup(func() {
		cancel()
		waiter.close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("summary waiter did not stop")
		}
	})
	awaitSummaryTestRefs(t, &registry, org, 2)
	other := summaryTestAdmission(&registry)
	defer other.close()
	independent, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := other.acquire(independent, summaryTestOrg(11)); err != nil {
		t.Fatal("organization A blocked B", err)
	}
	waiter.close()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("closed waiter did not detach")
	}
	awaitSummaryTestRefs(t, &registry, org, 1)
	if err := owner.acquire(context.Background(), summaryTestOrg(12)); err == nil {
		t.Fatal("request changed organizations")
	}
	owner.close()
	owner.close()
	awaitSummaryTestRefs(t, &registry, org, 0)
	replacement := summaryTestAdmission(&registry)
	defer replacement.close()
	if err := replacement.acquire(context.Background(), org); err != nil {
		t.Fatal(err)
	}
	_, _, fresh := summaryTestRefs(&registry, org)
	if fresh == original {
		t.Fatal("idle entry was retained")
	}
	// A stale release must never decrement a replacement entry for this org.
	var parsed pgtype.UUID
	_ = parsed.Scan(org)
	registry.leave(parsed.Bytes, original)
	if refs, _, entry := summaryTestRefs(&registry, org); refs != 1 || entry != fresh {
		t.Fatal("stale release removed a new owner")
	}
	replacement.close()
	other.close()
	if _, entries, _ := summaryTestRefs(&registry, org); entries != 0 {
		t.Fatal("idle entries retained")
	}
	if err := owner.acquire(context.Background(), org); !errors.Is(err, context.Canceled) {
		t.Fatal("closed admission reopened", err)
	}
}

func TestDiscoverySummaryAdmissionBoundsParticipantsAndSupportsHundredReaders(t *testing.T) {
	var registry discoverySummaryRegistry
	org := summaryTestOrg(20)
	owner := summaryTestAdmission(&registry)
	defer owner.close()
	if err := owner.acquire(context.Background(), org); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := make(chan error, discoverySummaryParticipants-1)
	var workers sync.WaitGroup
	for range discoverySummaryParticipants - 1 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			state := summaryTestAdmission(&registry)
			defer state.close()
			results <- state.acquire(ctx, org)
		}()
	}
	finished := make(chan struct{})
	go func() { workers.Wait(); close(finished) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(2 * time.Second):
			t.Error("summary participants did not stop")
		}
	})
	awaitSummaryTestRefs(t, &registry, org, discoverySummaryParticipants)
	excess := summaryTestAdmission(&registry)
	defer excess.close()
	var busy apiError
	if err := excess.acquire(context.Background(), org); !errors.As(err, &busy) || busy.status != 503 || busy.code != "discovery_busy" {
		t.Fatal("participant bound changed", err)
	}
	other := summaryTestAdmission(&registry)
	defer other.close()
	if err := other.acquire(context.Background(), summaryTestOrg(21)); err != nil {
		t.Fatal("A's participant cap affected B", err)
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled readers did not detach")
	}
	close(results)
	for err := range results {
		if !errors.Is(err, context.Canceled) {
			t.Error("unexpected queued result", err)
		}
	}
	awaitSummaryTestRefs(t, &registry, org, 1)
}

func TestDiscoverySummaryAdmissionFullRegistryBypassesOnlyResourceGuard(t *testing.T) {
	var registry discoverySummaryRegistry
	owners := []*discoverySummaryAdmission{}
	defer func() {
		for _, owner := range owners {
			owner.close()
		}
	}()
	for number := range discoverySummaryOrganizations {
		owner := summaryTestAdmission(&registry)
		if err := owner.acquire(context.Background(), summaryTestOrg(number+100)); err != nil {
			t.Fatal(err)
		}
		owners = append(owners, owner)
	}
	bypass := summaryTestAdmission(&registry)
	defer bypass.close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := bypass.acquire(ctx, summaryTestOrg(1000)); err != nil {
		t.Fatal("full metadata blocked another organization", err)
	}
	if !bypass.bypass || bypass.entry != nil {
		t.Fatal("registry-full fallback acquired a foreign permit")
	}
	if _, count, _ := summaryTestRefs(&registry, summaryTestOrg(1000)); count != discoverySummaryOrganizations {
		t.Fatal("registry grew beyond its bound")
	}
	bypass.close()
	owners[0].close()
	if err := bypass.acquire(context.Background(), summaryTestOrg(1000)); !errors.Is(err, context.Canceled) {
		t.Fatal("closed bypass reopened", err)
	}
	fresh := summaryTestAdmission(&registry)
	defer fresh.close()
	if err := fresh.acquire(context.Background(), summaryTestOrg(1000)); err != nil || fresh.bypass {
		t.Fatal("released metadata was not reclaimed", err)
	}
}

func TestDiscoverySummaryAdmissionCancellationDeadlinesAndMalformedOrganization(t *testing.T) {
	var registry discoverySummaryRegistry
	for _, org := range []string{"", "synthetic-not-an-organization"} {
		state := summaryTestAdmission(&registry)
		if err := state.acquire(context.Background(), org); err == nil || strings.Contains(err.Error(), org) && org != "" {
			t.Fatal("malformed organization was accepted or exposed")
		}
		state.close()
	}
	org := summaryTestOrg(30)
	owner := summaryTestAdmission(&registry)
	defer owner.close()
	if err := owner.acquire(context.Background(), org); err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	waiter := summaryTestAdmission(&registry)
	defer waiter.close()
	started := time.Now()
	if err := waiter.acquire(short, org); !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatal("shorter request deadline was extended", err)
	}
	awaitSummaryTestRefs(t, &registry, org, 1)
	bounded := summaryTestAdmission(&registry)
	defer bounded.close()
	started = time.Now()
	var busy apiError
	if err := bounded.acquire(context.Background(), org); !errors.As(err, &busy) || busy.status != 503 || time.Since(started) < discoverySummaryWait || time.Since(started) > discoverySummaryWait+time.Second {
		t.Fatal("five-second wait bound changed", err)
	}
	awaitSummaryTestRefs(t, &registry, org, 1)
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if err := owner.acquire(cancelled, org); !errors.Is(err, context.Canceled) {
		t.Fatal("prior success hid cancellation", err)
	}
}

func TestDiscoverySummaryAdmissionScopeAndPanicCleanup(t *testing.T) {
	for _, scenario := range []struct {
		method, path string
		present      bool
	}{
		{"GET", "/api/discovery/applications", true}, {"HEAD", "/api/discovery/applications", true},
		{"POST", "/api/discovery/applications", false}, {"GET", "/api/discovery/coverage", false},
	} {
		var registry discoverySummaryRegistry
		handler := discoverySummaryAdmissionHandler(&registry, func(_ http.ResponseWriter, r *http.Request) {
			if (summaryAdmissionFor(r.Context()) != nil) != scenario.present {
				t.Error("summary admission escaped its exact read route")
			}
		})
		handler(httptest.NewRecorder(), httptest.NewRequest(scenario.method, scenario.path, nil))
	}
	var registry discoverySummaryRegistry
	panicked := false
	func() {
		defer func() { panicked = recover() != nil }()
		discoverySummaryAdmissionHandler(&registry, func(_ http.ResponseWriter, r *http.Request) {
			if err := acquireDiscoverySummaryAdmission(r.Context(), summaryTestOrg(40)); err != nil {
				panic(err)
			}
			panic("synthetic summary panic")
		})(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/discovery/applications", nil))
	}()
	if _, count, _ := summaryTestRefs(&registry, summaryTestOrg(40)); !panicked || count != 0 {
		t.Fatal("panic retained summary ownership")
	}
}
