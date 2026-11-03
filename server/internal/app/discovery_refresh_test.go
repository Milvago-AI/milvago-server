package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func expireDiscoveryRead(t *testing.T, cache *discoveryReadCache, key discoveryReadKey, ago time.Duration) {
	t.Helper()
	cache.Lock()
	defer cache.Unlock()
	cache.entries[key].expires = time.Now().Add(-ago)
}

func awaitDiscoveryRefresh(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("bounded refresh did not finish")
	}
}

func TestDiscoveryRefreshFirstReaderReturnsPreviousWithoutRetainingRequestContext(t *testing.T) {
	var cache discoveryReadCache
	t.Cleanup(cache.close)
	key := discoveryReadKey{"organization/1", "", "", 50, false}
	cache.load(context.Background(), key, func() (json.RawMessage, error) { return json.RawMessage(`{"old":true}`), nil })
	expireDiscoveryRead(t, &cache, key, time.Second)
	started, release := make(chan context.Context, 1), make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	t.Cleanup(finish)
	requestContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	type requestValue struct{}
	requestContext = context.WithValue(requestContext, requestValue{}, "synthetic request value")
	value, err := cache.loadRefreshing(requestContext, key, func() (json.RawMessage, error) {
		t.Error("first refresh reader used its foreground transaction")
		return nil, errors.New("foreground refresh")
	}, func(ctx context.Context) (json.RawMessage, error) {
		started <- ctx
		<-release
		return json.RawMessage(`{"new":true}`), nil
	})
	if err != nil || string(value) != `{"old":true}` {
		t.Fatal(value, err)
	}
	var refreshContext context.Context
	select {
	case refreshContext = <-started:
	case <-time.After(time.Second):
		t.Fatal("refresh not started")
	}
	cancel()
	if refreshContext.Err() != nil {
		t.Fatal("request cancellation escaped into independent refresh")
	}
	if refreshContext.Value(requestValue{}) != nil {
		t.Fatal("background refresh retained request context values")
	}
	deadline, ok := refreshContext.Deadline()
	if !ok || time.Until(deadline) > 2*time.Second {
		t.Fatal("refresh has no bounded deadline")
	}
	cache.Lock()
	flight := cache.entries[key]
	cache.Unlock()
	finish()
	awaitDiscoveryRefresh(t, flight.done)
	value, err = cache.load(context.Background(), key, func() (json.RawMessage, error) { t.Error("refresh was lost"); return nil, nil })
	if err != nil || string(value) != `{"new":true}` {
		t.Fatal(value, err)
	}
}

func TestDiscoveryRefreshConcurrencyAndGraceCannotBeExtendedByRepeatedReaders(t *testing.T) {
	var cache discoveryReadCache
	t.Cleanup(cache.close)
	keys := make([]discoveryReadKey, 8)
	for n := range keys {
		keys[n] = discoveryReadKey{"organization/1", fmt.Sprint(n), "", 50, false}
		cache.load(context.Background(), keys[n], func() (json.RawMessage, error) { return json.RawMessage(`{}`), nil })
		expireDiscoveryRead(t, &cache, keys[n], time.Second)
	}
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	refresh := func(context.Context) (json.RawMessage, error) { <-release; return json.RawMessage(`{}`), nil }
	for n := 0; n < 32; n++ {
		_, err := cache.loadRefreshing(context.Background(), keys[n%len(keys)], func() (json.RawMessage, error) { t.Error("unexpected foreground refresh"); return nil, nil }, refresh)
		if err != nil {
			t.Fatal(err)
		}
	}
	cache.Lock()
	if cache.refreshing != 4 || cache.running != 4 {
		t.Error("background concurrency escaped its limit")
	}
	cache.Unlock()
	// A slot-denied page remains expired; serving it does not renew its grace.
	expireDiscoveryRead(t, &cache, keys[7], 3*time.Second)
	foreground := false
	_, err := cache.loadRefreshing(context.Background(), keys[7], func() (json.RawMessage, error) { foreground = true; return json.RawMessage(`{"current":true}`), nil }, refresh)
	if err != nil || !foreground {
		t.Fatal("expired aggregate escaped its closed grace window", err)
	}
	once.Do(func() { close(release) })
	cache.close()
	if cache.refreshing != 0 || cache.running != 0 {
		t.Fatal("refresh permits were retained")
	}
}

func TestDiscoveryRefreshInvalidationRejectsInFlightResultAndPreservesReplacement(t *testing.T) {
	var cache discoveryReadCache
	t.Cleanup(cache.close)
	key := discoveryReadKey{"organization/1", "", "", 50, false}
	cache.load(context.Background(), key, func() (json.RawMessage, error) { return json.RawMessage(`{"old":true}`), nil })
	expireDiscoveryRead(t, &cache, key, time.Second)
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	cache.loadRefreshing(context.Background(), key, func() (json.RawMessage, error) { t.Error("foreground refresh"); return nil, nil }, func(context.Context) (json.RawMessage, error) {
		<-release
		return json.RawMessage(`{"obsolete":true}`), nil
	})
	cache.Lock()
	flight := cache.entries[key]
	cache.Unlock()
	cache.invalidate(key.organization)
	value, err := cache.load(context.Background(), key, func() (json.RawMessage, error) { return json.RawMessage(`{"replacement":true}`), nil })
	if err != nil {
		t.Fatal(err)
	}
	once.Do(func() { close(release) })
	awaitDiscoveryRefresh(t, flight.done)
	if flight.err == nil || flight.value != nil {
		t.Fatal("invalidated background result was retained")
	}
	current, err := cache.load(context.Background(), key, func() (json.RawMessage, error) { t.Error("replacement removed"); return nil, nil })
	if err != nil || string(current) != string(value) {
		t.Fatal(current, err)
	}
}

func TestDiscoveryRefreshFailurePanicAndOversizeReleasePermits(t *testing.T) {
	for _, mode := range []string{"error", "panic", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			var cache discoveryReadCache
			t.Cleanup(cache.close)
			key := discoveryReadKey{"organization/1", "", "", 50, false}
			cache.load(context.Background(), key, func() (json.RawMessage, error) { return json.RawMessage(`{}`), nil })
			expireDiscoveryRead(t, &cache, key, time.Second)
			release := make(chan struct{})
			cache.loadRefreshing(context.Background(), key, func() (json.RawMessage, error) { t.Error("foreground refresh"); return nil, nil }, func(context.Context) (json.RawMessage, error) {
				<-release
				switch mode {
				case "panic":
					panic("synthetic failure")
				case "oversize":
					return make(json.RawMessage, 128*1024+1), nil
				}
				return nil, errors.New("synthetic failure")
			})
			cache.Lock()
			flight := cache.entries[key]
			cache.Unlock()
			close(release)
			awaitDiscoveryRefresh(t, flight.done)
			cache.close()
			if cache.running != 0 || cache.refreshing != 0 || len(cache.entries) != 0 {
				t.Fatal("failed refresh retained resources")
			}
		})
	}
}

func TestDiscoveryRefreshShutdownCancelsAndJoinsWorkers(t *testing.T) {
	var cache discoveryReadCache
	t.Cleanup(cache.close)
	key := discoveryReadKey{"organization/1", "", "", 50, false}
	cache.load(context.Background(), key, func() (json.RawMessage, error) { return json.RawMessage(`{}`), nil })
	expireDiscoveryRead(t, &cache, key, time.Second)
	started := make(chan struct{})
	cache.loadRefreshing(context.Background(), key, func() (json.RawMessage, error) { t.Error("foreground refresh"); return nil, nil }, func(ctx context.Context) (json.RawMessage, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	awaitDiscoveryRefresh(t, started)
	cache.close()
	if cache.running != 0 || cache.refreshing != 0 {
		t.Fatal("shutdown left active work")
	}
	_, err := cache.loadRefreshing(context.Background(), key, func() (json.RawMessage, error) { t.Error("work admitted after shutdown"); return nil, nil }, nil)
	if err == nil {
		t.Fatal("closed cache accepted work")
	}
}

func TestDiscoveryRefreshDeadlineCannotBeRenewedByWaiters(t *testing.T) {
	var cache discoveryReadCache
	t.Cleanup(cache.close)
	key := discoveryReadKey{"organization/1", "", "", 50, false}
	cache.load(context.Background(), key, func() (json.RawMessage, error) { return json.RawMessage(`{}`), nil })
	expireDiscoveryRead(t, &cache, key, time.Second)
	cache.loadRefreshing(context.Background(), key, func() (json.RawMessage, error) { t.Error("foreground refresh"); return nil, nil }, func(ctx context.Context) (json.RawMessage, error) { <-ctx.Done(); return nil, ctx.Err() })
	cache.Lock()
	flight := cache.entries[key]
	cache.Unlock()
	awaitDiscoveryRefresh(t, flight.done)
	if !errors.Is(flight.err, context.DeadlineExceeded) {
		t.Fatal("refresh outlived its absolute deadline", flight.err)
	}
	cache.close()
	if cache.running != 0 || cache.refreshing != 0 {
		t.Fatal("expired refresh retained resources")
	}
}
