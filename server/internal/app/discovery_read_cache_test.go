package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDiscoveryReadCacheCoalescesAndSeparatesOrganizationsAndQueries(t *testing.T) {
	var cache discoveryReadCache
	key := discoveryReadKey{"organization/1", "ollama", "", 50, false}
	var calls atomic.Int32
	var workers sync.WaitGroup
	for n := 0; n < 32; n++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			value, err := cache.load(context.Background(), key, func() (json.RawMessage, error) { calls.Add(1); return json.RawMessage(`{"items":[]}`), nil })
			if err != nil || string(value) != `{"items":[]}` {
				t.Error("coalesced response was lost", err)
			}
		}()
	}
	workers.Wait()
	if calls.Load() != 1 {
		t.Fatal("duplicate computation", calls.Load())
	}
	for _, other := range []discoveryReadKey{{"organization/1", "ollama", "", 50, true}, {"organization/2", "ollama", "", 50, false}, {"organization/1", "hermes", "", 50, false}, {"organization/1", "ollama", "next", 50, false}, {"organization/1", "ollama", "", 100, false}} {
		if _, err := cache.load(context.Background(), other, func() (json.RawMessage, error) { calls.Add(1); return json.RawMessage(`{}`), nil }); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 6 {
		t.Fatal("tenant, inventory permission, query, cursor or page size shared a cache key")
	}
	cache.Lock()
	cache.entries[key].expires = time.Now().Add(-time.Second)
	cache.Unlock()
	cache.load(context.Background(), key, func() (json.RawMessage, error) { calls.Add(1); return json.RawMessage(`{}`), nil })
	if calls.Load() != 7 {
		t.Fatal("expired aggregate was reused")
	}
	cache.invalidate(key.organization)
	cache.Lock()
	defer cache.Unlock()
	if len(cache.entries) != 1 {
		t.Fatal("invalidation crossed organizations or retained stale pages")
	}
}

func TestDiscoveryReadCacheCancellationFailuresAndStorageAreBounded(t *testing.T) {
	var cache discoveryReadCache
	key := discoveryReadKey{"organization/1", "", "", 50, false}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cache.load(ctx, key, func() (json.RawMessage, error) { t.Fatal("cancelled computation started"); return nil, nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for n := 0; n < 64; n++ {
		current := key
		current.query = fmt.Sprint(n)
		if _, err := cache.load(context.Background(), current, func() (json.RawMessage, error) { return json.RawMessage(`{}`), nil }); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := cache.load(context.Background(), key, func() (json.RawMessage, error) { t.Fatal("capacity exceeded"); return nil, nil }); err == nil {
		t.Fatal("cache admitted an unbounded key")
	}
	cache.invalidate(key.organization)
	if _, err := cache.load(context.Background(), key, func() (json.RawMessage, error) { return make(json.RawMessage, 128*1024+1), nil }); err == nil {
		t.Fatal("oversized page retained")
	}
	if len(cache.entries) != 0 {
		t.Fatal("failed computation retained a slot")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("loader panic was swallowed")
			}
		}()
		cache.load(context.Background(), key, func() (json.RawMessage, error) { panic("synthetic loader failure") })
	}()
	if len(cache.entries) != 0 {
		t.Fatal("panicked loader retained a slot")
	}
}

func TestDiscoveryReadCacheInvalidationCannotRemoveAReplacementFlight(t *testing.T) {
	var cache discoveryReadCache
	key := discoveryReadKey{"organization/1", "", "", 50, false}
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_, err := cache.load(context.Background(), key, func() (json.RawMessage, error) {
			close(started)
			<-release
			return json.RawMessage(`{"old":true}`), nil
		})
		if err == nil {
			t.Error("in-flight governance change returned stale data")
		}
	}()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cache.load(ctx, key, func() (json.RawMessage, error) { t.Error("cancelled waiter ran"); return nil, nil }); !errors.Is(err, context.Canceled) {
		t.Error(err)
	}
	cache.invalidate(key.organization)
	if _, err := cache.load(context.Background(), key, func() (json.RawMessage, error) { return json.RawMessage(`{"new":true}`), nil }); err != nil {
		t.Fatal(err)
	}
	close(release)
	<-done
	value, err := cache.load(context.Background(), key, func() (json.RawMessage, error) { t.Error("replacement entry was removed"); return nil, nil })
	if err != nil || string(value) != `{"new":true}` {
		t.Fatal("replacement lost", err)
	}
}

func TestDiscoveryReadCacheInvalidatedComputationsStillConsumeTheirBudget(t *testing.T) {
	var cache discoveryReadCache
	key := discoveryReadKey{"organization/1", "", "", 50, false}
	release := make(chan struct{})
	var workers sync.WaitGroup
	for n := 0; n < 64; n++ {
		started := make(chan struct{})
		workers.Add(1)
		go func() {
			defer workers.Done()
			cache.load(context.Background(), key, func() (json.RawMessage, error) { close(started); <-release; return json.RawMessage(`{}`), nil })
		}()
		<-started
		cache.invalidate(key.organization)
	}
	_, err := cache.load(context.Background(), key, func() (json.RawMessage, error) {
		t.Error("invalidation bypassed the computation capacity")
		return nil, nil
	})
	if err == nil {
		t.Error("unbounded detached computations admitted")
	}
	close(release)
	workers.Wait()
	cache.Lock()
	defer cache.Unlock()
	if cache.running != 0 || len(cache.entries) != 0 {
		t.Error("invalidated computations retained storage or permits")
	}
}

func TestDiscoveryReadCacheRefreshKeepsConcurrentReadersFastWithinAClosedGraceWindow(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprint("expired=", expired), func(t *testing.T) {
			var cache discoveryReadCache
			key := discoveryReadKey{"organization/1", "", "", 50, false}
			old := json.RawMessage(`{"items":[{"id":"old"}]}`)
			if _, err := cache.load(context.Background(), key, func() (json.RawMessage, error) { return old, nil }); err != nil {
				t.Fatal(err)
			}
			cache.Lock()
			cache.entries[key].expires = time.Now().Add(-time.Second)
			cache.Unlock()
			started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			finish := func() { once.Do(func() { close(release) }) }
			defer finish()
			go func() {
				defer close(done)
				_, err := cache.load(context.Background(), key, func() (json.RawMessage, error) {
					close(started)
					<-release
					return json.RawMessage(`{"items":[{"id":"new"}]}`), nil
				})
				if err != nil {
					t.Error(err)
				}
			}()
			<-started
			if expired {
				cache.Lock()
				cache.entries[key].previousUntil = time.Now().Add(-time.Second)
				cache.Unlock()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			value, err := cache.load(ctx, key, func() (json.RawMessage, error) { t.Error("duplicate refresh"); return nil, nil })
			if expired {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("expired value escaped its grace window", err)
				}
			} else if err != nil || string(value) != string(old) {
				t.Fatal("concurrent reader waited for the aggregate refresh", err)
			}
			finish()
			<-done
			value, err = cache.load(context.Background(), key, func() (json.RawMessage, error) { t.Error("refresh not retained"); return nil, nil })
			if err != nil || string(value) != `{"items":[{"id":"new"}]}` {
				t.Fatal("new aggregate not returned", err)
			}
		})
	}
}

func TestDiscoveryReadCacheGovernanceInvalidatesPreviousRefreshValues(t *testing.T) {
	var cache discoveryReadCache
	key := discoveryReadKey{"organization/1", "", "", 50, false}
	cache.load(context.Background(), key, func() (json.RawMessage, error) { return json.RawMessage(`{"old":true}`), nil })
	cache.Lock()
	cache.entries[key].expires = time.Now().Add(-time.Second)
	cache.Unlock()
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		_, err := cache.load(context.Background(), key, func() (json.RawMessage, error) {
			close(started)
			<-release
			return json.RawMessage(`{"old":true}`), nil
		})
		done <- err
	}()
	<-started
	cache.invalidate(key.organization)
	value, err := cache.load(context.Background(), key, func() (json.RawMessage, error) { return json.RawMessage(`{"new":true}`), nil })
	close(release)
	if previousErr := <-done; previousErr == nil {
		t.Error("invalidated refresh succeeded")
	}
	if err != nil || string(value) != `{"new":true}` {
		t.Fatal("governance change retained an old value", err)
	}
	cache.Lock()
	defer cache.Unlock()
	if cache.running != 0 || cache.entries[key].previous != nil {
		t.Error("completed refresh retained resources")
	}
}
