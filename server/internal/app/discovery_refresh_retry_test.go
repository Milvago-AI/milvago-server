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

type discoveryWaitingContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *discoveryWaitingContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestDiscoveryRefreshExpiredBudgetDoesNotCancelLiveReaders(t *testing.T) {
	for _, mode := range []string{"recover", "foreground_deadline", "background_error", "background_cancelled", "request_cancelled", "invalidated", "closed"} {
		t.Run(mode, func(t *testing.T) {
			var cache discoveryReadCache
			t.Cleanup(cache.close)
			key := discoveryReadKey{"organization/1", "", "", 50, false}
			cache.load(context.Background(), key, func() (json.RawMessage, error) { return json.RawMessage(`{"old":true}`), nil })
			expireDiscoveryRead(t, &cache, key, time.Second)
			release := make(chan struct{})
			var once sync.Once
			finish := func() { once.Do(func() { close(release) }) }
			t.Cleanup(finish)
			backgroundError := error(fmt.Errorf("independent refresh: %w", context.DeadlineExceeded))
			if mode == "background_error" {
				backgroundError = errors.New("synthetic non-timeout failure")
			} else if mode == "background_cancelled" {
				backgroundError = context.Canceled
			}
			cache.loadRefreshing(context.Background(), key, func() (json.RawMessage, error) { t.Error("unexpected initial foreground read"); return nil, nil }, func(context.Context) (json.RawMessage, error) {
				<-release
				return nil, backgroundError
			})
			cache.Lock()
			flight := cache.entries[key]
			flight.previousUntil = time.Now().Add(-time.Second)
			cache.Unlock()
			request, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := &discoveryWaitingContext{Context: request, waiting: make(chan struct{})}
			var calls atomic.Int32
			done := make(chan struct{})
			var value json.RawMessage
			var err error
			go func() {
				defer close(done)
				value, err = cache.loadRefreshing(ctx, key, func() (json.RawMessage, error) {
					calls.Add(1)
					if mode == "foreground_deadline" {
						return nil, context.DeadlineExceeded
					}
					return json.RawMessage(`{"current":true}`), nil
				}, nil)
			}()
			awaitDiscoveryRefresh(t, ctx.waiting)
			switch mode {
			case "request_cancelled":
				cancel()
			case "invalidated":
				cache.invalidate(key.organization)
			case "closed":
				cache.Lock()
				cache.closed = true
				cache.Unlock()
			}
			finish()
			awaitDiscoveryRefresh(t, done)
			awaitDiscoveryRefresh(t, flight.done)
			if mode == "recover" {
				if err != nil || string(value) != `{"current":true}` || calls.Load() != 1 {
					t.Fatalf("background deadline escaped into live reader: value=%s calls=%d err=%v", value, calls.Load(), err)
				}
			} else if mode == "foreground_deadline" {
				if !errors.Is(err, context.DeadlineExceeded) || calls.Load() != 1 {
					t.Fatal("foreground deadline was retried or lost", err, calls.Load())
				}
			} else if err == nil || value != nil || calls.Load() != 0 {
				t.Fatal("unrelated error, governance change or cancellation retried", mode, err, calls.Load())
			}
		})
	}
}

func TestDiscoveryRefreshDeadlineRetryCoalescesConcurrentReaders(t *testing.T) {
	var cache discoveryReadCache
	t.Cleanup(cache.close)
	key := discoveryReadKey{"organization/1", "", "", 50, false}
	cache.load(context.Background(), key, func() (json.RawMessage, error) { return json.RawMessage(`{}`), nil })
	expireDiscoveryRead(t, &cache, key, time.Second)
	release := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	t.Cleanup(finish)
	cache.loadRefreshing(context.Background(), key, func() (json.RawMessage, error) { t.Error("initial foreground"); return nil, nil }, func(context.Context) (json.RawMessage, error) {
		<-release
		return nil, context.DeadlineExceeded
	})
	cache.Lock()
	cache.entries[key].previousUntil = time.Now().Add(-time.Second)
	cache.Unlock()
	var calls atomic.Int32
	var workers sync.WaitGroup
	for n := 0; n < 16; n++ {
		ctx := &discoveryWaitingContext{Context: context.Background(), waiting: make(chan struct{})}
		workers.Add(1)
		go func() {
			defer workers.Done()
			value, err := cache.load(ctx, key, func() (json.RawMessage, error) { calls.Add(1); return json.RawMessage(`{"fresh":true}`), nil })
			if err != nil || string(value) != `{"fresh":true}` {
				t.Error("live reader inherited independent deadline", err)
			}
		}()
		awaitDiscoveryRefresh(t, ctx.waiting)
	}
	finish()
	workers.Wait()
	if calls.Load() != 1 {
		t.Fatal("deadline retry duplicated the aggregate query", calls.Load())
	}
	cache.close()
	if cache.running != 0 || cache.refreshing != 0 {
		t.Fatal("retry retained permits")
	}
}
