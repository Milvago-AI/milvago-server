package app

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

type discoveryReadKey struct {
	organization, query, after string
	limit                      int
	inventory                  bool
}

type discoveryReadEntry struct {
	done          chan struct{}
	value         json.RawMessage
	err           error
	expires       time.Time
	invalidated   bool
	previous      json.RawMessage
	previousUntil time.Time
	background    bool
}

// Aggregate pages contain application counts and states, never device identities
// or evidence. Authorization and privacy are checked before every cache access.
// A two-second window coalesces simultaneous dashboard reads. During a refresh,
// readers may use the previous authorized aggregate for at most two additional
// seconds. Background refreshes use independent, deadline-bound transactions;
// their closures must never retain a request, session or foreground transaction.
type discoveryReadCache struct {
	sync.Mutex
	entries    map[discoveryReadKey]*discoveryReadEntry
	running    int
	refreshing int
	closed     bool
	work       context.Context
	stop       context.CancelFunc
	workers    sync.WaitGroup
}

func (c *discoveryReadCache) load(ctx context.Context, key discoveryReadKey, read func() (json.RawMessage, error)) (json.RawMessage, error) {
	return c.loadMode(ctx, key, read, nil)
}

func (c *discoveryReadCache) loadRefreshing(ctx context.Context, key discoveryReadKey, read func() (json.RawMessage, error), refresh func(context.Context) (json.RawMessage, error)) (json.RawMessage, error) {
	return c.loadMode(ctx, key, read, refresh)
}

func (c *discoveryReadCache) loadMode(ctx context.Context, key discoveryReadKey, read func() (json.RawMessage, error), refresh func(context.Context) (json.RawMessage, error)) (json.RawMessage, error) {
	return c.loadAttempt(ctx, key, read, refresh, true)
}

func (c *discoveryReadCache) loadAttempt(ctx context.Context, key discoveryReadKey, read func() (json.RawMessage, error), refresh func(context.Context) (json.RawMessage, error), retry bool) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := time.Now()
	c.Lock()
	if c.closed {
		c.Unlock()
		return nil, apiError{503, "discovery_busy", "Discovery summaries are stopping."}
	}
	if c.entries == nil {
		c.entries = make(map[discoveryReadKey]*discoveryReadEntry)
	}
	for key, entry := range c.entries {
		select {
		case <-entry.done:
			if !now.Before(entry.expires.Add(2 * time.Second)) {
				delete(c.entries, key)
			}
		default:
		}
	}
	var previous json.RawMessage
	var previousUntil time.Time
	completed := false
	if entry, ok := c.entries[key]; ok {
		select {
		case <-entry.done:
			if now.Before(entry.expires) {
				c.Unlock()
				return entry.value, entry.err
			}
			if entry.err == nil && !entry.invalidated {
				previous, previousUntil = entry.value, entry.expires.Add(2*time.Second)
			}
			completed = true
		default:
			if !entry.invalidated && entry.previous != nil && now.Before(entry.previousUntil) {
				value := entry.previous
				c.Unlock()
				return value, nil
			}
			c.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-entry.done:
				// A background budget belongs to its independent transaction. A
				// live reader gets one coalesced attempt under its own deadline;
				// no stale grace or background deadline is renewed.
				if retry && entry.background && errors.Is(entry.err, context.DeadlineExceeded) {
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					return c.loadAttempt(ctx, key, read, nil, false)
				}
				return entry.value, entry.err
			}
		}
	}
	// Each completed page is at most 128 KiB; live entries and computations
	// together remain bounded to 64, including independent organizations.
	storage := len(c.entries)
	if completed {
		storage--
	}
	if storage+c.running >= 64 {
		c.Unlock()
		return nil, apiError{503, "discovery_busy", "Discovery summaries are temporarily busy."}
	}
	background := refresh != nil && previous != nil && now.Before(previousUntil)
	if background && c.refreshing >= 4 {
		// Keep the expired entry for a later attempt; the grace deadline does not move.
		c.Unlock()
		return previous, nil
	}
	entry := &discoveryReadEntry{done: make(chan struct{}), previous: previous, previousUntil: previousUntil, background: background}
	c.entries[key] = entry
	c.running++
	if background {
		if c.work == nil {
			c.work, c.stop = context.WithCancel(context.Background())
		}
		refreshContext, cancel := context.WithTimeout(c.work, 2*time.Second)
		c.refreshing++
		c.workers.Add(1)
		c.Unlock()
		go func() {
			defer c.workers.Done()
			defer cancel()
			// compute releases its flight even on panic. A background panic must
			// not terminate the process or leave an immortal refresh permit.
			defer func() { _ = recover() }()
			c.compute(key, entry, func() (json.RawMessage, error) { return refresh(refreshContext) }, true)
		}()
		return previous, nil
	}
	c.Unlock()
	return c.compute(key, entry, read, false)
}

func (c *discoveryReadCache) compute(key discoveryReadKey, entry *discoveryReadEntry, read func() (json.RawMessage, error), background bool) (json.RawMessage, error) {
	defer func() {
		if failure := recover(); failure != nil {
			c.Lock()
			if c.entries[key] == entry {
				delete(c.entries, key)
			}
			entry.err = apiError{503, "discovery_retry", "Discovery summary was interrupted."}
			c.running--
			if background {
				c.refreshing--
			}
			close(entry.done)
			c.Unlock()
			panic(failure)
		}
	}()
	value, err := read()
	if len(value) > 128*1024 {
		err = apiError{503, "discovery_busy", "Discovery summary exceeds its response budget."}
		value = nil
	}
	c.Lock()
	if entry.invalidated || c.closed {
		err = apiError{503, "discovery_retry", "Discovery governance changed; refresh the summary."}
		value = nil
	}
	entry.value, entry.err = value, err
	entry.previous = nil
	entry.expires = time.Now().Add(2 * time.Second)
	c.running--
	if background {
		c.refreshing--
	}
	if err != nil {
		if c.entries[key] == entry {
			delete(c.entries, key)
		}
	}
	close(entry.done)
	c.Unlock()
	return value, err
}

// No workers survive database-pool shutdown. The closed flag serializes Add
// against Wait, including requests racing with shutdown.
func (c *discoveryReadCache) close() {
	c.Lock()
	c.closed = true
	for _, entry := range c.entries {
		entry.invalidated = true
	}
	c.entries = nil
	if c.stop != nil {
		c.stop()
	}
	c.Unlock()
	c.workers.Wait()
}

func (a *App) CloseDiscovery() { a.discoveryReads.close() }

func (c *discoveryReadCache) invalidate(organization string) {
	c.Lock()
	defer c.Unlock()
	for key, entry := range c.entries {
		if key.organization == organization {
			entry.invalidated = true
			delete(c.entries, key)
		}
	}
}
