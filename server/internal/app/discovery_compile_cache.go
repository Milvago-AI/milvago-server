package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

const discoveryCompileCacheEntries = 16

type discoveryCompileKey struct {
	organization string
	digest       [sha256.Size]byte
}

type discoveryCompileEntry struct {
	done chan struct{}
	err  error
}

// This remembers only a successful catalog compilation, never authorization or
// report validity. Full immutable content and tenant identity determine reuse.
type discoveryCompileCache struct {
	sync.Mutex
	entries map[discoveryCompileKey]*discoveryCompileEntry
}

func (c *discoveryCompileCache) ensure(ctx context.Context, key discoveryCompileKey, compile func() error) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		c.Lock()
		if entry, ok := c.entries[key]; ok {
			c.Unlock()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-entry.done:
				if err := ctx.Err(); err != nil {
					return err
				}
				// A canceled compiler must not cancel another live request.
				if errors.Is(entry.err, context.Canceled) || errors.Is(entry.err, context.DeadlineExceeded) {
					continue
				}
				return entry.err
			}
		}
		if c.entries == nil {
			c.entries = make(map[discoveryCompileKey]*discoveryCompileEntry)
		}
		if len(c.entries) >= discoveryCompileCacheEntries {
			for oldKey, entry := range c.entries {
				select {
				case <-entry.done:
					delete(c.entries, oldKey)
				default:
					continue
				}
				break
			}
		}
		if len(c.entries) >= discoveryCompileCacheEntries {
			// All entries are in flight. The existing WASM semaphore and deadline
			// still bound this uncached call; never grow or evict a live entry.
			c.Unlock()
			err := compile()
			if err == nil {
				err = ctx.Err()
			}
			return err
		}
		entry := &discoveryCompileEntry{done: make(chan struct{})}
		c.entries[key] = entry
		c.Unlock()
		return c.compute(ctx, key, entry, compile)
	}
}

func (c *discoveryCompileCache) compute(ctx context.Context, key discoveryCompileKey, entry *discoveryCompileEntry, compile func() error) (err error) {
	defer func() {
		failure := recover()
		if failure != nil {
			err = errors.New("discovery catalog compilation interrupted")
		}
		if failure == nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		c.Lock()
		entry.err = err
		if err != nil && c.entries[key] == entry {
			delete(c.entries, key)
		}
		close(entry.done)
		c.Unlock()
		if failure != nil {
			panic(failure)
		}
	}()
	return compile()
}

type discoveryCatalogCheck func(context.Context, json.RawMessage) error
type discoveryReportCheck func(context.Context, json.RawMessage, json.RawMessage) error

func validateDiscoveryReportWith(ctx context.Context, cache *discoveryCompileCache, organization string, catalog, report json.RawMessage, compile discoveryCatalogCheck, validate discoveryReportCheck) error {
	// The compile miss and the report check share one total budget. Nested WASM
	// calls inherit this deadline instead of each gaining another two seconds.
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(catalog) > 2<<20 {
		return bad("Discovery input exceeds its limits.")
	}
	immutable := append(json.RawMessage(nil), catalog...)
	key := discoveryCompileKey{organization: organization, digest: sha256.Sum256(immutable)}
	if err := cache.ensure(ctx, key, func() error { return compile(ctx, immutable) }); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validate(ctx, immutable, report); err != nil {
		return err
	}
	return ctx.Err()
}

func (a *App) validateDiscoveryReport(ctx context.Context, organization string, catalog, report json.RawMessage) error {
	return validateDiscoveryReportWith(ctx, &a.discoveryCompiles, organization, catalog, report,
		func(ctx context.Context, frozen json.RawMessage) error {
			return discoveryEngine(ctx, map[string]any{"op": "compile", "catalog": frozen}, nil)
		},
		func(ctx context.Context, frozen, report json.RawMessage) error {
			return callDiscoveryEngine(ctx, map[string]any{"catalog": frozen, "report": report}, nil, "discovery_call_prevalidated_report")
		})
}
