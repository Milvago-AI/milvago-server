package app

import (
	"context"
	"sync"
	"time"
)

// These are admission permits, never events, sessions or authorization decisions.
// Unused permits are deliberately lost on restart, never refunded or recreated.
const publicQuotaReservation = 32
const maxQuotaReservations = 16384

type quotaReservation struct {
	budget    int
	remaining int
	expires   time.Time
	loading   chan struct{}
}
type quotaReservations struct {
	mu      sync.Mutex
	entries map[string]quotaReservation
}

func rateUnavailable() error {
	return apiError{503, "rate_limit_unavailable", "Request admission is temporarily unavailable."}
}

// reservePublicRate is used only for the two high-budget device-auth guards.
// Device identity, revocation and the exact per-device quota still hit PostgreSQL
// on every request. A public reservation cannot grant durable authorization.
func (a *App) reservePublicRate(ctx context.Context, key string, budget int) error {
	return a.reserveRate(ctx, 2, key, budget)
}

func quotaCacheKey(family int16, digest []byte) string {
	key := string(digest)
	if family != 2 {
		// A different quota family cannot reuse this family's lease.
		return string(rune('0'+family)) + key
	}
	return key
}

// Called with the reservation mutex held.
func (cache *quotaReservations) reclaimExpired(now time.Time) bool {
	for key, value := range cache.entries {
		if value.loading == nil && !now.Before(value.expires) {
			delete(cache.entries, key)
		}
	}
	return len(cache.entries) < maxQuotaReservations
}

// Called with the reservation mutex held.
func (cache *quotaReservations) consume(key string, lease quotaReservation, found bool, budget int, now time.Time) bool {
	if !found || lease.budget != budget || !now.Before(lease.expires) || lease.remaining <= 0 {
		return false
	}
	lease.remaining--
	cache.entries[key] = lease
	return true
}

// reserveRate is reservePublicRate in a given family: 2 for peers, 3 for totals.
func (a *App) reserveRate(ctx context.Context, family int16, key string, budget int) error {
	if a.db == nil {
		return rateUnavailable()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cache := &a.quotaReservations
	digest := hash(key)
	cacheKey := quotaCacheKey(family, digest)
	for {
		cache.mu.Lock()
		if ctx.Err() != nil {
			cache.mu.Unlock()
			return rateUnavailable()
		}
		now := time.Now()
		lease, found := cache.entries[cacheKey]
		if lease.loading != nil {
			cache.mu.Unlock()
			select {
			case <-lease.loading:
				continue
			case <-ctx.Done():
				return rateUnavailable()
			}
		}
		if cache.consume(cacheKey, lease, found, budget, now) {
			cache.mu.Unlock()
			return nil
		}
		if cache.entries == nil {
			cache.entries = make(map[string]quotaReservation)
		}
		if !found && len(cache.entries) >= maxQuotaReservations && !cache.reclaimExpired(now) {
			// A full cache falls back to PostgreSQL for this request.
			cache.mu.Unlock()
			return a.sharedRate(ctx, family, key, budget)
		}
		// One refill per key; never hold the map mutex during pool or SQL waits.
		// Other keys and already prepaid permits remain immediately accessible.
		loading := make(chan struct{})
		cache.entries[cacheKey] = quotaReservation{loading: loading}
		cache.mu.Unlock()
		reserved, err := a.loadPublicReservation(ctx, family, digest, budget)
		cache.mu.Lock()
		if err != nil {
			delete(cache.entries, cacheKey)
		} else {
			cache.entries[cacheKey] = reserved
		}
		close(loading)
		cache.mu.Unlock()
		return err
	}
}

func (a *App) loadPublicReservation(ctx context.Context, family int16, digest []byte, budget int) (quotaReservation, error) {
	// A request straddling a database minute may receive an already expired lease.
	// Retry once; do not turn expired permits into permission in a new window.
	for range 2 {
		started := time.Now()
		var granted int
		var validForMS int64
		err := a.db.QueryRow(ctx, "SELECT granted,valid_for_ms FROM reserve_rate_budget($4::smallint,$1::bytea,$2::integer,$3::integer)", digest, budget, publicQuotaReservation, family).Scan(&granted, &validForMS)
		if err != nil {
			return quotaReservation{}, rateUnavailable()
		}
		if granted == 0 {
			return quotaReservation{}, rateLimited()
		}
		// Use a monotonic deadline anchored BEFORE the SQL call. Time spent acquiring
		// a pool connection, locking, committing and returning can only shorten a lease.
		expires := started.Add(time.Duration(validForMS) * time.Millisecond)
		if time.Now().Before(expires) {
			return quotaReservation{budget: budget, remaining: granted - 1, expires: expires}, nil
		}
	}
	return quotaReservation{}, rateUnavailable()
}
