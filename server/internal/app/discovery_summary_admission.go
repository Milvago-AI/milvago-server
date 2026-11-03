package app

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

const (
	discoverySummaryOrganizations = 64
	discoverySummaryParticipants  = 128
	discoverySummaryWait          = 5 * time.Second
)

type discoverySummaryAdmissionKey struct{}

type discoverySummaryEntry struct {
	permit chan struct{}
	refs   int
}

type discoverySummaryRegistry struct {
	mu      sync.Mutex
	entries map[[16]byte]*discoverySummaryEntry
}

func discoverySummaryBusy() error {
	return apiError{503, "discovery_busy", "Discovery summaries are temporarily busy."}
}

// References include the owner and all queued requests. Live entries are never
// evicted: two channels for the same organization would defeat serialization.
func (registry *discoverySummaryRegistry) join(org [16]byte) (*discoverySummaryEntry, bool, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if entry := registry.entries[org]; entry != nil {
		if entry.refs >= discoverySummaryParticipants {
			return nil, false, discoverySummaryBusy()
		}
		entry.refs++
		return entry, false, nil
	}
	if len(registry.entries) >= discoverySummaryOrganizations {
		// This is only a performance guard. A full metadata map must not let
		// one subtree deny admission to an unrelated new organization.
		return nil, true, nil
	}
	if registry.entries == nil {
		registry.entries = make(map[[16]byte]*discoverySummaryEntry)
	}
	entry := &discoverySummaryEntry{permit: make(chan struct{}, 1), refs: 1}
	registry.entries[org] = entry
	return entry, false, nil
}

func (registry *discoverySummaryRegistry) leave(org [16]byte, entry *discoverySummaryEntry) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.entries[org] != entry {
		return
	}
	entry.refs--
	if entry.refs == 0 {
		delete(registry.entries, org)
	}
}

type discoverySummaryAdmission struct {
	registry    *discoverySummaryRegistry
	acquireOnce sync.Once
	closeOnce   sync.Once
	mu          sync.Mutex
	done        chan struct{}
	closed      bool
	bound       bool
	org         [16]byte
	entry       *discoverySummaryEntry
	bypass      bool
	err         error
}

func (admission *discoverySummaryAdmission) acquire(ctx context.Context, organization string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var parsed pgtype.UUID
	if err := parsed.Scan(organization); err != nil || !parsed.Valid {
		return errors.New("invalid discovery summary organization")
	}
	admission.mu.Lock()
	if admission.closed {
		admission.mu.Unlock()
		return context.Canceled
	}
	if admission.bound && admission.org != parsed.Bytes {
		admission.mu.Unlock()
		return errors.New("discovery summary organization changed")
	}
	admission.bound, admission.org = true, parsed.Bytes
	admission.mu.Unlock()
	admission.acquireOnce.Do(func() {
		entry, bypass, err := admission.registry.join(parsed.Bytes)
		if err != nil {
			admission.mu.Lock()
			admission.err = err
			admission.mu.Unlock()
			return
		}
		if bypass {
			admission.mu.Lock()
			admission.bypass = true
			admission.mu.Unlock()
			return
		}
		// This reference belongs to this acquisition until it hands off the
		// permit. Close can signal a queued request but cannot drop its ref.
		acquired, handedOff := false, false
		defer func() {
			if !handedOff {
				if acquired {
					<-entry.permit
				}
				admission.registry.leave(parsed.Bytes, entry)
			}
		}()
		wait, cancel := context.WithTimeout(ctx, discoverySummaryWait)
		defer cancel()
		select {
		case entry.permit <- struct{}{}:
			acquired = true
		case <-wait.Done():
			err = ctx.Err()
			if err == nil {
				err = discoverySummaryBusy()
			}
		case <-admission.done:
			err = context.Canceled
		}
		// A ready permit must not win a select against an already expired wait.
		if err == nil && wait.Err() != nil {
			err = ctx.Err()
			if err == nil {
				err = discoverySummaryBusy()
			}
		}
		admission.mu.Lock()
		defer admission.mu.Unlock()
		if admission.closed {
			err = context.Canceled
		} else if current := ctx.Err(); current != nil {
			err = current
		}
		admission.err = err
		if err == nil {
			admission.entry = entry
			handedOff = true
		}
	})
	if err := ctx.Err(); err != nil {
		return err
	}
	admission.mu.Lock()
	defer admission.mu.Unlock()
	if admission.closed {
		return context.Canceled
	}
	return admission.err
}

func (admission *discoverySummaryAdmission) close() {
	admission.closeOnce.Do(func() {
		admission.mu.Lock()
		admission.closed = true
		close(admission.done)
		entry, org := admission.entry, admission.org
		admission.entry = nil
		admission.mu.Unlock()
		if entry != nil {
			// Return the token before the final ref can remove its channel.
			<-entry.permit
			admission.registry.leave(org, entry)
		}
	})
}

func summaryAdmissionFor(ctx context.Context) *discoverySummaryAdmission {
	admission, _ := ctx.Value(discoverySummaryAdmissionKey{}).(*discoverySummaryAdmission)
	return admission
}

func checkDiscoverySummaryAdmissionOpen(ctx context.Context) error {
	if admission := summaryAdmissionFor(ctx); admission != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
		admission.mu.Lock()
		defer admission.mu.Unlock()
		if admission.closed {
			return context.Canceled
		}
	}
	return nil
}

func acquireDiscoverySummaryAdmission(ctx context.Context, org string) error {
	if admission := summaryAdmissionFor(ctx); admission != nil {
		return admission.acquire(ctx, org)
	}
	return nil
}

func endDiscoverySummaryAdmission(ctx context.Context) {
	if admission := summaryAdmissionFor(ctx); admission != nil {
		admission.close()
	}
}

func discoverySummaryAdmissionHandler(registry *discoverySummaryRegistry, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if (r.Method != http.MethodGet && r.Method != http.MethodHead) || r.URL.Path != "/api/discovery/applications" {
			next(w, r)
			return
		}
		admission := &discoverySummaryAdmission{registry: registry, done: make(chan struct{})}
		defer admission.close()
		r = r.WithContext(context.WithValue(r.Context(), discoverySummaryAdmissionKey{}, admission))
		next(w, r)
	}
}
