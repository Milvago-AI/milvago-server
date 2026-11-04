package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
)

const discoveryFingerprintCacheEntries = 16

type discoveryFingerprintKey struct {
	organization  string
	configuration [sha256.Size]byte
	catalog       [sha256.Size]byte
}

// Only a pure derived digest is retained. Authority, effective consent, report
// validity, catalog content and device data are never stored in this memo.
type discoveryFingerprintCache struct {
	sync.Mutex
	entries map[discoveryFingerprintKey]string
}

// The caller must resolve effectiveShadow before reaching this pure operation.
func (cache *discoveryFingerprintCache) fingerprint(organization string, sourceRevision int64, configuration DiscoverySettings, catalog json.RawMessage) (string, error) {
	immutable := append(json.RawMessage(nil), catalog...)
	settings, err := json.Marshal(struct {
		SourceRevision int64             `json:"source_revision"`
		Configuration  DiscoverySettings `json:"configuration"`
	}{sourceRevision, configuration})
	if err != nil {
		return "", err
	}
	key := discoveryFingerprintKey{organization: organization, configuration: sha256.Sum256(settings), catalog: sha256.Sum256(immutable)}
	cache.Lock()
	fingerprint, found := cache.entries[key]
	cache.Unlock()
	if found {
		return fingerprint, nil
	}
	// Concurrent misses may repeat this pure computation, outside the mutex.
	// No pending entries or waiter state can outlive the request.
	fingerprint, err = deriveDiscoveryFingerprint(sourceRevision, configuration, immutable)
	if err != nil {
		return "", err
	}
	cache.Lock()
	defer cache.Unlock()
	if existing, found := cache.entries[key]; found {
		return existing, nil
	}
	if cache.entries == nil {
		cache.entries = make(map[discoveryFingerprintKey]string)
	}
	if len(cache.entries) >= discoveryFingerprintCacheEntries {
		for old := range cache.entries {
			delete(cache.entries, old)
			break
		}
	}
	cache.entries[key] = fingerprint
	return fingerprint, nil
}

// Preserve the established fingerprint representation, including UseNumber and
// the outer struct's field order. Existing delivered fingerprints stay valid.
func deriveDiscoveryFingerprint(sourceRevision int64, configuration DiscoverySettings, catalog json.RawMessage) (string, error) {
	var canonical any
	decoder := json.NewDecoder(bytes.NewReader(catalog))
	decoder.UseNumber()
	if err := decoder.Decode(&canonical); err != nil {
		return "", err
	}
	raw, err := json.Marshal(struct {
		SourceRevision int64             `json:"source_revision"`
		Configuration  DiscoverySettings `json:"configuration"`
		Catalog        any               `json:"catalog"`
	}{sourceRevision, configuration, canonical})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}
