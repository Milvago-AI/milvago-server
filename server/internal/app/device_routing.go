package app

import (
	"sync"
	"time"
)

const deviceRoutingCapacity = 20000

type deviceRoutingEntry struct {
	organization, device string
	expires              time.Time
}
type deviceRoutingCache struct {
	sync.Mutex
	entries map[string]deviceRoutingEntry
}

// A hint only: deviceTx still checks the live credential and approval under its row lock.
// Known devices must not consume the anonymous peer budget of their shared reverse proxy.
func (c *deviceRoutingCache) get(digest []byte, now time.Time) (deviceRoutingEntry, bool) {
	if len(digest) != 32 {
		return deviceRoutingEntry{}, false
	}
	c.Lock()
	defer c.Unlock()
	key := string(digest)
	entry, ok := c.entries[key]
	if ok && !now.Before(entry.expires) {
		delete(c.entries, key)
		return deviceRoutingEntry{}, false
	}
	if ok {
		entry.expires = now.Add(90 * time.Second)
		c.entries[key] = entry
	}
	return entry, ok
}
func (c *deviceRoutingCache) forget(digest []byte) {
	c.Lock()
	defer c.Unlock()
	delete(c.entries, string(digest))
}
func (c *deviceRoutingCache) put(digest []byte, organization, device string, now time.Time) {
	if len(digest) != 32 {
		return
	}
	c.Lock()
	defer c.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]deviceRoutingEntry)
	}
	key := string(digest)
	if _, exists := c.entries[key]; !exists && len(c.entries) >= deviceRoutingCapacity {
		for key := range c.entries {
			delete(c.entries, key)
			break
		}
	}
	c.entries[key] = deviceRoutingEntry{organization: organization, device: device, expires: now.Add(90 * time.Second)}
}
