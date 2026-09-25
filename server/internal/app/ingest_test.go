package app

import (
	"testing"
	"time"
)

// An approved device is authenticated, not trusted: the ingestion budget is what
// stops one from filling the organization's storage. These are the properties the
// budget has to hold, independently of any database.
func TestIngestBudget(t *testing.T) {
	now := time.Date(2026, 9, 10, 14, 30, 12, 0, time.UTC)
	var limiter ingestLimiter

	t.Run("a device is refused once it exhausts its budget", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			if !limiter.allow("device-a /v2/events", 3, now) {
				t.Fatalf("request %d refused inside the budget", i+1)
			}
		}
		if limiter.allow("device-a /v2/events", 3, now) {
			t.Fatal("a device kept ingesting past its budget")
		}
	})

	t.Run("one device exhausting its budget does not refuse another", func(t *testing.T) {
		if !limiter.allow("device-b /v2/events", 3, now) {
			t.Fatal("an unrelated device was refused")
		}
	})

	t.Run("budgets are per route", func(t *testing.T) {
		if !limiter.allow("device-a /v2/heartbeat", 3, now) {
			t.Fatal("exhausting one route's budget refused another route")
		}
	})

	t.Run("the budget refills when the window turns", func(t *testing.T) {
		if limiter.allow("device-a /v2/events", 3, now.Add(30*time.Second)) {
			t.Fatal("the budget refilled inside the same minute")
		}
		if !limiter.allow("device-a /v2/events", 3, now.Add(time.Minute)) {
			t.Fatal("the budget did not refill on the next minute")
		}
	})

	t.Run("a turned window drops the previous counters", func(t *testing.T) {
		// Memory must be bounded by the devices seen within one minute, never by
		// how many devices the server has ever seen.
		for i := 0; i < 50; i++ {
			limiter.allow(string(rune('a'+i%26))+" /v2/events", 3, now.Add(2*time.Minute))
		}
		before := len(limiter.counts)
		limiter.allow("device-a /v2/events", 3, now.Add(3*time.Minute))
		if len(limiter.counts) != 1 || before == 1 {
			t.Fatalf("counters survived the window turn: %d before, %d after", before, len(limiter.counts))
		}
	})

	t.Run("the bounded routes are the ingestion routes", func(t *testing.T) {
		for _, route := range []string{"/v2/events", "/v2/heartbeat", "/v1/inventory"} {
			if deviceBudget[route] == 0 {
				t.Fatalf("%s has no ingestion budget", route)
			}
		}
	})
}
