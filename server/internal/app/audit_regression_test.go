package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInteractiveGrantCeiling(t *testing.T) {
	for _, key := range []string{"", "test-key"} {
		s := &Session{APIKeyID: key, Permissions: []string{"members.manage", "events.read"}}
		if s.mayGrant([]string{"events.read", "roles.manage"}) {
			t.Fatalf("principal with key %q granted a permission it does not hold", key)
		}
		if !s.mayGrant([]string{"events.read"}) {
			t.Fatal("a legitimate subset was refused")
		}
	}
}

func TestRateCardinalityAndLoginRefusal(t *testing.T) {
	now := time.Now()
	var limiter ingestLimiter
	for i := 0; i < maxRateKeys; i++ {
		if !limiter.allow(fmt.Sprint(i), 2, now) {
			t.Fatal("capacity not reached")
		}
	}
	// Full: a new key is admitted without being counted (the shared PostgreSQL budget
	// that every caller consults next decides), and the map does not grow.
	if !limiter.allow("new-token", 2, now) || len(limiter.counts) != maxRateKeys {
		t.Fatal("a full limiter refused a new caller, or arbitrary credentials grew it")
	}
	if !limiter.allow("0", 2, now) {
		t.Fatal("existing caller lost remaining budget")
	}
	if !limiter.allow("new-token", 2, now.Add(time.Minute)) || len(limiter.counts) != 1 {
		t.Fatal("limiter did not recover")
	}
	a := &App{}
	for i := 0; i < 1200; i++ {
		a.publicTotals.allow("login total", 1200, now)
	}
	request := httptest.NewRequest("GET", "/auth/login", nil)
	request.Header.Set("X-Forwarded-For", "203.0.113.22")
	w := httptest.NewRecorder()
	a.login(w, request)
	if w.Code != 429 {
		t.Fatalf("login reached database after exhausting budget: %d", w.Code)
	}
}

func TestPublicBudgetIgnoresForgedForwardingHeaders(t *testing.T) {
	a := &App{}
	r := httptest.NewRequest("GET", "/auth/login", nil)
	if !a.allowPublicRequest(r, "test", 1, 100) {
		t.Fatal("first request refused")
	}
	r.Header.Set("X-Forwarded-For", "198.51.100.12")
	if a.allowPublicRequest(r, "test", 1, 100) {
		t.Fatal("untrusted header bypassed peer budget")
	}
	r.RemoteAddr = "198.51.100.13:1234"
	if !a.allowPublicRequest(r, "test", 1, 100) {
		t.Fatal("different peer lost its budget")
	}
}

func TestRejectedPeerCannotSpendGlobalBudget(t *testing.T) {
	a := &App{}
	r := httptest.NewRequest("GET", "/auth/login", nil)
	if !a.allowPublicRequest(r, "test", 1, 3) {
		t.Fatal("first request refused")
	}
	for i := 0; i < 1200; i++ {
		if a.allowPublicRequest(r, "test", 1, 3) {
			t.Fatal("noisy peer accepted")
		}
	}
	r.RemoteAddr = "198.51.100.12:1234"
	if !a.allowPublicRequest(r, "test", 1, 3) {
		t.Fatal("rejected traffic consumed global budget")
	}
}

func TestDeviceAuthenticationIsBoundedBeforeDatabase(t *testing.T) {
	a := &App{}
	r := httptest.NewRequest("GET", "/v3/policy", nil)
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 43))
	for i := 0; i < 6000; i++ {
		if !a.allowPublicRequest(r, "device-auth", 6000, 60000) {
			t.Fatal("fixture did not reach the configured budget")
		}
	}
	_, _, _, err := a.deviceTx(r)
	var denied apiError
	if !errors.As(err, &denied) || denied.status != 429 {
		t.Fatalf("device lookup was not refused before database: %v", err)
	}
}

// A tenant other than the root one exports to public addresses only; the root keeps
// its explicit loopback collector, and every tenant keeps the metadata block.
func TestCollectorDialPublicOnly(t *testing.T) {
	prohibited := func(ctx context.Context, address string) bool {
		c, e := collectorDial(ctx, "tcp", address)
		if c != nil {
			c.Close()
		}
		return e != nil && strings.Contains(e.Error(), "prohibited")
	}
	restricted := withPublicOnly(context.Background())
	for _, address := range []string{"127.0.0.1:1", "10.0.0.1:443", "192.168.1.1:443", "100.64.0.1:443", "[::1]:1", "[fd00::1]:443"} {
		if !prohibited(restricted, address) {
			t.Fatalf("a non-root tenant may reach %s", address)
		}
	}
	if prohibited(context.Background(), "127.0.0.1:1") {
		t.Fatal("the root organization lost its explicit loopback collector")
	}
	if !prohibited(context.Background(), "169.254.169.254:80") {
		t.Fatal("metadata address reachable")
	}
}

// A ';'-separated spreadsheet splits a field on ';': every segment that would start a
// formula is neutralized, not only the first one.
func TestCSVSafeSegments(t *testing.T) {
	for in, want := range map[string]string{
		"pc-01":                "pc-01",
		"=1+1":                 "'=1+1",
		"pc;=HYPERLINK(\"x\")": "pc;'=HYPERLINK(\"x\")",
		"a; +1;b":              "a;' +1;b",
		"@x;-2":                "'@x;'-2",
	} {
		if got := csvSafe(in); got != want {
			t.Fatalf("csvSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

// Names and e-mails from the identity provider lose direction overrides, other
// controls and line separators, and keep everything else.
func TestIdentityText(t *testing.T) {
	for in, want := range map[string]string{
		"Synthetic Person":     "Synthetic Person",
		"invoice‮fdp":          "invoicefdp",
		"a b\u0085c\x07d":      "abcd",
		"person‍@example.test": "person‍@example.test",
		"‏שלום":                "שלום",
	} {
		if got := identityText(in); got != want {
			t.Fatalf("identityText(%q) = %q, want %q", in, got, want)
		}
	}
}

// A body read ahead of the transaction is reserved, capped one byte past its ceiling,
// and returned when released; signing out reads nothing.
func TestReadBodyReservation(t *testing.T) {
	before := readBytes.Load()
	hold := &bodyHold{}
	r := httptest.NewRequest("POST", "/api/enrollments", strings.NewReader(strings.Repeat("a", 200<<10)))
	r = r.WithContext(context.WithValue(r.Context(), bodyHoldKey{}, hold))
	if e := (&App{}).readBody(r, "person synthetic"); e != nil {
		t.Fatal(e)
	}
	// A principal has at most four bodies in flight.
	for range bodiesPerPrincipal - 1 {
		if !bodiesInFlight.acquire("person synthetic", bodiesPerPrincipal) {
			t.Fatal("slot refused below the ceiling")
		}
	}
	if e := (&App{}).readBody(httptest.NewRequest("POST", "/api/enrollments", strings.NewReader("{}")), "person synthetic"); e == nil {
		t.Fatal("a fifth body in flight was read")
	}
	for range bodiesPerPrincipal - 1 {
		bodiesInFlight.release("person synthetic")
	}
	if hold.reserved != 128<<10+1 || readBytes.Load()-before != 128<<10+1 {
		t.Fatalf("body not held at its ceiling: %d %d", hold.reserved, readBytes.Load()-before)
	}
	// A handler wrapping the body (decode does) does not lose the reservation.
	r.Body = http.MaxBytesReader(httptest.NewRecorder(), r.Body, 128<<10)
	hold.release()
	if readBytes.Load() != before {
		t.Fatal("reservation not returned")
	}
	out := httptest.NewRequest("POST", "/auth/logout", strings.NewReader("x"))
	if e := (&App{}).readBody(out, "person synthetic"); e != nil || out.Body != http.NoBody || readBytes.Load() != before {
		t.Fatal("logout read a body")
	}
	if !bodiesInFlight.acquire("person synthetic", 1) {
		t.Fatal("a released body kept its slot")
	}
	bodiesInFlight.release("person synthetic")
}

// A NAT64 address is judged by the IPv4 it reaches.
func TestCollectorIPUnwrapsNAT64(t *testing.T) {
	if !blockedCollectorIP(net.ParseIP("64:ff9b::a9fe:a9fe")) || !nonPublicCollectorIP(net.ParseIP("64:ff9b::a00:1")) || nonPublicCollectorIP(net.ParseIP("64:ff9b::808:808")) {
		t.Fatal("NAT64 addresses must be judged by their embedded IPv4")
	}
}

// The setup wizard and invitations refuse the e-mails the sign-in refuses.
func TestPlainAddressRefusesControls(t *testing.T) {
	if got, ok := plainAddress(" Owner@Example.test "); !ok || got != "owner@example.test" {
		t.Fatalf("a plain address was refused: %q %v", got, ok)
	}
	for _, raw := range []string{"owner‎@example.test", "owner‮@example.test", "owner\u0085@example.test", "Owner <owner@example.test>"} {
		if _, ok := plainAddress(raw); ok {
			t.Fatalf("accepted %q", raw)
		}
	}
	// The bootstrap match folds ASCII case only: "ſ" (U+017F) and the Kelvin sign are
	// other realm accounts, not the first owner.
	if asciiLower("Support@Example.test") != "support@example.test" || asciiLower("ſupport@example.test") == "support@example.test" || asciiLower("Key@example.test") == "key@example.test" {
		t.Fatal("bootstrap address folded beyond ASCII")
	}
}
