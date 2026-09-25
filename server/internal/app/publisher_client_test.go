package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func publisherSigned(t *testing.T, content []byte, revision int64, now time.Time) ([]byte, ed25519.PublicKey) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{61}, 32))
	sum := sha256.Sum256(content)
	raw, e := json.Marshal(map[string]any{"kind": "detection_catalog", "schema": 1, "revision": revision, "issued_at": now, "expires_at": now.Add(time.Hour), "min_engine": map[string]string{"extension": "0.5.0", "bridge": "0.5.0"}, "content_hash": hex.EncodeToString(sum[:]), "content": base64.StdEncoding.EncodeToString(content)})
	if e != nil {
		t.Fatal(e)
	}
	envelope, _ := json.Marshal(publisherEnvelope{base64.StdEncoding.EncodeToString(raw), base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))})
	return envelope, key.Public().(ed25519.PublicKey)
}
func TestPublisherSignatureAndNativeBoundary(t *testing.T) {
	now := time.Now().UTC()
	raw, key := publisherSigned(t, detectionFactory, 3, now)
	h, content, e := decodePublisherEnvelope(raw, key, 3, "", now)
	if e != nil || !bytes.Equal(content, detectionFactory) {
		t.Fatalf("signed factory rejected %v", e)
	}
	for _, verify := range []func() error{
		func() error { _, _, e := decodePublisherEnvelope(raw, key, 4, "", now); return e },
		func() error { _, _, e := decodePublisherEnvelope(raw, key, 3, "wrong", now); return e },
		func() error {
			_, _, e := decodePublisherEnvelope(raw, key, 3, h.ContentHash, now.Add(2*time.Hour))
			return e
		},
		func() error {
			_, _, e := decodePublisherEnvelope(raw, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{60}, 32)).Public().(ed25519.PublicKey), 0, "", now)
			return e
		},
	} {
		if verify() == nil {
			t.Fatal("invalid publisher authority accepted")
		}
	}
	var c DetectionContent
	if e = json.Unmarshal(detectionFactory, &c); e != nil {
		t.Fatal(e)
	}
	c.NativeTools = []DetectionNative{{ID: "codex", Platform: "windows", Parser: "otlp-v1", QualifiedVersions: []string{"1.0.0"}, TextVersions: []string{"1.0.0"}}}
	content, _ = json.Marshal(c)
	raw, key = publisherSigned(t, content, 4, now)
	if _, _, e = decodePublisherEnvelope(raw, key, 0, "", now); e == nil {
		t.Fatal("publisher activated unqualified raw native text")
	}
}
func TestPublisherEditionLimitsCommunityImport(t *testing.T) {
	var full DetectionContent
	if err := json.Unmarshal(detectionFactory, &full); err != nil {
		t.Fatal(err)
	}
	if err := validatePublisherEdition("commercial", detectionFactory); err != nil {
		t.Fatalf("commercial catalog rejected: %v", err)
	}
	if err := validatePublisherEdition("community", detectionFactory); err == nil {
		t.Fatal("full catalog accepted for Community")
	}
	narrow := full
	narrow.Providers = nil
	narrow.NativeTools = []DetectionNative{}
	for _, provider := range full.Providers {
		if provider.ID == "chatgpt" || provider.ID == "claude" {
			narrow.Providers = append(narrow.Providers, provider)
		}
	}
	content, err := json.Marshal(narrow)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePublisherEdition("community", content); err != nil {
		t.Fatalf("Community catalog rejected: %v", err)
	}
}
func TestPublisherTransportRefusesRedirectAndMetadata(t *testing.T) {
	var received atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1); w.WriteHeader(204) }))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	a := &App{config: Config{PublisherURL: redirect.URL, PublisherCredential: strings.Repeat("x", 40)}}
	if _, e := a.publisherRequest(context.Background(), "POST", "/v1/telemetry", []byte("{}")); e == nil {
		t.Fatal("redirect accepted")
	}
	if received.Load() != 0 {
		t.Fatal("credential followed redirect")
	}
	for _, raw := range []string{"http://169.254.169.254", "https://169.254.169.254", "https://100.100.100.200", "https://example.test/path", "https://user:password@example.test", "http://example.test"} {
		if _, e := publisherOrigin(raw); e == nil {
			t.Fatalf("unsafe publisher accepted: %s", raw)
		}
	}
}
func TestPublisherDialRejectsDNSLoopback(t *testing.T) {
	dns, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer dns.Close()
	go func() {
		for {
			buf := make([]byte, 1500)
			n, addr, e := dns.ReadFrom(buf)
			if e != nil {
				return
			}
			q := buf[:n]
			if len(q) < 17 {
				continue
			}
			end := 12
			for end < len(q) && q[end] != 0 {
				end += 1 + int(q[end])
			}
			end += 5
			if end > len(q) {
				continue
			}
			kind := uint16(q[end-4])<<8 | uint16(q[end-3])
			answer := []byte{127, 0, 0, 1}
			if kind == 28 {
				answer = make([]byte, 16)
				answer[15] = 1
			}
			reply := append([]byte{}, q[:end]...)
			reply[2] = 0x81
			reply[3] = 0x80
			reply[6] = 0
			reply[7] = 1
			reply[8] = 0
			reply[9] = 0
			reply[10] = 0
			reply[11] = 0
			reply = append(reply, 0xc0, 0x0c, byte(kind>>8), byte(kind), 0, 1, 0, 0, 0, 0, 0, byte(len(answer)))
			reply = append(reply, answer...)
			_, _ = dns.WriteTo(reply, addr)
		}
	}()
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", dns.LocalAddr().String())
	}}
	t.Cleanup(func() { net.DefaultResolver = previous })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if conn, e := collectorDial(ctx, "tcp", "publisher.example.test:443"); e == nil {
		conn.Close()
		t.Fatal("DNS-rebound loopback reached dial")
	} else if !strings.Contains(e.Error(), "prohibited") {
		t.Fatalf("did not exercise address guard: %v", e)
	}
}
func TestPublisherClientDatabase(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	setTenant(t, f.admin, f.org)
	var device string
	if e := f.admin.QueryRow(ctx, "INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,last_seen) VALUES($1,$2,'synthetic-device','windows','0.5.0','approved',now()) RETURNING id", f.org, hash(randomToken())).Scan(&device); e != nil {
		t.Fatal(e)
	}
	setConfig := func(t *testing.T, c IdentityPrivacyConfig) {
		t.Helper()
		raw, _ := json.Marshal(c)
		tag, e := f.admin.Exec(ctx, "INSERT INTO privacy_settings(organization_id,configuration,updated_at) VALUES($1,$2,now()-interval '3 days') ON CONFLICT(organization_id) DO UPDATE SET configuration=excluded.configuration,revision=privacy_settings.revision+1,updated_at=excluded.updated_at", f.org, raw)
		if e != nil || tag.RowsAffected() != 1 {
			t.Fatalf("consent not stored: %v", e)
		}
	}
	var requests atomic.Int32
	var fail atomic.Bool
	var bodies [][]byte
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, body)
		if fail.Load() {
			w.WriteHeader(503)
		} else {
			w.WriteHeader(202)
		}
	}))
	defer remote.Close()
	f.a.config.PublisherURL = remote.URL
	f.a.config.PublisherCredential = strings.Repeat("fixture", 6)
	t.Run("off_means_zero_requests", func(t *testing.T) {
		setConfig(t, defaultPrivacy())
		if e := f.a.publisherPass(ctx); e != nil {
			t.Fatal(e)
		}
		if requests.Load() != 0 {
			t.Fatal("disabled telemetry sent a request")
		}
	})
	t.Run("fleet_only_and_daily_limit", func(t *testing.T) {
		cfg := defaultPrivacy()
		cfg.ShareFleet = true
		setConfig(t, cfg)
		if e := f.a.publisherPass(ctx); e != nil {
			t.Fatal(e)
		}
		if requests.Load() != 1 {
			t.Fatalf("expected one request, got %d", requests.Load())
		}
		var b publisherBatch
		if e := json.Unmarshal(bodies[0], &b); e != nil {
			t.Fatal(e)
		}
		if b.Fleet == nil || b.Fleet.Enrolled != 1 || b.Fleet.Active30d != 1 || len(b.ProviderHealth) != 0 {
			t.Fatalf("incorrect fleet batch %+v", b)
		}
		for _, sentinel := range []string{device, f.org, "synthetic-device"} {
			if bytes.Contains(bodies[0], []byte(sentinel)) {
				t.Fatal("local identity leaked")
			}
		}
		if e := f.a.publisherPass(ctx); e != nil {
			t.Fatal(e)
		}
		if requests.Load() != 1 {
			t.Fatal("daily batch duplicated")
		}
	})
	t.Run("retry_is_immutable_and_optout_cancels", func(t *testing.T) {
		if _, e := f.admin.Exec(ctx, "UPDATE publisher_client_state SET last_telemetry_day=NULL"); e != nil {
			t.Fatal(e)
		}
		fail.Store(true)
		if e := f.a.publisherPass(ctx); e != nil {
			t.Fatal(e)
		}
		first := append([]byte{}, bodies[len(bodies)-1]...)
		tag, e := f.admin.Exec(ctx, "UPDATE publisher_client_outbox SET next_attempt=now()-interval '1 second'")
		if e != nil || tag.RowsAffected() != 1 {
			t.Fatal("no durable retry row")
		}
		if e = f.a.publisherPass(ctx); e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(first, bodies[len(bodies)-1]) {
			t.Fatal("retry changed signed batch")
		}
		before := requests.Load()
		setConfig(t, defaultPrivacy())
		if e = f.a.publisherPass(ctx); e != nil {
			t.Fatal(e)
		}
		if requests.Load() != before {
			t.Fatal("optout sent pending batch")
		}
		var count int
		if e = f.admin.QueryRow(ctx, "SELECT count(*) FROM publisher_client_outbox").Scan(&count); e != nil || count != 0 {
			t.Fatal("optout retained pending telemetry")
		}
	})
}
