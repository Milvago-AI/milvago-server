package app

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDiscoveryDeviceRoutingIsBoundedAndExpires(t *testing.T) {
	var cache deviceRoutingCache
	now := time.Now()
	key := make([]byte, 32)
	for index := 0; index < deviceRoutingCapacity*2; index++ {
		binary.LittleEndian.PutUint64(key, uint64(index))
		cache.put(key, "fixture-org", "fixture-device", now)
	}
	if len(cache.entries) != deviceRoutingCapacity {
		t.Fatal("routing cache exceeded its capacity", len(cache.entries))
	}
	entry, ok := cache.get(key, now)
	if !ok || entry.device != "fixture-device" {
		t.Fatal("routing hint missing")
	}
	if _, ok = cache.get(key, now.Add(91*time.Second)); ok {
		t.Fatal("expired hint was reused")
	}
	if _, ok = cache.get([]byte("image"), now); ok {
		t.Fatal("invalid credential digest accepted")
	}
}

func TestDiscoveryCachedDeviceStillRequiresLiveApproval(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	credential := randomToken()
	var device string
	if err := f.admin.QueryRow(ctx, `INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status) VALUES($1,$2,'Routing fixture','test','0.7.0','approved') RETURNING id`, f.org, hash(credential)).Scan(&device); err != nil {
		t.Fatal(err)
	}
	call := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/v1/discovery/policy", bytes.NewReader(nil))
		r.Header.Set("Authorization", "Bearer "+credential)
		w := httptest.NewRecorder()
		f.a.Handler().ServeHTTP(w, r)
		return w
	}
	requireHTTP(t, call(), 200)
	if _, ok := f.a.deviceRouting.get(hash(credential), time.Now()); !ok {
		t.Fatal("successful device lookup was not cached")
	}
	if _, err := f.admin.Exec(ctx, `UPDATE devices SET status='revoked' WHERE organization_id=$1 AND id=$2`, f.org, device); err != nil {
		t.Fatal(err)
	}
	requireHTTP(t, call(), 401)
	if _, ok := f.a.deviceRouting.get(hash(credential), time.Now()); ok {
		t.Fatal("revoked credential retained a routing hint")
	}
}

func TestDiscoveryActiveRoutingHintDoesNotPeriodicallyReenterAnonymousBudget(t *testing.T) {
	var cache deviceRoutingCache
	key := bytes.Repeat([]byte{8}, 32)
	now := time.Now()
	cache.put(key, "organization", "device", now)
	for seconds := 60; seconds <= 600; seconds += 60 {
		if _, ok := cache.get(key, now.Add(time.Duration(seconds)*time.Second)); !ok {
			t.Fatal("active device returned to anonymous routing", seconds)
		}
	}
	if _, ok := cache.get(key, now.Add(691*time.Second)); ok {
		t.Fatal("inactive device hint did not expire")
	}
	cache.put(key, "organization", "device", now)
	cache.forget(key)
	if _, ok := cache.get(key, now); ok {
		t.Fatal("forgotten hint remained")
	}
}
