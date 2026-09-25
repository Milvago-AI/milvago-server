package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

type builtinUpgradeFixture struct {
	f            *observabilityFixture
	content      DetectionContent
	factory      []byte
	expectedHash string
}

func newBuiltinUpgradeFixture(t *testing.T) builtinUpgradeFixture {
	t.Helper()
	f := newObservabilityFixture(t)
	content, err := decodeDetection(detectionFactory)
	if err != nil {
		t.Fatal(err)
	}
	// Startup inserts the providers covered by the edition being tested.
	restrictEditionProviders(&content)
	factory, err := json.Marshal(content)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(factory)
	return builtinUpgradeFixture{f: f, content: content, factory: factory, expectedHash: hex.EncodeToString(digest[:])}
}

func (fixture builtinUpgradeFixture) initialize(t *testing.T, ctx context.Context) {
	t.Helper()
	tx, err := fixture.f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err = initializeDetection(ctx, tx, "milvago_runtime"); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func (fixture builtinUpgradeFixture) current(t *testing.T, ctx context.Context) (int64, int, []byte, string, string) {
	t.Helper()
	var revision int64
	var count int
	var raw []byte
	var hash, source string
	if err := fixture.f.admin.QueryRow(ctx, "SELECT revision,content,content_hash,source,(SELECT count(*) FROM detection_catalogs) FROM detection_catalogs ORDER BY revision DESC LIMIT 1").Scan(&revision, &raw, &hash, &source, &count); err != nil {
		t.Fatal(err)
	}
	return revision, count, raw, hash, source
}

func (fixture builtinUpgradeFixture) assertInitial(t *testing.T, ctx context.Context) int64 {
	t.Helper()
	initial, count, raw, hash, source := fixture.current(t, ctx)
	if count != 1 || !bytes.Equal(raw, fixture.factory) || hash != fixture.expectedHash || source != "builtin" {
		t.Fatal("initial builtin fixture missing", count, source)
	}
	fixture.initialize(t, ctx)
	revision, count, _, _, _ := fixture.current(t, ctx)
	if revision != initial || count != 1 {
		t.Fatal("unchanged builtin duplicated")
	}
	return initial
}

func (fixture builtinUpgradeFixture) persistOlder(t *testing.T, ctx context.Context, initial int64) ([]byte, string) {
	t.Helper()
	changed := fixture.content
	changed.Providers = append([]DetectionProvider(nil), fixture.content.Providers...)
	if len(changed.Providers) == 0 {
		t.Fatal("factory has no providers")
	}
	changed.Providers[0].Label = "Synthetic earlier catalog"
	older, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(older, fixture.factory) {
		t.Fatal("older fixture unchanged")
	}
	oldDigest := sha256.Sum256(older)
	oldHash := hex.EncodeToString(oldDigest[:])
	if tag, err := fixture.f.admin.Exec(ctx, "UPDATE detection_catalogs SET content=$1,content_hash=$2 WHERE revision=$3", older, oldHash, initial); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("older builtin not obtained", err)
	}
	_, _, raw, hash, _ := fixture.current(t, ctx)
	if !bytes.Equal(raw, older) || hash == fixture.expectedHash {
		t.Fatal("older builtin not persisted")
	}
	return older, oldHash
}

func (fixture builtinUpgradeFixture) assertReplacement(t *testing.T, ctx context.Context, initial int64) {
	t.Helper()
	fixture.initialize(t, ctx)
	revision, count, raw, hash, source := fixture.current(t, ctx)
	if revision <= initial || count != 2 || !bytes.Equal(raw, fixture.factory) || hash != fixture.expectedHash || source != "builtin" {
		t.Fatal("changed builtin not replaced exactly once", revision, count, source)
	}
	upgraded := revision
	fixture.initialize(t, ctx)
	revision, count, _, _, _ = fixture.current(t, ctx)
	if revision != upgraded || count != 2 {
		t.Fatal("restart duplicated upgrade", revision, count)
	}
}

func (fixture builtinUpgradeFixture) assertEditedPreserved(t *testing.T, ctx context.Context, older []byte, oldHash string) {
	t.Helper()
	var edited int64
	if err := fixture.f.admin.QueryRow(ctx, "INSERT INTO detection_catalogs(content,content_hash,source) VALUES($1,$2,'edited') RETURNING revision", older, oldHash).Scan(&edited); err != nil {
		t.Fatal(err)
	}
	fixture.initialize(t, ctx)
	revision, count, raw, hash, source := fixture.current(t, ctx)
	if revision != edited || count != 3 || !bytes.Equal(raw, older) || hash != oldHash || source != "edited" {
		t.Fatal("edited latest catalog overwritten", revision, count, source)
	}
}

// Exercise the real startup migration against changed persisted bytes. A
// successful SQL execution alone cannot prove that a replacement was inserted.
func TestDetectionBuiltinUpgrade(t *testing.T) {
	fixture := newBuiltinUpgradeFixture(t)
	ctx := context.Background()
	initial := fixture.assertInitial(t, ctx)
	older, oldHash := fixture.persistOlder(t, ctx, initial)
	fixture.assertReplacement(t, ctx, initial)
	fixture.assertEditedPreserved(t, ctx, older, oldHash)
}

func waitForBuiltinPublication(t *testing.T, ctx context.Context, f *observabilityFixture, finished <-chan error, pid int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		select {
		case err := <-finished:
			t.Fatalf("startup completed without waiting for publication: %v", err)
		default:
		}
		var waiting bool
		if err := f.a.db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted)", pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("startup advisory wait not observed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func publishedCatalogBytes(t *testing.T) ([]byte, string) {
	t.Helper()
	content, err := decodeDetection(detectionFactory)
	if err != nil {
		t.Fatal(err)
	}
	if len(content.Providers) == 0 {
		t.Fatal("factory providers missing")
	}
	content.Providers[0].Label = "Synthetic published catalog"
	raw, err := json.Marshal(content)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:])
}

// Observe the actual PostgreSQL lock wait rather than infer serialization from
// goroutine timing. Publish edited bytes only once startup is proven waiting.
func TestDetectionBuiltinSerializesWithPublication(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	publisher, e := f.a.db.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer publisher.Rollback(ctx)
	if _, e = publisher.Exec(ctx, "SELECT pg_advisory_xact_lock(726403212)"); e != nil {
		t.Fatal(e)
	}
	startup, e := f.admin.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	var pid int
	if e = startup.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); e != nil {
		t.Fatal(e)
	}
	finished := make(chan error, 1)
	go func() {
		defer startup.Rollback(ctx)
		err := initializeDetection(ctx, startup, "milvago_runtime")
		if err == nil {
			err = startup.Commit(ctx)
		}
		finished <- err
	}()
	waitForBuiltinPublication(t, ctx, f, finished, pid)
	raw, digest := publishedCatalogBytes(t)
	var edited int64
	if e = publisher.QueryRow(ctx, "INSERT INTO detection_catalogs(content,content_hash,source) VALUES($1,$2,'edited') RETURNING revision", raw, digest).Scan(&edited); e != nil {
		t.Fatal(e)
	}
	if e = publisher.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	select {
	case e = <-finished:
		if e != nil {
			t.Fatal(e)
		}
	case <-ctx.Done():
		t.Fatal("startup did not resume after publication", ctx.Err())
	}
	var revision int64
	var stored []byte
	var source string
	var count int
	if e = f.admin.QueryRow(ctx, "SELECT revision,content,source,(SELECT count(*) FROM detection_catalogs) FROM detection_catalogs ORDER BY revision DESC LIMIT 1").Scan(&revision, &stored, &source, &count); e != nil {
		t.Fatal(e)
	}
	if revision != edited || source != "edited" || !bytes.Equal(stored, raw) || count != 2 {
		t.Fatal("concurrent edited publication overwritten", revision, source, count)
	}
}
