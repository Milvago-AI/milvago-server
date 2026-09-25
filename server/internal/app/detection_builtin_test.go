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

// Exercise the real startup migration against changed persisted bytes. A
// successful SQL execution alone cannot prove that a replacement was inserted.
func TestDetectionBuiltinUpgrade(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	content, err := decodeDetection(detectionFactory)
	if err != nil {
		t.Fatal(err)
	}
	// The built-in catalogue is inserted as the edition covers it, so the bytes this
	// test expects are the narrowed ones wherever the edition narrows.
	restrictEditionProviders(&content)
	factory, err := json.Marshal(content)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(factory)
	expectedHash := hex.EncodeToString(digest[:])
	initialize := func(t *testing.T) {
		t.Helper()
		tx, e := f.admin.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		if e = initializeDetection(ctx, tx, "milvago_runtime"); e != nil {
			t.Fatal(e)
		}
		if e = tx.Commit(ctx); e != nil {
			t.Fatal(e)
		}
	}
	current := func(t *testing.T) (int64, int, []byte, string, string) {
		t.Helper()
		var revision int64
		var count int
		var raw []byte
		var hash, source string
		if e := f.admin.QueryRow(ctx, "SELECT revision,content,content_hash,source,(SELECT count(*) FROM detection_catalogs) FROM detection_catalogs ORDER BY revision DESC LIMIT 1").Scan(&revision, &raw, &hash, &source, &count); e != nil {
			t.Fatal(e)
		}
		return revision, count, raw, hash, source
	}
	initial, count, raw, hash, source := current(t)
	if count != 1 || !bytes.Equal(raw, factory) || hash != expectedHash || source != "builtin" {
		t.Fatal("initial builtin fixture missing", count, source)
	}
	initialize(t)
	revision, count, _, _, _ := current(t)
	if revision != initial || count != 1 {
		t.Fatal("unchanged builtin duplicated")
	}
	// Create earlier valid builtin bytes with a different provider label.
	changed := content
	changed.Providers = append([]DetectionProvider(nil), content.Providers...)
	if len(changed.Providers) == 0 {
		t.Fatal("factory has no providers")
	}
	changed.Providers[0].Label = "Synthetic earlier catalog"
	older, e := json.Marshal(changed)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Equal(older, factory) {
		t.Fatal("older fixture unchanged")
	}
	oldDigest := sha256.Sum256(older)
	if tag, e := f.admin.Exec(ctx, "UPDATE detection_catalogs SET content=$1,content_hash=$2 WHERE revision=$3", older, hex.EncodeToString(oldDigest[:]), initial); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("older builtin not obtained", e)
	}
	_, _, raw, hash, _ = current(t)
	if !bytes.Equal(raw, older) || hash == expectedHash {
		t.Fatal("older builtin not persisted")
	}
	initialize(t)
	revision, count, raw, hash, source = current(t)
	if revision <= initial || count != 2 || !bytes.Equal(raw, factory) || hash != expectedHash || source != "builtin" {
		t.Fatal("changed builtin not replaced exactly once", revision, count, source)
	}
	upgraded := revision
	initialize(t)
	revision, count, _, _, _ = current(t)
	if revision != upgraded || count != 2 {
		t.Fatal("restart duplicated upgrade", revision, count)
	}
	var edited int64
	if e := f.admin.QueryRow(ctx, "INSERT INTO detection_catalogs(content,content_hash,source) VALUES($1,$2,'edited') RETURNING revision", older, hex.EncodeToString(oldDigest[:])).Scan(&edited); e != nil {
		t.Fatal(e)
	}
	initialize(t)
	revision, count, raw, hash, source = current(t)
	if revision != edited || count != 3 || !bytes.Equal(raw, older) || hash != hex.EncodeToString(oldDigest[:]) || source != "edited" {
		t.Fatal("edited latest catalog overwritten", revision, count, source)
	}
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
	deadline := time.Now().Add(3 * time.Second)
	for {
		select {
		case err := <-finished:
			t.Fatalf("startup completed without waiting for publication: %v", err)
		default:
		}
		var waiting bool
		if e = f.a.db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted)", pid).Scan(&waiting); e != nil {
			t.Fatal(e)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("startup advisory wait not observed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	content, e := decodeDetection(detectionFactory)
	if e != nil {
		t.Fatal(e)
	}
	if len(content.Providers) == 0 {
		t.Fatal("factory providers missing")
	}
	content.Providers[0].Label = "Synthetic published catalog"
	raw, e := json.Marshal(content)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	var edited int64
	if e = publisher.QueryRow(ctx, "INSERT INTO detection_catalogs(content,content_hash,source) VALUES($1,$2,'edited') RETURNING revision", raw, hex.EncodeToString(sum[:])).Scan(&edited); e != nil {
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
