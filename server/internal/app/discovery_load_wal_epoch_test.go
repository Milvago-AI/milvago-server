package app

import (
	"context"
	"math"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type discoveryLoadWALSample struct {
	records, fpi, bytes, buffersFull                    uint64
	checkTimed, checkRequested, checkDone, checkBuffers uint64
	checkWriteMS, checkSyncMS                           float64
	walReset, checkReset                                *time.Time
}

type discoveryLoadRuntimeWALSettings struct {
	fsync, fullPage, commit, compression, syncMethod string
	maxWALBytes, sharedBufferBytes                   int64
}

type discoveryLoadWALEpoch struct {
	baseline                                     discoveryLoadWALSample
	baselineOK, settingsOK, durable, modeMatches bool
	expected                                     string
	experiment                                   bool
}

func discoveryLoadWALCount(value string) (uint64, bool) {
	if len(value) == 0 || len(value) > 20 {
		return 0, false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return 0, false
		}
	}
	number, err := strconv.ParseUint(value, 10, 64)
	return number, err == nil
}

func discoveryLoadWALDelta(before, after discoveryLoadWALSample) (discoveryLoadWALSample, bool) {
	if before.walReset == nil || after.walReset == nil || before.checkReset == nil || after.checkReset == nil || !before.walReset.Equal(*after.walReset) || !before.checkReset.Equal(*after.checkReset) {
		return discoveryLoadWALSample{}, false
	}
	left := []uint64{before.records, before.fpi, before.bytes, before.buffersFull, before.checkTimed, before.checkRequested, before.checkDone, before.checkBuffers}
	right := []uint64{after.records, after.fpi, after.bytes, after.buffersFull, after.checkTimed, after.checkRequested, after.checkDone, after.checkBuffers}
	deltas := make([]uint64, len(left))
	for index := range left {
		if right[index] < left[index] {
			return discoveryLoadWALSample{}, false
		}
		deltas[index] = right[index] - left[index]
	}
	for _, value := range []float64{before.checkWriteMS, before.checkSyncMS, after.checkWriteMS, after.checkSyncMS} {
		if value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
			return discoveryLoadWALSample{}, false
		}
	}
	if after.checkWriteMS < before.checkWriteMS || after.checkSyncMS < before.checkSyncMS {
		return discoveryLoadWALSample{}, false
	}
	return discoveryLoadWALSample{records: deltas[0], fpi: deltas[1], bytes: deltas[2], buffersFull: deltas[3], checkTimed: deltas[4], checkRequested: deltas[5], checkDone: deltas[6], checkBuffers: deltas[7], checkWriteMS: after.checkWriteMS - before.checkWriteMS, checkSyncMS: after.checkSyncMS - before.checkSyncMS}, true
}

// Only known static labels and bounded numeric settings can enter test logs.
func discoveryLoadWALSettings(settings discoveryLoadRuntimeWALSettings) (discoveryLoadRuntimeWALSettings, bool, bool) {
	output := settings
	for _, field := range []*string{&output.fsync, &output.fullPage} {
		if *field != "on" && *field != "off" {
			*field = "other"
		}
	}
	switch output.commit {
	case "on", "remote_apply", "remote_write", "local", "off":
	default:
		output.commit = "other"
	}
	switch output.compression {
	case "off", "pglz", "lz4", "zstd":
	case "on":
		output.compression = "pglz"
	default:
		output.compression = "other"
	}
	switch output.syncMethod {
	case "fdatasync", "fsync", "fsync_writethrough", "open_datasync", "open_sync":
	default:
		output.syncMethod = "other"
	}
	validSizes := output.maxWALBytes > 0 && output.maxWALBytes <= 1<<40 && output.sharedBufferBytes > 0 && output.sharedBufferBytes <= 1<<40
	if !validSizes {
		output.maxWALBytes, output.sharedBufferBytes = 0, 0
	}
	durable := output.fsync == "on" && output.fullPage == "on" && (output.commit == "on" || output.commit == "remote_apply" || output.commit == "remote_write" || output.commit == "local")
	return output, validSizes, durable
}

func discoveryLoadWALModeMatches(actual, expected string) bool {
	return (expected == "off" || expected == "pglz") && actual == expected
}

func (snapshot *discoveryLoadFailureSnapshot) readWAL() (discoveryLoadWALSample, bool) {
	if snapshot.connection == nil {
		return discoveryLoadWALSample{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), discoveryLoadSnapshotTimeout)
	defer cancel()
	var raw [8]string
	var value discoveryLoadWALSample
	err := snapshot.connection.QueryRow(ctx, `SELECT w.wal_records::text,w.wal_fpi::text,w.wal_bytes::text,w.wal_buffers_full::text,
 c.num_timed::text,c.num_requested::text,c.num_done::text,c.buffers_written::text,
 c.write_time,c.sync_time,w.stats_reset,c.stats_reset
 FROM pg_catalog.pg_stat_wal w CROSS JOIN pg_catalog.pg_stat_checkpointer c`).Scan(&raw[0], &raw[1], &raw[2], &raw[3], &raw[4], &raw[5], &raw[6], &raw[7], &value.checkWriteMS, &value.checkSyncMS, &value.walReset, &value.checkReset)
	if err != nil {
		return discoveryLoadWALSample{}, false
	}
	var counts [8]uint64
	for index := range raw {
		number, valid := discoveryLoadWALCount(raw[index])
		if !valid {
			return discoveryLoadWALSample{}, false
		}
		counts[index] = number
	}
	value.records, value.fpi, value.bytes, value.buffersFull = counts[0], counts[1], counts[2], counts[3]
	value.checkTimed, value.checkRequested, value.checkDone, value.checkBuffers = counts[4], counts[5], counts[6], counts[7]
	// Reject missing/reset identities or invalid timers before declaring a baseline.
	_, valid := discoveryLoadWALDelta(value, value)
	return value, valid
}

func (snapshot *discoveryLoadFailureSnapshot) beginWAL(t *testing.T, runtimePool *pgxpool.Pool) discoveryLoadWALEpoch {
	t.Helper()
	epoch := discoveryLoadWALEpoch{}
	expected := os.Getenv("MILVAGO_DISCOVERY_EXPECT_WAL_COMPRESSION")
	if expected != "" {
		epoch.experiment = true
		if expected == "off" || expected == "pglz" {
			epoch.expected = expected
		} else {
			epoch.expected = "other"
			t.Error("WAL experiment label is invalid; capacity is not qualified")
		}
	}
	var settings discoveryLoadRuntimeWALSettings
	if runtimePool != nil {
		ctx, cancel := context.WithTimeout(context.Background(), discoveryLoadSnapshotTimeout)
		err := runtimePool.QueryRow(ctx, `SELECT current_setting('fsync'),current_setting('full_page_writes'),current_setting('synchronous_commit'),current_setting('wal_compression'),current_setting('wal_sync_method'),pg_catalog.pg_size_bytes(current_setting('max_wal_size')),pg_catalog.pg_size_bytes(current_setting('shared_buffers'))`).Scan(&settings.fsync, &settings.fullPage, &settings.commit, &settings.compression, &settings.syncMethod, &settings.maxWALBytes, &settings.sharedBufferBytes)
		cancel()
		if err == nil {
			var sizesOK bool
			settings, sizesOK, epoch.durable = discoveryLoadWALSettings(settings)
			epoch.settingsOK = sizesOK
			epoch.modeMatches = !epoch.experiment || discoveryLoadWALModeMatches(settings.compression, epoch.expected)
			t.Logf("runtime WAL settings fsync=%s full_page_writes=%s synchronous_commit=%s wal_compression=%s wal_sync_method=%s max_wal_size_bytes=%d shared_buffers_bytes=%d numeric_settings_valid=%t durable=%t", settings.fsync, settings.fullPage, settings.commit, settings.compression, settings.syncMethod, settings.maxWALBytes, settings.sharedBufferBytes, sizesOK, epoch.durable)
			if !epoch.durable {
				t.Error("runtime WAL settings are non-durable or unverified; capacity is not qualified")
			}
			if epoch.experiment && !epoch.modeMatches {
				t.Error("runtime WAL compression does not match experiment; capacity is not qualified")
			}
		}
	}
	if !epoch.settingsOK {
		t.Log("runtime WAL settings unavailable or invalid; durability is unverified")
		if epoch.experiment {
			t.Error("WAL experiment lacks runtime settings proof; capacity is not qualified")
		}
	}
	epoch.baseline, epoch.baselineOK = snapshot.readWAL()
	if !epoch.baselineOK {
		t.Log("WAL epoch baseline unavailable")
		if epoch.experiment {
			t.Error("WAL experiment lacks baseline counters; capacity is not qualified")
		}
	}
	return epoch
}

func (snapshot *discoveryLoadFailureSnapshot) endWAL(t *testing.T, epoch discoveryLoadWALEpoch, completedIngest, completedReads int, ingestErrors map[int]int) {
	t.Helper()
	// The capture worker has been joined before this read of its dedicated Conn.
	after, available := snapshot.readWAL()
	delta, comparable := discoveryLoadWALDelta(epoch.baseline, after)
	if !epoch.baselineOK || !available || !comparable {
		t.Log("WAL epoch unavailable or reset/non-monotonic; no delta proof")
		if epoch.experiment {
			t.Error("WAL experiment lacks comparable counters; capacity is not qualified")
		}
		return
	}
	expected := epoch.expected
	if expected == "" {
		expected = "none"
	}
	successfulIngest := completedIngest
	for _, count := range ingestErrors {
		successfulIngest -= count
	}
	if successfulIngest < 0 {
		successfulIngest = 0
	}
	t.Logf("approximate WAL epoch reset_unchanged=true runtime_settings_verified=%t durable=%t compression_matches_expected=%t expected_compression=%s completed_ingest_responses=%d successful_ingest_responses=%d completed_read_responses=%d wal_records=%d wal_fpi=%d wal_bytes=%d wal_buffers_full=%d checkpoint_timed=%d checkpoint_requested=%d checkpoint_done=%d checkpoint_buffers_written=%d checkpoint_write_ms=%.3f checkpoint_sync_ms=%.3f", epoch.settingsOK, epoch.durable, epoch.modeMatches, expected, completedIngest, successfulIngest, completedReads, delta.records, delta.fpi, delta.bytes, delta.buffersFull, delta.checkTimed, delta.checkRequested, delta.checkDone, delta.checkBuffers, delta.checkWriteMS, delta.checkSyncMS)
	if successfulIngest > 0 {
		t.Logf("approximate WAL per successful ingest response: bytes=%.3f fpi=%.6f", float64(delta.bytes)/float64(successfulIngest), float64(delta.fpi)/float64(successfulIngest))
	}
	t.Log("WAL statistics can lag about one second; epoch can include delayed bootstrap/preparation statistics and omit final activity; ratios are not sole-ingest attribution or exact CPU/PGX boundaries")
}

func TestDiscoveryLoadWALDeltaRejectsResetAndRegression(t *testing.T) {
	reset := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	other := reset.Add(time.Second)
	before := discoveryLoadWALSample{records: 10, fpi: 20, bytes: 1000, buffersFull: 2, checkTimed: 3, checkRequested: 4, checkDone: 5, checkBuffers: 6, checkWriteMS: 7, checkSyncMS: 8, walReset: &reset, checkReset: &reset}
	after := discoveryLoadWALSample{records: 30, fpi: 22, bytes: 4096, buffersFull: 3, checkTimed: 4, checkRequested: 6, checkDone: 7, checkBuffers: 9, checkWriteMS: 10.5, checkSyncMS: 9.25, walReset: &reset, checkReset: &reset}
	delta, valid := discoveryLoadWALDelta(before, after)
	if !valid || delta.records != 20 || delta.fpi != 2 || delta.bytes != 3096 || delta.buffersFull != 1 || delta.checkTimed != 1 || delta.checkRequested != 2 || delta.checkDone != 2 || delta.checkBuffers != 3 || delta.checkWriteMS != 3.5 || delta.checkSyncMS != 1.25 {
		t.Fatal("valid WAL epoch lost exact deltas")
	}
	for _, mutate := range []func(*discoveryLoadWALSample){
		func(v *discoveryLoadWALSample) { v.walReset = &other }, func(v *discoveryLoadWALSample) { v.checkReset = &other }, func(v *discoveryLoadWALSample) { v.walReset = nil }, func(v *discoveryLoadWALSample) { v.checkReset = nil },
		func(v *discoveryLoadWALSample) { v.records = 0 }, func(v *discoveryLoadWALSample) { v.fpi = 0 }, func(v *discoveryLoadWALSample) { v.bytes = 0 }, func(v *discoveryLoadWALSample) { v.buffersFull = 0 },
		func(v *discoveryLoadWALSample) { v.checkTimed = 0 }, func(v *discoveryLoadWALSample) { v.checkRequested = 0 }, func(v *discoveryLoadWALSample) { v.checkDone = 0 }, func(v *discoveryLoadWALSample) { v.checkBuffers = 0 },
		func(v *discoveryLoadWALSample) { v.checkWriteMS = 0 }, func(v *discoveryLoadWALSample) { v.checkSyncMS = math.NaN() }, func(v *discoveryLoadWALSample) { v.checkWriteMS = math.Inf(1) },
	} {
		changed := after
		mutate(&changed)
		if _, valid := discoveryLoadWALDelta(before, changed); valid {
			t.Fatal("reset/regressing/nonfinite WAL epoch accepted")
		}
	}
}

func TestDiscoveryLoadWALCountIsExactAndBounded(t *testing.T) {
	for _, raw := range []string{"-1", "1.2", "secret", "18446744073709551616", "123456789012345678901"} {
		if _, ok := discoveryLoadWALCount(raw); ok {
			t.Fatal("invalid WAL count accepted")
		}
	}
	value, ok := discoveryLoadWALCount("18446744073709551615")
	if !ok || value != ^uint64(0) {
		t.Fatal("bounded uint64 WAL count lost precision")
	}
}

func TestDiscoveryLoadRuntimeWALSettingsAreDurableAndStatic(t *testing.T) {
	base := discoveryLoadRuntimeWALSettings{fsync: "on", fullPage: "on", commit: "on", compression: "pglz", syncMethod: "fdatasync", maxWALBytes: 1 << 30, sharedBufferBytes: 128 << 20}
	for _, commit := range []string{"on", "local", "remote_write", "remote_apply"} {
		value := base
		value.commit = commit
		_, valid, durable := discoveryLoadWALSettings(value)
		if !valid || !durable {
			t.Fatal("durable runtime WAL settings refused")
		}
	}
	for _, mutate := range []func(*discoveryLoadRuntimeWALSettings){func(v *discoveryLoadRuntimeWALSettings) { v.fsync = "off" }, func(v *discoveryLoadRuntimeWALSettings) { v.fullPage = "off" }, func(v *discoveryLoadRuntimeWALSettings) { v.commit = "off" }, func(v *discoveryLoadRuntimeWALSettings) { v.commit = "synthetic-secret" }} {
		value := base
		mutate(&value)
		if _, _, durable := discoveryLoadWALSettings(value); durable {
			t.Fatal("non-durable/unverified WAL settings accepted")
		}
	}
	value := base
	value.compression = "synthetic-secret"
	value.syncMethod = "synthetic-secret"
	value.maxWALBytes = -1
	output, valid, _ := discoveryLoadWALSettings(value)
	if valid || output.compression != "other" || output.syncMethod != "other" || output.maxWALBytes != 0 || output.sharedBufferBytes != 0 {
		t.Fatal("dynamic WAL labels or invalid sizes escaped normalization")
	}
	for _, pair := range []struct {
		actual, expected string
		matches          bool
	}{{"off", "off", true}, {"pglz", "pglz", true}, {"off", "pglz", false}, {"pglz", "off", false}, {"other", "other", false}, {"off", "synthetic-secret", false}} {
		if discoveryLoadWALModeMatches(pair.actual, pair.expected) != pair.matches {
			t.Fatal("WAL experiment accepted the wrong/unverified runtime mode")
		}
	}
}
