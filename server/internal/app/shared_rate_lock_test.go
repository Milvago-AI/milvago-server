package app

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestSharedRateNewKeyAllowsConcurrentForeignKeyCheck(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	for attempt := range 3 {
		window := currentRateWindow(t, f.admin)
		if _, err := f.admin.Exec(ctx, `DELETE FROM rate_windows WHERE family=1 AND window_start=$1`, window); err != nil {
			t.Fatal(err)
		}
		if _, err := f.admin.Exec(ctx, `INSERT INTO rate_windows(family,window_start) VALUES(1,$1)`, window); err != nil {
			t.Fatal(err)
		}
		owner, err := f.a.db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer owner.Rollback(ctx)
		var granted int
		var validForMS int64
		if err = owner.QueryRow(ctx, `SELECT granted,valid_for_ms FROM reserve_rate_budget(1::smallint,$1::bytea,2,1)`, hash(fmt.Sprintf("synthetic-lock-owner-%d", attempt))).Scan(&granted, &validForMS); err != nil || granted != 1 {
			t.Fatal("first quota did not reserve its new counter", granted, err)
		}
		var actualWindow time.Time
		if err = owner.QueryRow(ctx, `SELECT date_trunc('minute',clock_timestamp())`).Scan(&actualWindow); err != nil {
			t.Fatal(err)
		}
		if !actualWindow.Equal(window) {
			if err = owner.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			continue
		}
		probe, err := f.admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer probe.Rollback(ctx)
		if _, err = probe.Exec(ctx, `SET LOCAL statement_timeout='500ms'`); err != nil {
			t.Fatal(err)
		}
		// This raw fixture row intentionally has no cardinality claim. Roll it
		// back immediately: its only purpose is the parent's real FK check.
		_, err = probe.Exec(ctx, `INSERT INTO rate_counters(family,window_start,key_hash,hits) VALUES(1,$1,$2,1)`, window, hash(fmt.Sprintf("synthetic-lock-probe-%d", attempt)))
		if err != nil {
			t.Fatal("a new counter blocked a different counter's FK KEY SHARE", err)
		}
		if err = probe.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if err = owner.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		var keys, counters int
		if err = f.admin.QueryRow(ctx, `SELECT keys,(SELECT count(*) FROM rate_counters WHERE family=1 AND window_start=$1) FROM rate_windows WHERE family=1 AND window_start=$1`, window).Scan(&keys, &counters); err != nil || keys != 0 || counters != 0 {
			t.Fatal("rollback separated counter storage from cardinality", keys, counters, err)
		}
		return
	}
	t.Fatal("lock regression could not begin within one database minute")
}

func TestSharedRateConcurrentLastSlotKeepsExactQuotaAndCardinality(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	for attempt := range 3 {
		window := currentRateWindow(t, f.admin)
		if _, err := f.admin.Exec(ctx, `DELETE FROM rate_windows WHERE family=1 AND window_start=$1`, window); err != nil {
			t.Fatal(err)
		}
		if _, err := f.admin.Exec(ctx, `INSERT INTO rate_windows(family,window_start,keys) VALUES(1,$1,16383)`, window); err != nil {
			t.Fatal(err)
		}
		if _, err := f.admin.Exec(ctx, `INSERT INTO rate_counters(family,window_start,key_hash,hits) SELECT 1,$1,sha256(convert_to('synthetic-seeded-'||n,'UTF8')),1 FROM generate_series(1,16383)n`, window); err != nil {
			t.Fatal(err)
		}
		if !currentRateWindow(t, f.admin).Equal(window) {
			continue
		}
		key := fmt.Sprintf("synthetic-last-slot-%d", attempt)
		accepted, limited := concurrentSharedRateResults(t, f, func(int) string { return key }, 17)
		if !currentRateWindow(t, f.admin).Equal(window) {
			continue
		}
		if accepted != 17 || limited != 15 {
			t.Fatal("same-key contenders did not consume exact durable quota", accepted, limited)
		}
		var spent int
		if err := f.admin.QueryRow(ctx, `SELECT hits FROM rate_counters WHERE family=1 AND window_start=$1 AND key_hash=$2`, window, hash(key)).Scan(&spent); err != nil || spent != 17 {
			t.Fatal("same-key contenders lost or duplicated quota", spent, err)
		}
		accepted, limited = concurrentSharedRateResults(t, f, func(index int) string {
			return fmt.Sprintf("synthetic-full-slot-%d-%d", attempt, index)
		}, 2)
		if !currentRateWindow(t, f.admin).Equal(window) {
			continue
		}
		if accepted != 32 || limited != 0 {
			t.Fatal("full window changed admitted/not-counted semantics", accepted, limited)
		}
		var keys, counters, orphans int
		if err := f.admin.QueryRow(ctx, `SELECT keys,(SELECT count(*) FROM rate_counters WHERE family=1 AND window_start=$1),(SELECT count(*) FROM rate_counters c WHERE c.family=1 AND c.window_start=$1 AND NOT EXISTS(SELECT 1 FROM rate_windows w WHERE w.family=c.family AND w.window_start=c.window_start)) FROM rate_windows WHERE family=1 AND window_start=$1`, window).Scan(&keys, &counters, &orphans); err != nil || keys != 16384 || counters != 16384 || orphans != 0 {
			t.Fatal("concurrent admission changed cardinality or retained an orphan", keys, counters, orphans, err)
		}
		return
	}
	t.Fatal("cardinality regression could not finish within one database minute")
}

func concurrentSharedRateResults(t *testing.T, f *observabilityFixture, key func(int) string, budget int) (int, int) {
	t.Helper()
	var workers sync.WaitGroup
	results := make(chan error, 32)
	for index := range 32 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			results <- f.a.sharedRate(context.Background(), 1, key(index), budget)
		}()
	}
	workers.Wait()
	close(results)
	accepted, limited := 0, 0
	for err := range results {
		switch rateStatus(err) {
		case 200:
			accepted++
		case 429:
			limited++
		default:
			t.Fatal("unexpected concurrent quota result", err)
		}
	}
	return accepted, limited
}

func TestSharedRateConcurrentDistinctKeysKeepCardinality(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	for attempt := range 3 {
		window := currentRateWindow(t, f.admin)
		if _, err := f.admin.Exec(ctx, `DELETE FROM rate_windows WHERE family=1 AND window_start=$1`, window); err != nil {
			t.Fatal(err)
		}
		if _, err := f.admin.Exec(ctx, `INSERT INTO rate_windows(family,window_start,keys) VALUES(1,$1,16383)`, window); err != nil {
			t.Fatal(err)
		}
		if _, err := f.admin.Exec(ctx, `INSERT INTO rate_counters(family,window_start,key_hash,hits) SELECT 1,$1,sha256(convert_to('synthetic-seeded-'||n,'UTF8')),1 FROM generate_series(1,16383)n`, window); err != nil {
			t.Fatal(err)
		}
		if !currentRateWindow(t, f.admin).Equal(window) {
			continue
		}
		accepted, limited := concurrentSharedRateResults(t, f, func(index int) string {
			return fmt.Sprintf("synthetic-distinct-slot-%d-%d", attempt, index)
		}, 2)
		if !currentRateWindow(t, f.admin).Equal(window) {
			continue
		}
		if accepted != 32 || limited != 0 {
			t.Fatal("distinct contenders changed admitted/not-counted semantics", accepted, limited)
		}
		var keys, counters int
		if err := f.admin.QueryRow(ctx, `SELECT keys,(SELECT count(*) FROM rate_counters WHERE family=1 AND window_start=$1) FROM rate_windows WHERE family=1 AND window_start=$1`, window).Scan(&keys, &counters); err != nil || keys != 16384 || counters != 16384 {
			t.Fatal("distinct contenders exceeded or lost the last cardinality slot", keys, counters, err)
		}
		return
	}
	t.Fatal("distinct admission regression could not finish within one database minute")
}
