package app

import (
	"context"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

type discoveryLoadTrace struct {
	sync.Mutex
	epoch  uint64
	active bool
	stats  map[string]discoveryLoadTiming
}

type discoveryLoadTiming struct {
	count, failures int64
	total, maximum  time.Duration
}

type discoveryLoadSpan struct {
	start time.Time
	epoch uint64
	class string
}

type discoveryLoadQuerySpanKey struct{}
type discoveryLoadBatchSpanKey struct{}
type discoveryLoadAcquireSpanKey struct{}

func (trace *discoveryLoadTrace) begin() {
	trace.Lock()
	defer trace.Unlock()
	trace.epoch++
	trace.active = true
	trace.stats = make(map[string]discoveryLoadTiming)
}

func (trace *discoveryLoadTrace) span(class string) discoveryLoadSpan {
	trace.Lock()
	defer trace.Unlock()
	if !trace.active {
		return discoveryLoadSpan{}
	}
	return discoveryLoadSpan{start: time.Now(), epoch: trace.epoch, class: class}
}

func (trace *discoveryLoadTrace) finish(span discoveryLoadSpan, duration time.Duration, failed bool) {
	if span.epoch == 0 {
		return
	}
	trace.Lock()
	defer trace.Unlock()
	if !trace.active || span.epoch != trace.epoch {
		return
	}
	metric := trace.stats[span.class]
	metric.count++
	metric.total += duration
	if duration > metric.maximum {
		metric.maximum = duration
	}
	if failed {
		metric.failures++
	}
	trace.stats[span.class] = metric
}

// Static categories keep storage and output bounded. Neither SQL text nor its
// parameters, error details, identities or connection strings are retained.
func discoveryLoadQueryClass(sql string) string {
	switch {
	case strings.HasPrefix(sql, "SELECT consume_rate_budget("):
		return "rate"
	case strings.HasPrefix(sql, "SELECT granted,valid_for_ms FROM reserve_rate_budget("):
		return "reserve_rate"
	case strings.HasPrefix(sql, "SELECT organization_id,device_id FROM device_identity("):
		return "device_identity"
	case strings.HasPrefix(sql, "SELECT set_config("):
		return "tenant_context"
	case strings.HasPrefix(sql, "SELECT pg_advisory_"):
		return "barrier"
	case strings.HasPrefix(sql, "SELECT status FROM devices"):
		return "live_device"
	case strings.HasPrefix(sql, "SELECT revision,configuration FROM discovery_settings"):
		return "discovery_settings"
	case strings.HasPrefix(sql, "SELECT content FROM discovery_catalogs"):
		return "discovery_catalog"
	case strings.HasPrefix(sql, "SELECT revision,configuration,inherit_sections FROM shadow_settings"):
		return "shadow_settings"
	case strings.HasPrefix(sql, "SELECT group_id,group_revision FROM devices"):
		return "device_group"
	case strings.HasPrefix(sql, "SELECT revision,configuration FROM shadow_device_overrides"):
		return "device_override"
	case strings.HasPrefix(sql, "SELECT revision,fingerprint FROM discovery_device_authorizations"):
		return "delivery_authorization"
	case strings.HasPrefix(sql, "WITH\n e AS"):
		return "capacity"
	case strings.HasPrefix(sql, "WITH RECURSIVE identification_keys AS"):
		return "applications_page"
	case strings.Contains(sql, "INSERT INTO discovery_identifications("):
		return "identification_write"
	case strings.Contains(sql, "INSERT INTO discovery_communications("):
		return "communication_write"
	case strings.HasPrefix(sql, "INSERT INTO discovery_entities("):
		return "entity_write"
	case strings.HasPrefix(sql, "INSERT INTO discovery_relations("):
		return "relation_write"
	case strings.HasPrefix(sql, "INSERT INTO discovery_coverage("):
		return "coverage_write"
	case strings.Contains(sql, "discovery_scans"):
		return "scan_ledger"
	case sql == "begin" || strings.HasPrefix(sql, "begin "):
		return "begin"
	case sql == "commit":
		return "commit"
	case sql == "rollback":
		return "rollback"
	default:
		return "other"
	}
}

func (trace *discoveryLoadTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, discoveryLoadQuerySpanKey{}, trace.span("query:"+discoveryLoadQueryClass(data.SQL)))
}
func (trace *discoveryLoadTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	if span, ok := ctx.Value(discoveryLoadQuerySpanKey{}).(discoveryLoadSpan); ok {
		trace.finish(span, time.Since(span.start), data.Err != nil)
	}
}
func (trace *discoveryLoadTrace) TraceAcquireStart(ctx context.Context, _ *pgxpool.Pool, _ pgxpool.TraceAcquireStartData) context.Context {
	return context.WithValue(ctx, discoveryLoadAcquireSpanKey{}, trace.span("pool_acquire"))
}
func (trace *discoveryLoadTrace) TraceAcquireEnd(ctx context.Context, _ *pgxpool.Pool, data pgxpool.TraceAcquireEndData) {
	if span, ok := ctx.Value(discoveryLoadAcquireSpanKey{}).(discoveryLoadSpan); ok {
		trace.finish(span, time.Since(span.start), data.Err != nil)
	}
}
func (trace *discoveryLoadTrace) TraceBatchStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceBatchStartData) context.Context {
	class := "batch:other"
	if len(data.Batch.QueuedQueries) > 0 {
		first := data.Batch.QueuedQueries[0].SQL
		if strings.HasPrefix(first, "DELETE FROM discovery_entities ") {
			class = "batch:expiry"
		}
		if strings.HasPrefix(first, "INSERT INTO discovery_entities(") {
			class = "batch:store"
		}
	}
	return context.WithValue(ctx, discoveryLoadBatchSpanKey{}, trace.span(class))
}
func (trace *discoveryLoadTrace) TraceBatchQuery(ctx context.Context, _ *pgx.Conn, data pgx.TraceBatchQueryData) {
	if span, ok := ctx.Value(discoveryLoadBatchSpanKey{}).(discoveryLoadSpan); ok {
		// PGX supplies no per-statement start time: count responses without
		// pretending this is a server execution-time measurement.
		span.class = "batch_statement_count:" + discoveryLoadQueryClass(data.SQL)
		trace.finish(span, 0, data.Err != nil)
	}
}
func (trace *discoveryLoadTrace) TraceBatchEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceBatchEndData) {
	if span, ok := ctx.Value(discoveryLoadBatchSpanKey{}).(discoveryLoadSpan); ok {
		trace.finish(span, time.Since(span.start), data.Err != nil)
	}
}

func (trace *discoveryLoadTrace) logFailure(t *testing.T) {
	t.Helper()
	if !t.Failed() {
		return
	}
	trace.Lock()
	snapshot := make(map[string]discoveryLoadTiming, len(trace.stats))
	for key, value := range trace.stats {
		snapshot[key] = value
	}
	trace.Unlock()
	keys := make([]string, 0, len(snapshot))
	for key := range snapshot {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	t.Log("Stage wall timings overlap across concurrent requests; they are not CPU time or additive components of workload wall time. Event-slot waiting before pool acquisition is not traced.")
	for _, key := range keys {
		value := snapshot[key]
		t.Logf("load stage=%s count=%d total=%s max=%s errors=%d", key, value.count, value.total, value.maximum, value.failures)
	}
}

// Install only for an isolated, non-parallel load profile. Do not initialize the
// lazy runtime here: its first real caller must still own the compilation cost.
func instrumentDiscoveryLoadWASM(t *testing.T, trace *discoveryLoadTrace) {
	t.Helper()
	original := sharedDiscoveryRuntime
	sharedDiscoveryRuntime = func() (*dlpRuntime, error) {
		span := trace.span("wasm:runtime")
		base, err := original()
		trace.finish(span, time.Since(span.start), err != nil)
		if err != nil {
			return base, err
		}
		copy := *base
		copy.runtime = &discoveryLoadWASMRuntime{Runtime: base.runtime, trace: trace}
		return &copy, nil
	}
	// Register before constructing the App: LIFO cleanup restores the factory
	// only after the App, its workers and its runtime DB pool have closed.
	t.Cleanup(func() { sharedDiscoveryRuntime = original })
}

type discoveryLoadWASMRuntime struct {
	wazero.Runtime
	trace *discoveryLoadTrace
}

func (runtime *discoveryLoadWASMRuntime) InstantiateModule(ctx context.Context, compiled wazero.CompiledModule, config wazero.ModuleConfig) (api.Module, error) {
	span := runtime.trace.span("wasm:instantiate")
	module, err := runtime.Runtime.InstantiateModule(ctx, compiled, config)
	runtime.trace.finish(span, time.Since(span.start), err != nil)
	if module == nil {
		return module, err
	}
	return &discoveryLoadWASMModule{Module: module, trace: runtime.trace}, err
}

type discoveryLoadWASMModule struct {
	api.Module
	trace *discoveryLoadTrace
}

func (module *discoveryLoadWASMModule) ExportedFunction(name string) api.Function {
	function := module.Module.ExportedFunction(name)
	if function == nil {
		return nil
	}
	class := ""
	switch name {
	case "discovery_alloc":
		class = "wasm:alloc"
	case "discovery_call":
		class = "wasm:ordinary_call"
	case "discovery_call_prevalidated_report":
		class = "wasm:prevalidated_report"
	default:
		return function
	}
	return &discoveryLoadWASMFunction{Function: function, trace: module.trace, class: class}
}

func (module *discoveryLoadWASMModule) Close(ctx context.Context) error {
	span := module.trace.span("wasm:close")
	err := module.Module.Close(ctx)
	module.trace.finish(span, time.Since(span.start), err != nil)
	return err
}

type discoveryLoadWASMFunction struct {
	api.Function
	trace *discoveryLoadTrace
	class string
}

func (function *discoveryLoadWASMFunction) Call(ctx context.Context, args ...uint64) ([]uint64, error) {
	span := function.trace.span(function.class)
	values, err := function.Function.Call(ctx, args...)
	function.trace.finish(span, time.Since(span.start), err != nil)
	return values, err
}

func (function *discoveryLoadWASMFunction) CallWithStack(ctx context.Context, stack []uint64) error {
	span := function.trace.span(function.class)
	err := function.Function.CallWithStack(ctx, stack)
	function.trace.finish(span, time.Since(span.start), err != nil)
	return err
}

var _ wazero.Runtime = (*discoveryLoadWASMRuntime)(nil)
var _ api.Module = (*discoveryLoadWASMModule)(nil)
var _ api.Function = (*discoveryLoadWASMFunction)(nil)
