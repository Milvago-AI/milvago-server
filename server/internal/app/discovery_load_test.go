package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// A failed backend must end a measured run instead of producing fast error
// responses for the rest of its scheduled duration.
type discoveryLoadAbort struct {
	once sync.Once
	done chan struct{}
}

func newDiscoveryLoadAbort() *discoveryLoadAbort {
	return &discoveryLoadAbort{done: make(chan struct{})}
}

func (a *discoveryLoadAbort) fail() bool {
	first := false
	a.once.Do(func() { first = true; close(a.done) })
	return first
}

func (a *discoveryLoadAbort) waitUntil(offered time.Time) bool {
	if delay := time.Until(offered); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-a.done:
			return false
		case <-timer.C:
		}
	}
	select {
	case <-a.done:
		return false
	default:
		return true
	}
}

func TestDiscoveryLoadAbortStopsWaitingAndConcurrentFailures(t *testing.T) {
	abort := newDiscoveryLoadAbort()
	defer abort.fail()
	if !abort.waitUntil(time.Now().Add(-time.Second)) {
		t.Fatal("healthy arrival was lost")
	}
	result := make(chan bool, 1)
	go func() { result <- abort.waitUntil(time.Now().Add(time.Hour)) }()
	winners := make(chan bool, 64)
	var clients sync.WaitGroup
	for range 64 {
		clients.Add(1)
		go func() { defer clients.Done(); winners <- abort.fail() }()
	}
	clients.Wait()
	close(winners)
	count := 0
	for first := range winners {
		if first {
			count++
		}
	}
	if count != 1 || abort.waitUntil(time.Now().Add(-time.Second)) {
		t.Fatal("failed workload accepted a new arrival or multiple first failures")
	}
	select {
	case accepted := <-result:
		if accepted {
			t.Fatal("failure did not interrupt the waiting generator")
		}
	case <-time.After(time.Second):
		t.Fatal("failed workload retained a waiting generator")
	}
}

// This bounded smoke profile measures the real HTTP handler, WASM validator,
// authorization and PostgreSQL commit. It is deliberately separate from the
// reference-hardware qualification. Long endurance is deliberately out of scope.
func TestDiscoveryLoadSmoke(t *testing.T) {
	runDiscoveryLoadSmoke(t, 1000, 100, false)
}

// Ten thousand identities, not agents. Keep the object/history volume bounded
// for the single development host while exercising each device's policy path.
func TestDiscoveryLoadFleetSmoke(t *testing.T) {
	runDiscoveryLoadSmoke(t, 10000, 10, false)
}

// Start at the volume reached by the peak, so a short smoke also exercises
// the expensive refresh before spending fifteen minutes on the measured run.
func TestDiscoveryLoadFleetDenseSmoke(t *testing.T) {
	runDiscoveryLoadSmoke(t, 10000, 100, false)
}

// A fifteen-minute x3 peak on the bounded local fixture. This measures a longer
// resource sample, without claiming the separate reference-hardware profile.
func TestDiscoveryLoadFleetPeak(t *testing.T) {
	if os.Getenv("MILVAGO_DISCOVERY_PEAK_15M") != "1" {
		t.Skip("requires the explicit fifteen-minute isolated peak fixture")
	}
	runDiscoveryLoadProfile(t, 10000, 10, false, nil, 900)
}

func TestDiscoveryLoadFleetHistoricalSmoke(t *testing.T) {
	runDiscoveryHistoricalWorkload(t, 20)
}

func TestDiscoveryLoadFleetHistoricalPeak(t *testing.T) {
	if os.Getenv("MILVAGO_DISCOVERY_PEAK_15M") != "1" {
		t.Skip("requires the explicit fifteen-minute isolated peak fixture")
	}
	runDiscoveryHistoricalWorkload(t, 900)
}

func runDiscoveryHistoricalWorkload(t *testing.T, peakSeconds int) {
	if os.Getenv("MILVAGO_DISCOVERY_HISTORY_10M") != "1" {
		t.Skip("requires the explicit ten-million-event isolated history fixture")
	}
	// Keep the full workload while measuring the actual bounded local hardware.
	// Existing current-state rows contribute the remaining one million events.
	seed := func(f *observabilityFixture) {
		ctx := context.Background()
		for first := 100; first < 1000; first += 100 {
			if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_events(organization_id,device_id,scope,entity_id,kind,application_id)
				SELECT $1,d.id,'endpoint','process/'||n,'identified','openclaw'
				FROM devices d CROSS JOIN generate_series($2::integer,$3::integer)n
				WHERE d.organization_id=$1 AND d.id::text LIKE '00000000-0000-4000-8000-%'`, f.org, first, first+99); err != nil {
				t.Fatal(err)
			}
			t.Logf("Prepared %d/9 million historical events", first/100)
		}
	}
	runDiscoveryLoadProfile(t, 10000, 100, false, seed, peakSeconds)
}

func TestDiscoveryLoadDNSHintsSmoke(t *testing.T) {
	runDiscoveryLoadSmoke(t, 1000, 100, true)
}

func runDiscoveryLoadSmoke(t *testing.T, fleet, objectsPerDevice int, dnsHints bool) {
	runDiscoveryLoadSmokeWithSeed(t, fleet, objectsPerDevice, dnsHints, nil)
}

func runDiscoveryLoadSmokeWithSeed(t *testing.T, fleet, objectsPerDevice int, dnsHints bool, seed func(*observabilityFixture)) {
	runDiscoveryLoadProfile(t, fleet, objectsPerDevice, dnsHints, seed, 20)
}

func runDiscoveryLoadProfile(t *testing.T, fleet, objectsPerDevice int, dnsHints bool, seed func(*observabilityFixture), peakSeconds int) {
	if os.Getenv("MILVAGO_DISCOVERY_LOAD_SMOKE") != "1" {
		t.Skip("separate required load smoke: MILVAGO_DISCOVERY_LOAD_SMOKE=1 with an isolated test database")
	}
	f := newObservabilityFixture(t)
	t.Logf("RESOURCE PROFILE: CPUs=%d GOMAXPROCS=%d runtime_pool=%d ingest_slots=%d WASM_slots=4", runtime.NumCPU(), runtime.GOMAXPROCS(0), f.a.db.Config().MaxConns, max(1, int(f.a.db.Config().MaxConns)-2))
	ctx := context.Background()
	type device struct {
		ID         string `json:"id"`
		Credential string `json:"credential"`
		Revision   int64  `json:"-"`
		Peer       string `json:"-"`
	}
	devices := make([]device, fleet)
	for n := range devices {
		devices[n] = device{ID: fmt.Sprintf("00000000-0000-4000-8000-%012d", n+1), Credential: randomToken(), Peer: fmt.Sprintf("10.%d.%d.%d:40000", (n+1)>>16, ((n+1)>>8)&255, (n+1)&255)}
	}
	records := []map[string]string{}
	for _, d := range devices {
		records = append(records, map[string]string{"id": d.ID, "credential_hash": hex.EncodeToString(hash(d.Credential))})
	}
	raw, _ := json.Marshal(records)
	if _, err := f.admin.Exec(ctx, `INSERT INTO devices(organization_id,id,credential_hash,hostname,platform,version,status,kind,capabilities) SELECT $1,id::uuid,decode(credential_hash,'hex'),'Synthetic load host','test','0.7.0','approved','browser','["discovery-v1"]' FROM jsonb_to_recordset($2) x(id text,credential_hash text)`, f.org, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO discovery_settings(organization_id,revision,configuration) VALUES($1,1,'{"host":true,"containers":false,"virtual_machines":false,"guest_read":false,"guest_execute":false,"http":false,"network":false,"interval_seconds":300}')`, f.org); err != nil {
		t.Fatal(err)
	}
	if dnsHints {
		if _, err := f.admin.Exec(ctx, `UPDATE discovery_settings SET configuration=jsonb_set(configuration,'{network}','true') WHERE organization_id=$1`, f.org); err != nil {
			t.Fatal(err)
		}
	}
	call := func(d device, path string, body any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		method := "POST"
		if body == nil {
			method = "GET"
		}
		request := httptest.NewRequest(method, path, bytes.NewReader(raw))
		// Model distinct socket peers. Sharing httptest's default address would
		// measure the 6,000/minute single-peer abuse guard during preparation.
		// The actual handler and its peer/global/device limits remain enabled.
		request.RemoteAddr = d.Peer
		request.Header.Set("Authorization", "Bearer "+d.Credential)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		f.a.Handler().ServeHTTP(response, request)
		return response
	}
	if seed != nil {
		seed(f)
	}
	// Preparation is sequential and bounded by the fleet. Artificial pacing here
	// would add ten minutes to the five profiles before the measured arrivals.
	for n := range devices {
		response := call(devices[n], "/v1/discovery/policy", nil)
		requireHTTP(t, response, 200)
		var signed struct {
			Payload string `json:"payload"`
		}
		if json.Unmarshal(response.Body.Bytes(), &signed) != nil {
			t.Fatal("invalid policy")
		}
		payload, _ := base64.StdEncoding.DecodeString(signed.Payload)
		var policy struct {
			Revision int64 `json:"revision"`
		}
		if json.Unmarshal(payload, &policy) != nil || policy.Revision == 0 {
			t.Fatal("missing policy revision")
		}
		devices[n].Revision = policy.Revision
		if (n+1)%1000 == 0 {
			t.Logf("Prepared %d/%d synthetic device identities; no agents installed", n+1, fleet)
		}
	}
	for _, query := range []string{
		`INSERT INTO discovery_entities(organization_id,device_id,scope,id,kind,sequence) SELECT $1,d.id,'endpoint','process/'||n,'process',1 FROM devices d CROSS JOIN generate_series(0,$2::integer)n WHERE d.organization_id=$1 AND d.id::text LIKE '00000000-0000-4000-8000-%'`,
		`INSERT INTO discovery_identifications(organization_id,device_id,scope,entity_id,application_id,signature_id,signature_revision,state,evidence,sequence) SELECT $1,d.id,'endpoint','process/'||n,'openclaw','openclaw.process',1,'executed','[]',1 FROM devices d CROSS JOIN generate_series(0,$2::integer)n WHERE d.organization_id=$1 AND d.id::text LIKE '00000000-0000-4000-8000-%'`,
		`INSERT INTO discovery_events(organization_id,device_id,scope,entity_id,kind,application_id) SELECT $1,d.id,'endpoint','process/'||n,'identified','openclaw' FROM devices d CROSS JOIN generate_series(0,$2::integer)n WHERE d.organization_id=$1 AND d.id::text LIKE '00000000-0000-4000-8000-%'`,
	} {
		if _, err := f.admin.Exec(ctx, query, f.org, objectsPerDevice-1); err != nil {
			t.Fatal(err)
		}
	}
	// Bulk fixture inserts need planner statistics before the first aggregate.
	for _, table := range []string{"devices", "discovery_entities", "discovery_identifications", "discovery_events"} {
		if _, err := f.admin.Exec(ctx, "ANALYZE "+table); err != nil {
			t.Fatal(err)
		}
	}
	historicalRows := int64(fleet * objectsPerDevice)
	readPaths := []string{"/api/discovery/applications?limit=50"}
	if os.Getenv("MILVAGO_DISCOVERY_HISTORY_10M") == "1" {
		for table, expected := range map[string]int64{
			"devices": int64(fleet), "discovery_entities": int64(fleet * objectsPerDevice),
			"discovery_identifications": int64(fleet * objectsPerDevice), "discovery_events": int64(fleet * 1000),
		} {
			var count int64
			if err := f.admin.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE organization_id=$1", f.org).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != expected {
				t.Fatalf("historical workload %s: got %d, want %d", table, count, expected)
			}
			if table == "discovery_events" {
				historicalRows = count
			}
			t.Logf("Verified workload %s: %d rows", table, count)
		}
		readPaths = append(readPaths, "/api/discovery/applications/openclaw/instances?limit=50",
			"/api/discovery/applications/openclaw/locations?limit=50", "/api/discovery/events?limit=50",
			"/api/discovery/coverage?limit=50", "/api/discovery/environments?limit=50")
	}
	// Warm lazy DB/WASM/cache resources before comparing bounded resource use.
	for _, path := range readPaths {
		requireHTTP(t, f.call("GET", path, nil, ""), 200)
	}
	runtime.GC()
	var memoryBefore runtime.MemStats
	runtime.ReadMemStats(&memoryBefore)
	goroutinesBefore := runtime.NumGoroutine()
	fdBefore, _ := os.ReadDir("/proc/self/fd")
	entities := []any{}
	matches := []any{}
	observed := time.Now().Unix()
	for n := 0; n < 100; n++ {
		id := "process/" + strconv.Itoa(n)
		entities = append(entities, map[string]any{"id": id, "kind": "process"})
		matches = append(matches, map[string]any{"entity_id": id, "application_id": "openclaw", "signature_id": "openclaw.process", "signature_revision": 1, "state": "executed", "evidence": []any{map[string]any{"fact_id": "fact/" + strconv.Itoa(n), "source": "host_process", "observed_at": observed, "fields": []string{"executable"}}}})
	}
	queries := []any{}
	if dnsHints {
		entities = append(entities, map[string]any{"id": "host/dns", "kind": "host"})
		for _, provider := range []string{"openai", "anthropic", "google", "mistral"} {
			queries = append(queries, map[string]any{"entity_id": "host/dns", "provider": provider, "evidence": map[string]any{"fact_id": "fact/dns-" + provider, "source": "host_dns_query", "observed_at": observed, "fields": []string{"remote_host"}}})
		}
	}
	type job struct {
		index    int
		sequence int64
		offered  time.Time
	}
	// Absorb a brief client scheduler pause at the 99/s spike without losing
	// arrivals. This queue is bounded at under one second of peak traffic;
	// latency still includes the original arrival time and must meet the SLO.
	work := make(chan job, 64)
	abort := newDiscoveryLoadAbort()
	var workers sync.WaitGroup
	var mutex sync.Mutex
	acknowledged := map[string]int64{}
	var ingest, ingestSlow, failed, reads, readSlow500, readSlow1000 int
	responseCodes := map[int]int{}
	ingestCodes := map[int]int{}
	readCodes := map[int]int{}
	rejectedAdmission := 0
	var serviceTimes, queueTimes []time.Duration
	// Independent agents are concurrent clients. Four serial clients would cap
	// the generator at 4 / handler latency before the server's own admission.
	// Keep both the client concurrency and queue bounded; WASM remains capped at 4.
	// At 99 arrivals/s a 200 ms handler needs at least 20 concurrent clients.
	// Bound the generator at 32 so it does not impose its own lower throughput.
	for n := 0; n < 32; n++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for job := range work {
				d := devices[job.index]
				report := map[string]any{"version": 1, "catalog_revision": discoveryFixtureCatalogRevision, "settings_revision": d.Revision, "run_id": nil, "scope": "endpoint", "sequence": job.sequence, "page": 0, "pages": 1, "observed_at": time.Now().Unix(), "complete": false, "entities": entities, "relations": []any{}, "coverage": []any{}, "result": map[string]any{"identifications": matches, "communications": []any{}, "queries": queries, "evaluated_facts": 100, "unknown_conditions": 0}}
				start := time.Now()
				response := call(d, "/v1/discovery/reports", report)
				elapsed := time.Since(start)
				mutex.Lock()
				serviceTimes = append(serviceTimes, elapsed)
				queueTimes = append(queueTimes, start.Sub(job.offered))
				ingest++
				if time.Since(job.offered) >= time.Second {
					ingestSlow++
				}
				if response.Code != 200 {
					failed++
					responseCodes[response.Code]++
					ingestCodes[response.Code]++
					if abort.fail() {
						t.Logf("first workload failure: ingest HTTP %d; stop scheduling", response.Code)
					}
				} else if job.sequence > acknowledged[d.ID] {
					acknowledged[d.ID] = job.sequence
				}
				mutex.Unlock()
			}
		}()
	}
	stop := make(chan struct{})
	readPathCounts, readPathSlow500, readPathSlow1000 := map[string]int{}, map[string]int{}, map[string]int{}
	readPathFailures := map[string]map[int]int{}
	var readers sync.WaitGroup
	people := discoveryLoadReaders(t, f, 100)
	// Each real synthetic person reads once every ten seconds; quotas stay active.
	for n := 0; n < 10; n++ {
		readers.Add(1)
		go func(first int) {
			defer readers.Done()
			turn := first
			personIndex := first
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-stop:
					return
				case <-abort.done:
					return
				case <-ticker.C:
					start := time.Now()
					path := readPaths[turn%len(readPaths)]
					turn++
					person := people[personIndex]
					personIndex = (personIndex + 10) % len(people)
					response := person.call("GET", path, nil, "")
					elapsed := time.Since(start)
					mutex.Lock()
					reads++
					readPathCounts[path]++
					if elapsed >= 500*time.Millisecond {
						readPathSlow500[path]++
					}
					if elapsed >= time.Second {
						readPathSlow1000[path]++
					}
					if elapsed >= 500*time.Millisecond {
						readSlow500++
					}
					if elapsed >= time.Second {
						readSlow1000++
					}
					if response.Code != 200 {
						failed++
						responseCodes[response.Code]++
						readCodes[response.Code]++
						if readPathFailures[path] == nil {
							readPathFailures[path] = map[int]int{}
						}
						readPathFailures[path][response.Code]++
						if abort.fail() {
							t.Logf("first workload failure: interactive HTTP %d route=%s elapsed=%s; stop scheduling", response.Code, path, elapsed)
						}
					}
					mutex.Unlock()
				}
			}
		}(n)
	}
	sent := 0
	sequence := time.Now().UnixMilli()
	rates := []int{33, 33, 33}
	if fleet == 10000 {
		rates[1] = 99 // Short x3 spike, followed by recovery at the nominal rate.
	}
	minimumOffered := 0
	cpuBefore := discoveryLoadCPUStats()
	measurementStarted := time.Now()
phases:
	for phase, rate := range rates {
		seconds := 20
		if phase == 1 {
			seconds = peakSeconds
		}
		phaseStarted := time.Now()
		mutex.Lock()
		serviceFrom, queueFrom, rejectedFrom := len(serviceTimes), len(queueTimes), rejectedAdmission
		mutex.Unlock()
		minimumOffered += rate * seconds
		// Absolute arrival times retain every offered request when the scheduler
		// is briefly delayed. Ticker drops would otherwise hide generator loss.
		for arrival := 0; arrival < rate*seconds; arrival++ {
			offered := phaseStarted.Add(time.Duration(arrival+1) * time.Second / time.Duration(rate))
			if !abort.waitUntil(offered) {
				break phases
			}
			if arrival > 0 && arrival%(rate*60) == 0 {
				var sample runtime.MemStats
				runtime.ReadMemStats(&sample)
				fds, _ := os.ReadDir("/proc/self/fd")
				t.Logf("resource sample phase=%d second=%d: heap=%d bytes goroutines=%d fd=%d", phase+1, arrival/rate, sample.HeapAlloc, runtime.NumGoroutine(), len(fds))
			}
			select {
			case work <- job{index: sent % fleet, sequence: sequence + int64(sent), offered: offered}:
				sent++
			default:
				mutex.Lock()
				failed++
				rejectedAdmission++
				if abort.fail() {
					t.Log("first workload failure: admission rejected; stop scheduling")
				}
				mutex.Unlock()
			}
		}
		mutex.Lock()
		services := append([]time.Duration(nil), serviceTimes[serviceFrom:]...)
		queues := append([]time.Duration(nil), queueTimes[queueFrom:]...)
		rejections := rejectedAdmission - rejectedFrom
		mutex.Unlock()
		sort.Slice(services, func(i, j int) bool { return services[i] < services[j] })
		sort.Slice(queues, func(i, j int) bool { return queues[i] < queues[j] })
		if len(services) > 0 {
			t.Logf("phase %d: offered %d/s for %s; completed %d; handler p95=%s max=%s; generator queue p95=%s max=%s; pending=%d; rejected=%d", phase+1, rate, time.Since(phaseStarted), len(services), services[(len(services)-1)*95/100], services[len(services)-1], queues[(len(queues)-1)*95/100], queues[len(queues)-1], len(work), rejections)
		}
	}
	close(work)
	workers.Wait()
	close(stop)
	readers.Wait()
	cpuAfter := discoveryLoadCPUStats()
	quota, _ := os.ReadFile("/sys/fs/cgroup/cpu.max")
	t.Logf("application CPU: quota=%q wall=%s usage=%s throttled=%s throttled periods=%d/%d", strings.TrimSpace(string(quota)), time.Since(measurementStarted), time.Duration(cpuAfter["usage_usec"]-cpuBefore["usage_usec"])*time.Microsecond, time.Duration(cpuAfter["throttled_usec"]-cpuBefore["throttled_usec"])*time.Microsecond, cpuAfter["nr_throttled"]-cpuBefore["nr_throttled"], cpuAfter["nr_periods"]-cpuBefore["nr_periods"])
	t.Logf("BOUNDED LOCAL PROFILE: %d devices, %d seeded current objects, %d seeded historical rows, 100 facts per report; peak=%ds; %d ingest responses, %d interactive reads, %d failures", fleet, fleet*objectsPerDevice, historicalRows, peakSeconds, ingest, reads, failed)
	t.Logf("admission rejected=%d, HTTP errors=%v, ingest >=1s=%d, reads >=500ms=%d >=1s=%d", rejectedAdmission, responseCodes, ingestSlow, readSlow500, readSlow1000)
	t.Logf("HTTP errors by operation: ingest=%v reads=%v", ingestCodes, readCodes)
	t.Logf("interactive failures by route=%v", readPathFailures)
	if !abort.waitUntil(time.Now()) {
		t.Error("load profile aborted after first HTTP failure or rejected admission; capacity is not qualified")
		return
	}
	verifyDiscoveryLoadReaderAdmission(t, f, people)
	t.Logf("interactive route counts=%v slow500ms=%v slow1s=%v", readPathCounts, readPathSlow500, readPathSlow1000)
	for _, path := range readPaths {
		count := readPathCounts[path]
		if count == 0 || readPathSlow500[path]*100 > count*5 || readPathSlow1000[path]*100 > count {
			t.Errorf("interactive route latency target failed: %s count=%d slow500ms=%d slow1s=%d", path, count, readPathSlow500[path], readPathSlow1000[path])
		}
	}

	if failed != 0 {
		t.Errorf("load smoke lost admission or returned errors: %d", failed)
	}
	if ingest < minimumOffered-80 {
		t.Errorf("offered nominal rate was not maintained: %d requests", ingest)
	}
	if ingestSlow*100 > ingest*5 {
		t.Errorf("ingest p95 exceeded one second: %d/%d", ingestSlow, ingest)
	}
	if reads == 0 || readSlow500*100 > reads*5 || readSlow1000*100 > reads {
		t.Errorf("interactive latency targets failed: >=500ms %d, >=1s %d, total %d", readSlow500, readSlow1000, reads)
	}
	rows, err := f.admin.Query(ctx, `SELECT device_id::text,sequence,finalized FROM discovery_scans WHERE organization_id=$1`, f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var stored int64
		var finalized bool
		if err = rows.Scan(&id, &stored, &finalized); err != nil {
			t.Fatal(err)
		}
		if minimum, ok := acknowledged[id]; ok {
			if stored < minimum || !finalized {
				t.Fatal("acknowledged page was not durable")
			}
			delete(acknowledged, id)
		}
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(acknowledged) != 0 {
		t.Fatal("acknowledged device scans are missing", len(acknowledged))
	}
	rows.Close()
	if dnsHints {
		var queries, contacts int
		if err := f.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM discovery_events WHERE organization_id=$1 AND kind='provider_domain_queried'),(SELECT count(*) FROM discovery_communications WHERE organization_id=$1)`, f.org).Scan(&queries, &contacts); err != nil || queries != 4*min(fleet, sent) || contacts != 0 {
			t.Fatal("DNS load deduplication/contact separation", queries, contacts, err)
		}
		t.Logf("DNS load: %d daily provider hints retained; repeated requests created no contacts", queries)
	}
	// This is a short regression bound, not a proof of long-term leak freedom.
	runtime.GC()
	var memoryAfter runtime.MemStats
	runtime.ReadMemStats(&memoryAfter)
	fdAfter, _ := os.ReadDir("/proc/self/fd")
	goroutinesAfter := runtime.NumGoroutine()
	t.Logf("short resource sample: live heap %d -> %d bytes; goroutines %d -> %d; FD %d -> %d", memoryBefore.HeapAlloc, memoryAfter.HeapAlloc, goroutinesBefore, goroutinesAfter, len(fdBefore), len(fdAfter))
	if memoryAfter.HeapAlloc > memoryBefore.HeapAlloc+128*1024*1024 || goroutinesAfter > goroutinesBefore+32 || len(fdAfter) > len(fdBefore)+32 {
		t.Fatal("short load exceeded bounded retained resources")
	}
}

func discoveryLoadCPUStats() map[string]int64 {
	out := map[string]int64{}
	raw, err := os.ReadFile("/sys/fs/cgroup/cpu.stat")
	if err != nil || len(raw) > 4096 {
		return out
	}
	fields := strings.Fields(string(raw))
	for n := 0; n+1 < len(fields); n += 2 {
		value, err := strconv.ParseInt(fields[n+1], 10, 64)
		if err == nil {
			out[fields[n]] = value
		}
	}
	return out
}
