package app

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type readerFromRecorder struct {
	*httptest.ResponseRecorder
	called bool
}

func (w *readerFromRecorder) ReadFrom(r io.Reader) (int64, error) {
	w.called = true
	return io.Copy(w.ResponseRecorder, r)
}

func testMetricsApp(token string) *App {
	a := &App{config: Config{MetricsToken: token}, mux: http.NewServeMux()}
	a.registerMetrics()
	a.mux.HandleFunc("GET /items/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return a
}

func TestMetricsResponseWriterPreservesReaderFrom(t *testing.T) {
	base := &readerFromRecorder{ResponseRecorder: httptest.NewRecorder()}
	w := &metricsResponseWriter{ResponseWriter: base, status: http.StatusOK}
	n, err := w.ReadFrom(strings.NewReader("payload"))
	if err != nil || n != int64(len("payload")) {
		t.Fatalf("ReadFrom = %d, %v", n, err)
	}
	if !base.called || base.Body.String() != "payload" || w.status != http.StatusOK {
		t.Fatalf("ReaderFrom delegation = called:%t body:%q status:%d", base.called, base.Body.String(), w.status)
	}
}

// scrape reads /metrics with the token the app was built with. Every test that
// wants the counters has to present one, because an unconfigured token now means
// the route is off.
func scrape(h http.Handler, token string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	h.ServeHTTP(w, r)
	return w
}

func TestMetricsExposeAndNormalizeRoutes(t *testing.T) {
	a := testMetricsApp("metrics-token")
	h := a.Handler()
	for _, path := range []string{"/items/first", "/items/second"} {
		r := httptest.NewRequest(http.MethodGet, path+"?secret=hidden", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusNoContent {
			t.Fatalf("%s status = %d", path, w.Code)
		}
	}
	w := scrape(h, "metrics-token")
	if w.Code != http.StatusOK {
		t.Fatalf("metrics status = %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"milvago_http_requests_total{method=\"GET\",route=\"GET /items/{id}\",status=\"204\"} 2",
		"milvago_http_request_duration_seconds",
		"milvago_pg_pool_total_connections 0",
		"# TYPE milvago_pg_pool_acquire_total counter",
		"milvago_pg_pool_acquire_total 0",
		"# TYPE milvago_pg_pool_acquire_duration_seconds_total counter",
		"milvago_pg_pool_acquire_duration_seconds_total 0",
		"# TYPE milvago_pg_pool_empty_acquire_total counter",
		"milvago_pg_pool_empty_acquire_total 0",
		"# TYPE milvago_pg_pool_canceled_acquire_total counter",
		"milvago_pg_pool_canceled_acquire_total 0",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics missing %q", want)
		}
	}
	for _, forbidden := range []string{"route=\"GET /items/first\"", "route=\"GET /items/second\"", "secret=hidden"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("metrics contain raw request value %q", forbidden)
		}
	}
}

// An unconfigured token closes the route rather than opening it, and answers 404
// so that nothing advertises the endpoint's existence.
func TestMetricsClosedWithoutToken(t *testing.T) {
	h := testMetricsApp("").Handler()
	for _, authorization := range []string{"", "Bearer anything", "Bearer "} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		r.Header.Set("Authorization", authorization)
		h.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Fatalf("authorization %q status = %d, wanted 404", authorization, w.Code)
		}
		if strings.Contains(w.Body.String(), "milvago_") || w.Header().Get("WWW-Authenticate") != "" {
			t.Fatalf("a closed metrics route disclosed itself: %q %q", w.Body.String(), w.Header().Get("WWW-Authenticate"))
		}
	}
	// The guard inside the comparison is independent of the handler's.
	if metricTokenAllowed("Bearer anything", "") || metricTokenAllowed("", "") {
		t.Fatal("an empty configured token must authorize nothing")
	}
	// Health probes stay reachable: they are how the orchestrator schedules.
	for _, path := range []string{"/health", "/healthz", "/health/live", "/readyz"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code == http.StatusNotFound {
			t.Fatalf("%s was closed along with the metrics route", path)
		}
	}
}

func TestMetricsToken(t *testing.T) {
	a := testMetricsApp("metrics-token")
	h := a.Handler()
	for _, authorization := range []string{"", "Bearer wrong"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		r.Header.Set("Authorization", authorization)
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("authorization %q status = %d", authorization, w.Code)
		}
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.Header.Set("Authorization", "Bearer metrics-token")
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "# HELP milvago_pg_pool_total_connections") {
		t.Fatalf("authorized metrics response = %d %q", w.Code, w.Body.String())
	}
}

func TestHealthAliases(t *testing.T) {
	a := testMetricsApp("")
	h := a.Handler()
	for _, path := range []string{"/health/live", "/healthz"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "\"status\":\"live\"") {
			t.Fatalf("%s = %d %q", path, w.Code, w.Body.String())
		}
	}
	for _, path := range []string{"/health", "/readyz"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "\"status\":\"unavailable\"") {
			t.Fatalf("%s = %d %q", path, w.Code, w.Body.String())
		}
	}
}

func TestMetricsInFlightAndImplicitStatus(t *testing.T) {
	a := testMetricsApp("metrics-token")
	started := make(chan struct{})
	release := make(chan struct{})
	a.mux.HandleFunc("GET /slow", func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusNoContent)
	})
	a.mux.HandleFunc("GET /empty", func(http.ResponseWriter, *http.Request) {})
	h := a.Handler()
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/slow", nil))
		close(done)
	}()
	<-started
	metrics := scrape(h, "metrics-token")
	if !strings.Contains(metrics.Body.String(), "milvago_http_requests_in_flight 1") {
		t.Fatalf("in-flight gauge = %q", metrics.Body.String())
	}
	close(release)
	<-done
	metrics = scrape(h, "metrics-token")
	if !strings.Contains(metrics.Body.String(), "milvago_http_requests_in_flight 0") {
		t.Fatalf("in-flight gauge after request = %q", metrics.Body.String())
	}
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/empty", nil))
	metrics = scrape(h, "metrics-token")
	if !strings.Contains(metrics.Body.String(), "milvago_http_requests_total{method=\"GET\",route=\"GET /empty\",status=\"200\"} 1") {
		t.Fatalf("implicit status was not counted as 200: %q", metrics.Body.String())
	}
}

func TestZeroValueAppMetricsHandler(t *testing.T) {
	var a App
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health/live", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("zero-value App live status = %d", w.Code)
	}
}
