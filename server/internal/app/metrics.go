package app

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type appMetrics struct {
	registry *prometheus.Registry
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	inFlight prometheus.Gauge
}

func newAppMetrics(pool *pgxpool.Pool) *appMetrics {
	registry := prometheus.NewRegistry()
	registry.MustRegister(prometheus.NewGoCollector(), prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	requests := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "milvago_http_requests_total", Help: "Number of HTTP requests handled by Milvago."}, []string{"method", "route", "status"})
	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "milvago_http_request_duration_seconds", Help: "Time spent handling Milvago HTTP requests."}, []string{"method", "route"})
	inFlight := prometheus.NewGauge(prometheus.GaugeOpts{Name: "milvago_http_requests_in_flight", Help: "HTTP requests currently being handled by Milvago."})
	registry.MustRegister(requests, duration, inFlight)
	registry.MustRegister(
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "milvago_pg_pool_total_connections", Help: "Current PostgreSQL pool connections."}, func() float64 {
			if pool == nil {
				return 0
			}
			return float64(pool.Stat().TotalConns())
		}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "milvago_pg_pool_acquired_connections", Help: "Current acquired PostgreSQL pool connections."}, func() float64 {
			if pool == nil {
				return 0
			}
			return float64(pool.Stat().AcquiredConns())
		}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "milvago_pg_pool_idle_connections", Help: "Current idle PostgreSQL pool connections."}, func() float64 {
			if pool == nil {
				return 0
			}
			return float64(pool.Stat().IdleConns())
		}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "milvago_pg_pool_max_connections", Help: "Configured maximum PostgreSQL pool connections."}, func() float64 {
			if pool == nil {
				return 0
			}
			return float64(pool.Stat().MaxConns())
		}),
	)
	for _, counter := range []struct {
		name string
		help string
		read func(*pgxpool.Stat) float64
	}{
		{"milvago_pg_pool_acquire_total", "Successful PostgreSQL pool acquisitions.", func(s *pgxpool.Stat) float64 { return float64(s.AcquireCount()) }},
		{"milvago_pg_pool_acquire_duration_seconds_total", "Cumulative duration of successful PostgreSQL pool acquisitions.", func(s *pgxpool.Stat) float64 { return s.AcquireDuration().Seconds() }},
		{"milvago_pg_pool_empty_acquire_total", "PostgreSQL pool acquisitions that waited for a connection.", func(s *pgxpool.Stat) float64 { return float64(s.EmptyAcquireCount()) }},
		{"milvago_pg_pool_canceled_acquire_total", "PostgreSQL pool acquisitions canceled by context.", func(s *pgxpool.Stat) float64 { return float64(s.CanceledAcquireCount()) }},
	} {
		registry.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{Name: counter.name, Help: counter.help}, func() float64 {
			if pool == nil {
				return 0
			}
			return counter.read(pool.Stat())
		}))
	}
	return &appMetrics{registry: registry, requests: requests, duration: duration, inFlight: inFlight}
}

func (a *App) metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	// No token configured means the route is off, not open. It answers 404 rather
	// than 401 so an unconfigured deployment does not advertise that a metrics
	// endpoint exists at all: the counters carry no tenant data, but the route
	// label set enumerates the served API surface (and therefore the edition),
	// and the pool gauges tell an attacker when the instance is under pressure.
	// Exposing that takes a deliberate MILVAGO_METRICS_TOKEN.
	if a.config.MetricsToken == "" {
		http.NotFound(w, r)
		return
	}
	if !metricTokenAllowed(r.Header.Get("Authorization"), a.config.MetricsToken) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	promhttp.HandlerFor(a.metrics.registry, promhttp.HandlerOpts{}).ServeHTTP(w, r)
}

func (a *App) live(w http.ResponseWriter, _ *http.Request) { healthReply(w, http.StatusOK, "live") }
func (a *App) ready(w http.ResponseWriter, r *http.Request) {
	if a.db == nil {
		healthReply(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if a.db.Ping(ctx) != nil {
		healthReply(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	healthReply(w, http.StatusOK, "ready")
}
func healthReply(w http.ResponseWriter, status int, state string) {
	w.Header().Set("Cache-Control", "no-store")
	reply(w, status, map[string]string{"status": state})
}

func (a *App) registerMetrics() {
	if a.mux == nil {
		a.mux = http.NewServeMux()
	}
	a.metricsOnce.Do(func() {
		a.metrics = newAppMetrics(a.db)
		a.registerExportMetrics(a.metrics.registry)
		a.mux.HandleFunc("GET /metrics", a.metricsHandler)
		a.mux.HandleFunc("GET /health", a.ready)
		a.mux.HandleFunc("GET /health/live", a.live)
		a.mux.HandleFunc("GET /healthz", a.live)
		a.mux.HandleFunc("GET /readyz", a.ready)
	})
}

func (m *appMetrics) serve(next http.Handler, w http.ResponseWriter, r *http.Request) {
	if isMetricsPath(r.URL.Path) || isProbePath(r.URL.Path) {
		next.ServeHTTP(w, r)
		return
	}
	start := time.Now()
	wrapped := &metricsResponseWriter{ResponseWriter: w, status: http.StatusOK}
	m.inFlight.Inc()
	defer m.inFlight.Dec()
	next.ServeHTTP(wrapped, r)
	route := metricRoute(r)
	method := metricMethod(r.Method)
	m.requests.WithLabelValues(method, route, metricStatus(wrapped.status)).Inc()
	m.duration.WithLabelValues(method, route).Observe(time.Since(start).Seconds())
}

func metricTokenAllowed(authorization, token string) bool {
	// An unconfigured token authorizes nothing. The handler already answers 404 in
	// that case, so this is the second of two closed doors: a future caller that
	// reaches this function directly cannot be handed a free pass by an empty
	// configuration value.
	if token == "" {
		return false
	}
	const prefix = "Bearer "
	if len(authorization) < len(prefix) || authorization[:len(prefix)] != prefix {
		return false
	}
	expected := sha256.Sum256([]byte(token))
	provided := sha256.Sum256([]byte(authorization[len(prefix):]))
	return subtle.ConstantTimeCompare(expected[:], provided[:]) == 1
}
func isProbePath(path string) bool {
	return path == "/health" || path == "/health/live" || path == "/healthz" || path == "/readyz"
}
func isMetricsPath(path string) bool { return path == "/metrics" }
func metricMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodHead, http.MethodOptions:
		return method
	default:
		return "OTHER"
	}
}
func metricStatus(status int) string {
	if status < 100 || status > 599 {
		return "OTHER"
	}
	return strconv.Itoa(status)
}
func metricRoute(r *http.Request) string {
	switch r.Pattern {
	case "", "/api/", "/v1/":
		return "not_found"
	case "/":
		return "static"
	default:
		return r.Pattern
	}
}

type metricsResponseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *metricsResponseWriter) WriteHeader(status int) {
	if status >= 100 && status < 200 {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	if !w.wroteHeader {
		w.status = status
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *metricsResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.status = http.StatusOK
		w.wroteHeader = true
	}
	return w.ResponseWriter.Write(b)
}
func (w *metricsResponseWriter) ReadFrom(r io.Reader) (int64, error) {
	if !w.wroteHeader {
		w.status = http.StatusOK
		w.wroteHeader = true
	}
	if readerFrom, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		return readerFrom.ReadFrom(r)
	}
	return io.Copy(w.ResponseWriter, r)
}
func (w *metricsResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *metricsResponseWriter) Flush() {
	if !w.wroteHeader {
		w.status = http.StatusOK
		w.wroteHeader = true
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

var _ http.Flusher = (*metricsResponseWriter)(nil)
var _ io.ReaderFrom = (*metricsResponseWriter)(nil)
