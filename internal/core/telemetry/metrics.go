package telemetry

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds Prometheus metric collectors for Raiwall WAF telemetry.
type Metrics struct {
	registry              *prometheus.Registry
	RequestsTotal         *prometheus.CounterVec
	BlockedTotal          *prometheus.CounterVec
	RequestDuration       *prometheus.HistogramVec
	TelemetryDroppedTotal prometheus.Counter
	ActiveConnections     prometheus.Gauge
	BannedIPsTotal        prometheus.Gauge
}

// DefaultMetrics is the global default metrics instance registered on the default prometheus registry.
var DefaultMetrics = NewMetrics(prometheus.DefaultRegisterer)

// NewMetrics constructs and registers Prometheus metrics on the given registerer.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	var promRegistry *prometheus.Registry
	if r, ok := reg.(*prometheus.Registry); ok {
		promRegistry = r
	} else {
		promRegistry = prometheus.NewRegistry()
		reg = promRegistry
	}

	requestsTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "raiwall_requests_total",
			Help: "Total count of HTTP requests processed by the Raiwall gateway.",
		},
		[]string{"method", "status", "action"},
	)

	blockedTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "raiwall_blocked_total",
			Help: "Total count of security threats blocked by Raiwall.",
		},
		[]string{"reason", "rule_id"},
	)

	requestDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "raiwall_request_duration_seconds",
			Help:    "Latency duration distribution of requests processed by Raiwall.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"action"},
	)

	telemetryDroppedTotal := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "raiwall_telemetry_dropped_total",
			Help: "Total number of forensic events dropped due to ring buffer saturation.",
		},
	)

	activeConnections := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "raiwall_active_connections",
			Help: "Current number of active client connections handled by the gateway.",
		},
	)

	bannedIPsTotal := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "raiwall_banned_ips_total",
			Help: "Current number of temporarily or permanently banned client IP addresses.",
		},
	)

	_ = reg.Register(requestsTotal)
	_ = reg.Register(blockedTotal)
	_ = reg.Register(requestDuration)
	_ = reg.Register(telemetryDroppedTotal)
	_ = reg.Register(activeConnections)
	_ = reg.Register(bannedIPsTotal)

	return &Metrics{
		registry:              promRegistry,
		RequestsTotal:         requestsTotal,
		BlockedTotal:          blockedTotal,
		RequestDuration:       requestDuration,
		TelemetryDroppedTotal: telemetryDroppedTotal,
		ActiveConnections:     activeConnections,
		BannedIPsTotal:        bannedIPsTotal,
	}
}

// RecordRequest observes request completion with method, status, action, and duration.
func (m *Metrics) RecordRequest(method, status, action string, duration time.Duration) {
	m.RequestsTotal.WithLabelValues(method, status, action).Inc()
	m.RequestDuration.WithLabelValues(action).Observe(duration.Seconds())
}

// RecordBlock increments the threat block counter for a given reason and rule ID.
func (m *Metrics) RecordBlock(reason, ruleID string) {
	m.BlockedTotal.WithLabelValues(reason, ruleID).Inc()
}

// RecordTelemetryDropped records dropped events from ring buffer saturation.
func (m *Metrics) RecordTelemetryDropped(count float64) {
	m.TelemetryDroppedTotal.Add(count)
}

// SetActiveConnections sets the gauge of current active proxy connections.
func (m *Metrics) SetActiveConnections(count float64) {
	m.ActiveConnections.Set(count)
}

// SetBannedIPs updates the active banned IP count gauge.
func (m *Metrics) SetBannedIPs(count float64) {
	m.BannedIPsTotal.Set(count)
}

// Handler returns an HTTP handler for scraping Prometheus metrics.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}
