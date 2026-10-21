package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/telemetry"
)

// TelemetryAPI exposes REST and streaming endpoints for forensic events and analytics.
type TelemetryAPI struct {
	store    telemetry.ForensicStore
	streamer *EventStreamer
	metrics  *telemetry.Metrics
}

// NewTelemetryAPI constructs a TelemetryAPI controller.
func NewTelemetryAPI(store telemetry.ForensicStore, streamer *EventStreamer, metrics *telemetry.Metrics) *TelemetryAPI {
	if metrics == nil {
		metrics = telemetry.DefaultMetrics
	}
	return &TelemetryAPI{
		store:    store,
		streamer: streamer,
		metrics:  metrics,
	}
}

// ServeHTTP routes management API requests under /.raiwall/.
func (api *TelemetryAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cleanPath := strings.TrimSuffix(r.URL.Path, "/")

	switch cleanPath {
	case "/.raiwall/api/events/stream", "/api/v1/telemetry/events/stream", "/.raiwall/api/v1/telemetry/events/stream":
		if api.streamer != nil {
			api.streamer.ServeHTTP(w, r)
			return
		}
		http.Error(w, "Streamer disabled", http.StatusServiceUnavailable)

	case "/.raiwall/api/events", "/api/v1/telemetry/events", "/.raiwall/api/v1/telemetry/events":
		api.handleEventsQuery(w, r)

	case "/.raiwall/api/events/stats", "/api/v1/telemetry/events/stats", "/.raiwall/api/v1/telemetry/events/stats":
		api.handleStatsQuery(w, r)

	case "/.raiwall/metrics", "/metrics":
		if api.metrics != nil {
			api.metrics.Handler().ServeHTTP(w, r)
			return
		}
		http.Error(w, "Metrics disabled", http.StatusServiceUnavailable)

	default:
		http.NotFound(w, r)
	}
}

func (api *TelemetryAPI) handleEventsQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if api.store == nil {
		http.Error(w, "Storage not configured", http.StatusServiceUnavailable)
		return
	}

	q := r.URL.Query()
	params := telemetry.QueryParams{
		ClientIP:    q.Get("client_ip"),
		Action:      q.Get("action"),
		RuleID:      q.Get("rule_id"),
		Country:     q.Get("country"),
		MinSeverity: q.Get("min_severity"),
	}

	if st := q.Get("start_time"); st != "" {
		if t, err := time.Parse(time.RFC3339, st); err == nil {
			params.StartTime = t
		}
	}
	if et := q.Get("end_time"); et != "" {
		if t, err := time.Parse(time.RFC3339, et); err == nil {
			params.EndTime = t
		}
	}

	if l := q.Get("limit"); l != "" {
		if limitVal, err := strconv.Atoi(l); err == nil {
			params.Limit = limitVal
		}
	}
	if o := q.Get("offset"); o != "" {
		if offsetVal, err := strconv.Atoi(o); err == nil {
			params.Offset = offsetVal
		}
	}

	result, err := api.store.Query(r.Context(), params)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func (api *TelemetryAPI) handleStatsQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if api.store == nil {
		http.Error(w, "Storage not configured", http.StatusServiceUnavailable)
		return
	}

	q := r.URL.Query()
	start := time.Now().Add(-24 * time.Hour)
	end := time.Now()

	if st := q.Get("start_time"); st != "" {
		if t, err := time.Parse(time.RFC3339, st); err == nil {
			start = t
		}
	}
	if et := q.Get("end_time"); et != "" {
		if t, err := time.Parse(time.RFC3339, et); err == nil {
			end = t
		}
	}

	stats, err := api.store.QueryAggregates(r.Context(), start, end)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}
