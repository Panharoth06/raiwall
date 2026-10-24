package api

import (
	"encoding/json"
	"net/http"
	"net/url"
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

	case "/.raiwall/api/incidents", "/api/v1/telemetry/incidents", "/.raiwall/api/v1/telemetry/incidents":
		api.handleIncidentsQuery(w, r)

	case "/.raiwall/metrics", "/metrics":
		if api.metrics != nil {
			api.metrics.Handler().ServeHTTP(w, r)
			return
		}
		http.Error(w, "Metrics disabled", http.StatusServiceUnavailable)

	default:
		if eventID, ok := incidentEventCurlID(cleanPath); ok {
			api.handleEventCurl(w, r, eventID)
			return
		}
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

	start, end := parseTimeWindow(r.URL.Query())
	stats, err := api.store.QueryAggregates(r.Context(), start, end)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}

// handleIncidentsQuery returns events grouped into sliding 5-minute incident clusters.
func (api *TelemetryAPI) handleIncidentsQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if api.store == nil {
		http.Error(w, "Storage not configured", http.StatusServiceUnavailable)
		return
	}

	q := r.URL.Query()
	start, end := parseTimeWindow(q)
	params := telemetry.IncidentQueryParams{
		StartTime: start,
		EndTime:   end,
		ClientIP:  q.Get("client_ip"),
		Host:      q.Get("host"),
		Limit:     atoiDefault(q.Get("limit"), 20),
		Offset:    atoiDefault(q.Get("offset"), 0),
	}

	result, err := api.store.GetAggregatedIncidents(r.Context(), params)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if result.Incidents == nil {
		result.Incidents = []*telemetry.Incident{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// handleEventCurl renders a reproducible curl command for a stored forensic event.
func (api *TelemetryAPI) handleEventCurl(w http.ResponseWriter, r *http.Request, eventID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if api.store == nil {
		http.Error(w, "Storage not configured", http.StatusServiceUnavailable)
		return
	}

	event, err := api.store.GetEventByID(r.Context(), eventID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if event == nil {
		http.Error(w, "Event not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Curl string `json:"curl"`
	}{Curl: telemetry.GenerateCurlCommand(event)})
}

// incidentEventCurlID extracts the event identifier from an .../events/{id}/curl path.
func incidentEventCurlID(cleanPath string) (string, bool) {
	const suffix = "/curl"
	if !strings.HasSuffix(cleanPath, suffix) {
		return "", false
	}
	trimmed := strings.TrimSuffix(cleanPath, suffix)
	for _, prefix := range []string{
		"/.raiwall/api/v1/telemetry/events/",
		"/.raiwall/api/events/",
		"/api/v1/telemetry/events/",
	} {
		if !strings.HasPrefix(trimmed, prefix) {
			continue
		}
		id := strings.TrimPrefix(trimmed, prefix)
		if id == "" || strings.Contains(id, "/") {
			return "", false
		}
		return id, true
	}
	return "", false
}

func parseTimeWindow(q url.Values) (time.Time, time.Time) {
	end := time.Now()
	if et := q.Get("end_time"); et != "" {
		if t, err := time.Parse(time.RFC3339, et); err == nil {
			end = t
		}
	}
	start := end.Add(-24 * time.Hour)
	if st := q.Get("start_time"); st != "" {
		if t, err := time.Parse(time.RFC3339, st); err == nil {
			start = t
		}
	}
	return start, end
}

func atoiDefault(raw string, fallback int) int {
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return v
}
