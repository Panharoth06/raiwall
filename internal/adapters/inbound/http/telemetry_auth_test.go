package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestTelemetryAPI_RequiresAuthentication pins the control-plane boundary for
// forensic events, aggregates, incidents, replay, metrics and the live stream.
func TestTelemetryAPI_RequiresAuthentication(t *testing.T) {
	deny := func(*http.Request) error { return errors.New("unauthenticated") }
	api := NewTelemetryAPI(nil, NewEventStreamer(), nil, deny)

	paths := []string{
		"/.raiwall/api/events",
		"/.raiwall/api/events/stats",
		"/.raiwall/api/incidents",
		"/.raiwall/api/events/stream",
		"/.raiwall/metrics",
		"/metrics",
		"/.raiwall/api/events/evt-1/curl",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			api.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d", rec.Code)
			}
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
				t.Errorf("unexpected CORS header %q", got)
			}
		})
	}
}

// TestTelemetryAPI_FailsClosedWithoutAuthenticator ensures a wiring mistake
// cannot silently expose the telemetry surface.
func TestTelemetryAPI_FailsClosedWithoutAuthenticator(t *testing.T) {
	api := NewTelemetryAPI(nil, NewEventStreamer(), nil, nil)

	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.raiwall/api/events", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}
