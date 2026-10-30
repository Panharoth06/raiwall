package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGeoIPStatusAPI_ReportsDatabaseState(t *testing.T) {
	handler := NewGeoIPStatusAPI(func() GeoIPStatus {
		return GeoIPStatus{CountryDB: true, CityDB: true, ASNDB: false}
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.raiwall/api/v1/telemetry/geoip", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("unexpected content type %q", got)
	}

	var status GeoIPStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !status.CountryDB || !status.CityDB || status.ASNDB {
		t.Errorf("unexpected status payload: %+v", status)
	}
}

func TestGeoIPStatusAPI_NilProviderReportsUnavailable(t *testing.T) {
	handler := NewGeoIPStatusAPI(nil)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.raiwall/api/v1/telemetry/geoip", nil))

	var status GeoIPStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if status.CountryDB || status.CityDB || status.ASNDB {
		t.Errorf("expected all databases unavailable, got %+v", status)
	}
}

func TestGeoIPStatusAPI_RejectsNonGet(t *testing.T) {
	handler := NewGeoIPStatusAPI(nil)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/.raiwall/api/v1/telemetry/geoip", nil))

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}
