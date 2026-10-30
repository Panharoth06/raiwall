package api

import (
	"encoding/json"
	"net/http"
)

// GeoIPStatus reports which MaxMind databases are currently loaded. The
// dashboard uses it to distinguish "no matching traffic" from "geo lookup is
// disabled", which otherwise look identical in an empty country breakdown.
type GeoIPStatus struct {
	CountryDB bool `json:"country_db"`
	CityDB    bool `json:"city_db"`
	ASNDB     bool `json:"asn_db"`
}

// GeoIPStatusAPI serves the read-only GeoIP database status endpoint.
type GeoIPStatusAPI struct {
	provider func() GeoIPStatus
}

// NewGeoIPStatusAPI constructs a status handler. A nil provider reports every
// database as unavailable.
func NewGeoIPStatusAPI(provider func() GeoIPStatus) *GeoIPStatusAPI {
	return &GeoIPStatusAPI{provider: provider}
}

// ServeHTTP implements http.Handler.
func (api *GeoIPStatusAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	status := GeoIPStatus{}
	if api.provider != nil {
		status = api.provider()
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(status)
}
