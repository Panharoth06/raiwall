package caddy

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/Panharoth06/raiwall/internal/adapters/outbound/geoip"
	"github.com/Panharoth06/raiwall/internal/core/acl"
)

func TestNormalizePayloadLocation(t *testing.T) {
	cases := map[string]string{
		"Query":      "QUERY",
		"Body":       "BODY",
		"Path":       "URLPATH",
		"Cookie":     "COOKIE",
		"User-Agent": "HEADER",
		"":           "",
	}
	for input, want := range cases {
		if got := normalizePayloadLocation(input); got != want {
			t.Errorf("normalizePayloadLocation(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestCloneHeaderMapIsDeepCopy(t *testing.T) {
	src := http.Header{"Content-Type": {"application/json"}}
	cloned := cloneHeaderMap(src)

	if len(cloned) != 1 || cloned["Content-Type"][0] != "application/json" {
		t.Fatalf("unexpected clone: %+v", cloned)
	}

	cloned["Content-Type"][0] = "text/plain"
	if src.Get("Content-Type") != "application/json" {
		t.Errorf("clone mutated source header: %q", src.Get("Content-Type"))
	}
}

func TestLookupGeoCarriesCityAndCoordinates(t *testing.T) {
	reader := geoip.NewNoopGeoIPReader()
	reader.SetStaticLookup(net.ParseIP("203.0.113.9"), acl.GeoData{
		Country:   "NL",
		Continent: "EU",
		City:      "Amsterdam",
		ASN:       1103,
		ASOrg:     "KPN B.V.",
		Latitude:  52.3676,
		Longitude: 4.9041,
	})

	m := &Middleware{}
	m.SetGeoIPReader(reader)

	geo := m.lookupGeo(net.ParseIP("203.0.113.9"))
	if geo.Country != "NL" || geo.City != "Amsterdam" {
		t.Fatalf("unexpected geo data: %+v", geo)
	}
	if geo.Latitude != 52.3676 || geo.Longitude != 4.9041 {
		t.Errorf("expected city coordinates to be mapped, got %+v", geo)
	}
	if geo.ASN != 1103 || geo.ASOrg != "KPN B.V." {
		t.Errorf("expected ASN data to be mapped, got %+v", geo)
	}
}

func TestGeoIPStatusReflectsReaderState(t *testing.T) {
	m := &Middleware{}
	if status := m.geoIPStatus(); status.CountryDB || status.CityDB || status.ASNDB {
		t.Errorf("expected unavailable status without a reader, got %+v", status)
	}

	m.SetGeoIPReader(geoip.NewNoopGeoIPReader())
	if status := m.geoIPStatus(); status.CountryDB || status.CityDB || status.ASNDB {
		t.Errorf("expected unavailable status for a noop reader, got %+v", status)
	}
}

func TestExistingGeoIPConfigSkipsMissingEditions(t *testing.T) {
	dir := t.TempDir()
	cityPath := filepath.Join(dir, "GeoLite2-City.mmdb")
	if err := os.WriteFile(cityPath, []byte("city"), 0o640); err != nil {
		t.Fatalf("seed city db: %v", err)
	}

	m := &Middleware{}
	cfg := m.existingGeoIPConfig(geoip.Config{
		CountryPath: filepath.Join(dir, "GeoLite2-Country.mmdb"),
		CityPath:    cityPath,
		ASNPath:     "",
	})

	if cfg.CountryPath != "" {
		t.Errorf("expected missing country db to be dropped, got %q", cfg.CountryPath)
	}
	if cfg.CityPath != cityPath {
		t.Errorf("expected city db to survive, got %q", cfg.CityPath)
	}
	if cfg.ASNPath != "" {
		t.Errorf("expected unset asn db to stay empty, got %q", cfg.ASNPath)
	}
}
