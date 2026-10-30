package geoip

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/oschwald/maxminddb-golang"
)

type mmdbCountryRecord struct {
	Continent struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"continent"`
	Country struct {
		IsoCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		IsoCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
}

type mmdbCityRecord struct {
	Continent struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"continent"`
	Country struct {
		IsoCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		IsoCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

type mmdbASNRecord struct {
	AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}

// Config identifies the MaxMind databases served by a GeoIPReader. Empty paths
// disable the corresponding lookup, and the city database also supplies country
// and continent when no dedicated country database is configured.
type Config struct {
	CountryPath string
	CityPath    string
	ASNPath     string
}

// GeoIPReader performs thread-safe geographic and autonomous system lookups
// using MaxMind MMDB databases with safe zero-panic fallback.
type GeoIPReader struct {
	countryReader   *maxminddb.Reader
	cityReader      *maxminddb.Reader
	asnReader       *maxminddb.Reader
	staticOverrides map[string]acl.GeoData
	mu              sync.RWMutex
}

// NewGeoIPReader opens the databases described by cfg. Databases that are not
// configured are skipped; configured paths that do not exist are an error.
func NewGeoIPReader(cfg Config) (*GeoIPReader, error) {
	r := &GeoIPReader{}

	databases := []struct {
		path  string
		label string
		dest  **maxminddb.Reader
	}{
		{cfg.CountryPath, "country", &r.countryReader},
		{cfg.CityPath, "city", &r.cityReader},
		{cfg.ASNPath, "asn", &r.asnReader},
	}

	for _, db := range databases {
		reader, err := openDatabase(db.path, db.label)
		if err != nil {
			_ = r.Close()
			return nil, err
		}
		*db.dest = reader
	}

	return r, nil
}

func openDatabase(path, label string) (*maxminddb.Reader, error) {
	if path == "" {
		return nil, nil
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("%s mmdb file not found: %s", label, path)
	}
	reader, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s mmdb %q: %w", label, path, err)
	}
	return reader, nil
}

// NewGeoIPReaderFromBytes initializes readers from in-memory byte buffers.
func NewGeoIPReaderFromBytes(countryBytes, cityBytes, asnBytes []byte) (*GeoIPReader, error) {
	r := &GeoIPReader{}

	databases := []struct {
		data  []byte
		label string
		dest  **maxminddb.Reader
	}{
		{countryBytes, "country", &r.countryReader},
		{cityBytes, "city", &r.cityReader},
		{asnBytes, "asn", &r.asnReader},
	}

	for _, db := range databases {
		if len(db.data) == 0 {
			continue
		}
		reader, err := maxminddb.FromBytes(db.data)
		if err != nil {
			_ = r.Close()
			return nil, fmt.Errorf("parse %s mmdb bytes: %w", db.label, err)
		}
		*db.dest = reader
	}

	return r, nil
}

// NewNoopGeoIPReader returns a reader that safely returns empty GeoData for all lookups.
func NewNoopGeoIPReader() *GeoIPReader {
	return &GeoIPReader{}
}

// NewGeoIPReaderOptional creates a GeoIPReader, ignoring missing files gracefully.
func NewGeoIPReaderOptional(cfg Config) *GeoIPReader {
	r, err := NewGeoIPReader(cfg)
	if err != nil {
		return &GeoIPReader{}
	}
	return r
}

// HasCountryDB reports whether a country database (or a city database, which
// carries country data) is active.
func (r *GeoIPReader) HasCountryDB() bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.countryReader != nil || r.cityReader != nil
}

// HasCityDB reports whether a city database is active.
func (r *GeoIPReader) HasCityDB() bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cityReader != nil
}

// HasASNDB reports whether an ASN database is active.
func (r *GeoIPReader) HasASNDB() bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.asnReader != nil
}

// LookupAddr queries geographic and ASN data for a netip.Addr.
func (r *GeoIPReader) LookupAddr(addr netip.Addr) acl.GeoData {
	if !addr.IsValid() {
		return acl.GeoData{}
	}
	ip := net.IP(addr.Unmap().AsSlice())
	return r.Lookup(ip)
}

// SetStaticLookup maps an IP to static GeoData for testing or manual overrides.
func (r *GeoIPReader) SetStaticLookup(ip net.IP, data acl.GeoData) {
	if r == nil || ip == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.staticOverrides == nil {
		r.staticOverrides = make(map[string]acl.GeoData)
	}
	r.staticOverrides[ip.String()] = data
}

// Lookup queries geographic and ASN data for an IP.
func (r *GeoIPReader) Lookup(ip net.IP) acl.GeoData {
	if r == nil || ip == nil {
		return acl.GeoData{}
	}

	r.mu.RLock()
	if len(r.staticOverrides) > 0 {
		if data, ok := r.staticOverrides[ip.String()]; ok {
			r.mu.RUnlock()
			return data
		}
		if ip4 := ip.To4(); ip4 != nil {
			if data, ok := r.staticOverrides[ip4.String()]; ok {
				r.mu.RUnlock()
				return data
			}
		}
	}
	r.mu.RUnlock()

	addr, ok := acl.NetipAddrFromIP(ip)
	if !ok || addr.IsLoopback() || addr.IsPrivate() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() {
		return acl.GeoData{}
	}

	queryIP := ip
	if ip4 := ip.To4(); ip4 != nil {
		queryIP = ip4
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	var geo acl.GeoData

	var cityRec mmdbCityRecord
	cityDecoded := false
	if r.cityReader != nil {
		if err := r.cityReader.Lookup(queryIP, &cityRec); err == nil {
			cityDecoded = true
			geo.City = cityRec.City.Names["en"]
			geo.Latitude = cityRec.Location.Latitude
			geo.Longitude = cityRec.Location.Longitude
		}
	}

	if r.countryReader != nil {
		var rec mmdbCountryRecord
		if err := r.countryReader.Lookup(queryIP, &rec); err == nil {
			geo.Continent = rec.Continent.Code
			geo.Country = firstNonEmpty(rec.Country.IsoCode, rec.RegisteredCountry.IsoCode)
		}
	} else if cityDecoded {
		geo.Continent = cityRec.Continent.Code
		geo.Country = firstNonEmpty(cityRec.Country.IsoCode, cityRec.RegisteredCountry.IsoCode)
	}

	if r.asnReader != nil {
		var rec mmdbASNRecord
		if err := r.asnReader.Lookup(queryIP, &rec); err == nil {
			geo.ASN = rec.AutonomousSystemNumber
			geo.ASOrg = rec.AutonomousSystemOrganization
		}
	}

	return geo
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// Close closes open MMDB database readers.
func (r *GeoIPReader) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	var errs []error
	for _, reader := range []**maxminddb.Reader{&r.countryReader, &r.cityReader, &r.asnReader} {
		if *reader == nil {
			continue
		}
		if err := (*reader).Close(); err != nil {
			errs = append(errs, err)
		}
		*reader = nil
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
