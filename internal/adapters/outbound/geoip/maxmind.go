package geoip

import (
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

type mmdbASNRecord struct {
	AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}

// GeoIPReader performs thread-safe geographic and autonomous system lookups
// using MaxMind MMDB databases with safe zero-panic fallback.
type GeoIPReader struct {
	countryReader   *maxminddb.Reader
	asnReader       *maxminddb.Reader
	staticOverrides map[string]acl.GeoData
	mu              sync.RWMutex
}

// NewGeoIPReader creates a GeoIPReader. If countryPath or asnPath are empty,
// the corresponding database reader is omitted and queries return empty metadata safely.
func NewGeoIPReader(countryPath, asnPath string) (*GeoIPReader, error) {
	r := &GeoIPReader{}

	if countryPath != "" {
		if _, err := os.Stat(countryPath); err == nil {
			cr, err := maxminddb.Open(countryPath)
			if err != nil {
				return nil, fmt.Errorf("open country mmdb %q: %w", countryPath, err)
			}
			r.countryReader = cr
		} else {
			return nil, fmt.Errorf("country mmdb file not found: %s", countryPath)
		}
	}

	if asnPath != "" {
		if _, err := os.Stat(asnPath); err == nil {
			ar, err := maxminddb.Open(asnPath)
			if err != nil {
				if r.countryReader != nil {
					_ = r.countryReader.Close()
				}
				return nil, fmt.Errorf("open asn mmdb %q: %w", asnPath, err)
			}
			r.asnReader = ar
		} else {
			if r.countryReader != nil {
				_ = r.countryReader.Close()
			}
			return nil, fmt.Errorf("asn mmdb file not found: %s", asnPath)
		}
	}

	return r, nil
}

// NewGeoIPReaderFromBytes initializes readers from in-memory byte buffers.
func NewGeoIPReaderFromBytes(countryBytes, asnBytes []byte) (*GeoIPReader, error) {
	r := &GeoIPReader{}

	if len(countryBytes) > 0 {
		cr, err := maxminddb.FromBytes(countryBytes)
		if err != nil {
			return nil, fmt.Errorf("parse country mmdb bytes: %w", err)
		}
		r.countryReader = cr
	}

	if len(asnBytes) > 0 {
		ar, err := maxminddb.FromBytes(asnBytes)
		if err != nil {
			if r.countryReader != nil {
				_ = r.countryReader.Close()
			}
			return nil, fmt.Errorf("parse asn mmdb bytes: %w", err)
		}
		r.asnReader = ar
	}

	return r, nil
}

// NewNoopGeoIPReader returns a reader that safely returns empty GeoData for all lookups.
func NewNoopGeoIPReader() *GeoIPReader {
	return &GeoIPReader{}
}

// NewGeoIPReaderOptional creates a GeoIPReader, ignoring missing files gracefully.
func NewGeoIPReaderOptional(countryPath, asnPath string) *GeoIPReader {
	r, err := NewGeoIPReader(countryPath, asnPath)
	if err != nil {
		return &GeoIPReader{}
	}
	return r
}

// HasCountryDB reports whether a country database is active.
func (r *GeoIPReader) HasCountryDB() bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.countryReader != nil
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

	if r.countryReader != nil {
		var rec mmdbCountryRecord
		if err := r.countryReader.Lookup(queryIP, &rec); err == nil {
			geo.Continent = rec.Continent.Code
			if rec.Country.IsoCode != "" {
				geo.Country = rec.Country.IsoCode
			} else {
				geo.Country = rec.RegisteredCountry.IsoCode
			}
		}
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

// Close closes open MMDB database readers.
func (r *GeoIPReader) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	var errs []error
	if r.countryReader != nil {
		if err := r.countryReader.Close(); err != nil {
			errs = append(errs, err)
		}
		r.countryReader = nil
	}
	if r.asnReader != nil {
		if err := r.asnReader.Close(); err != nil {
			errs = append(errs, err)
		}
		r.asnReader = nil
	}

	if len(errs) > 0 {
		return fmt.Errorf("close geoip readers: %v", errs)
	}
	return nil
}
