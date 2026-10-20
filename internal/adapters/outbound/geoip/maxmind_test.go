package geoip

import (
	"net"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/acl"
)

func TestGeoIPReader_NoopAndGracefulFallback(t *testing.T) {
	reader := NewNoopGeoIPReader()
	defer reader.Close()

	testIPs := []struct {
		name string
		ip   net.IP
	}{
		{"nil IP", nil},
		{"IPv4 loopback", net.ParseIP("127.0.0.1")},
		{"IPv6 loopback", net.ParseIP("::1")},
		{"RFC 1918 10/8", net.ParseIP("10.10.10.10")},
		{"RFC 1918 172.16/12", net.ParseIP("172.16.0.5")},
		{"RFC 1918 192.168/16", net.ParseIP("192.168.1.100")},
		{"Link-local", net.ParseIP("169.254.1.1")},
		{"Public IP without DB", net.ParseIP("8.8.8.8")},
		{"IPv6 Public without DB", net.ParseIP("2606:4700:4700::1111")},
	}

	for _, tc := range testIPs {
		t.Run(tc.name, func(t *testing.T) {
			geo := reader.Lookup(tc.ip)
			if geo.Country != "" || geo.Continent != "" || geo.ASN != 0 || geo.ASOrg != "" {
				t.Errorf("expected empty GeoData for %v, got %+v", tc.ip, geo)
			}
		})
	}

	var nilReader *GeoIPReader
	geo := nilReader.Lookup(net.ParseIP("8.8.8.8"))
	if geo.Country != "" {
		t.Errorf("expected empty GeoData for nil reader, got %+v", geo)
	}
	if err := nilReader.Close(); err != nil {
		t.Errorf("expected nil error on nil reader close, got %v", err)
	}
}

func TestGeoIPReader_MissingDatabaseFiles(t *testing.T) {
	_, err := NewGeoIPReader("/tmp/nonexistent_country_raiwall.mmdb", "")
	if err == nil {
		t.Errorf("expected error for non-existent country mmdb file")
	}

	_, err = NewGeoIPReader("", "/tmp/nonexistent_asn_raiwall.mmdb")
	if err == nil {
		t.Errorf("expected error for non-existent asn mmdb file")
	}
}

func TestGeoIPReader_CloseIdempotent(t *testing.T) {
	reader := NewNoopGeoIPReader()
	if err := reader.Close(); err != nil {
		t.Fatalf("first Close() failed: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("second Close() failed: %v", err)
	}
}

func TestGeoIPReader_LookupAddr_StaticOverride(t *testing.T) {
	reader := NewNoopGeoIPReader()
	defer reader.Close()

	reader.SetStaticLookup(net.ParseIP("10.0.0.1"), acl.GeoData{Country: "US", ASN: 15169})
	addr, ok := acl.NetipAddrFromIP(net.ParseIP("10.0.0.1"))
	if !ok {
		t.Fatalf("NetipAddrFromIP failed")
	}

	geo := reader.LookupAddr(addr)
	if geo.Country != "US" || geo.ASN != 15169 {
		t.Errorf("expected static override Country 'US', got %+v", geo)
	}
}
