package acl

import (
	"net"
	"net/http"
)

// GeoIPPort defines the driven port for GeoIP / ASN lookups.
type GeoIPPort interface {
	Lookup(ip net.IP) GeoData
	Close() error
}

// GeoIPReader is an alias for GeoIPPort for compatibility.
type GeoIPReader = GeoIPPort

// FeedLoaderPort defines the driven port for threat feed loading.
type FeedLoaderPort interface {
	LoadFile(path string, feedName string) (int, error)
}

// AccessControlPort defines the driving port for access control evaluation.
type AccessControlPort interface {
	Evaluate(req *http.Request, ip net.IP, ja4 string, geo GeoData) (*ACLVerdict, error)
}
