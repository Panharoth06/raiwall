package rate

import (
	"net"
	"net/http"
	"time"
)

// RateLimiterPort defines the primary interface for rate limiting implementations.
type RateLimiterPort = RateLimiter

// RateStoragePort defines the pluggable storage backend for GCRA rate limiting.
type RateStoragePort = RateStorage

// WaitingRoomPort defines the contract for virtual waiting room queue managers.
type WaitingRoomPort interface {
	ShouldEnterWaitingRoom() bool
	AcquireLease() func()
	Enqueue(ip net.IP, ja4 string) (*QueueEntry, int, int, error)
	GetPosition(id string) (int, int, bool)
	AdmitEntry(id string) bool
	RemoveEntry(id string)
	IsAdmitted(r *http.Request, ip net.IP, ja4 string) bool
	Close() error
}

// BanManagerPort defines the contract for auto-banned client management.
type BanManagerPort interface {
	IsBanned(ip net.IP, ja4 string) (bool, string)
	Ban(key string, ip net.IP, ja4 string, reason string, ttl time.Duration, siteID string)
	Unban(ip net.IP, ja4 string) bool
	ListBans() []*BanEntry
}
