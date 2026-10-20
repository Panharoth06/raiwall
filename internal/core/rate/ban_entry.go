package rate

import (
	"fmt"
	"net"
	"time"
)

// DefaultBanDuration is the default ban lifetime (24 hours).
const DefaultBanDuration = 24 * time.Hour

// BanEntry records metadata about an auto-banned client.
type BanEntry struct {
	Key              string        `json:"key"`
	ClientIP         string        `json:"client_ip,omitempty"`
	JA4              string        `json:"ja4,omitempty"`
	Reason           string        `json:"reason"`
	SiteID           string        `json:"site_id,omitempty"`
	Duration         time.Duration `json:"duration,omitempty"`
	RemainingSeconds int64         `json:"remaining_seconds"`
	BannedAt         time.Time     `json:"banned_at"`
	ExpiresAt        time.Time     `json:"expires_at"`
}

// BanKey builds a lookup key combining IP and JA4.
func BanKey(ip net.IP, ja4 string) string {
	ipStr := ""
	if ip != nil {
		ipStr = ip.String()
	}
	if ipStr != "" && ja4 != "" {
		return fmt.Sprintf("%s|%s", ipStr, ja4)
	}
	if ipStr != "" {
		return ipStr
	}
	return ja4
}
