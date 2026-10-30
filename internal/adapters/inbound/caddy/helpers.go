package caddy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/bot"
	"github.com/Panharoth06/raiwall/internal/core/rate"
	"github.com/Panharoth06/raiwall/internal/core/telemetry"
	"go.uber.org/zap"
)

type banStoreAdapter struct {
	bm *rate.BanManager
}

func (a *banStoreAdapter) Ban(ip net.IP, ja4 string, ttl time.Duration, reason string) {
	if a.bm != nil {
		a.bm.Ban(ip, ja4, ttl, reason)
	}
}

func (a *banStoreAdapter) IsBanned(ip net.IP, ja4 string) (bool, *bot.BanEntry) {
	if a.bm == nil {
		return false, nil
	}
	banned, entry := a.bm.IsBanned(ip, ja4)
	if !banned || entry == nil {
		return false, nil
	}
	return true, &bot.BanEntry{
		Key:       entry.Key,
		ClientIP:  entry.ClientIP,
		JA4:       entry.JA4,
		BannedAt:  entry.BannedAt,
		ExpiresAt: entry.ExpiresAt,
		Reason:    entry.Reason,
	}
}

func (a *banStoreAdapter) Unban(key string) {
	if a.bm != nil {
		a.bm.Unban(key)
	}
}

func (a *banStoreAdapter) EvictExpired() int {
	if a.bm != nil {
		return a.bm.EvictExpired()
	}
	return 0
}

func (a *banStoreAdapter) Count() int {
	if a.bm != nil {
		return a.bm.Count()
	}
	return 0
}

func (a *banStoreAdapter) Clear() {
	if a.bm != nil {
		a.bm.Clear()
	}
}

func (a *banStoreAdapter) Close() {
	if a.bm != nil {
		_ = a.bm.Close()
	}
}

func (m *Middleware) recordTelemetry(event *telemetry.ForensicEvent) {
	if event == nil {
		return
	}

	// 1. Sanitize the event (PCI-DSS & PII scrubbing, 2KB cap)
	telemetry.Sanitize(event)

	// 2. Broadcast immediately to SSE subscribers
	if m.streamer != nil {
		m.streamer.Broadcast(event)
	}

	// 3. Dispatch alert asynchronously if threat level qualifies
	if m.alertEngine != nil && (event.Action == "block" || event.Action == "ban" || event.Severity == "critical" || event.Severity == "high") {
		go func(ev *telemetry.ForensicEvent) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := m.alertEngine.Dispatch(ctx, ev); err != nil {
				if m.logger != nil {
					m.logger.Warn("Failed to dispatch alert", zap.Error(err))
				} else {
					fmt.Printf("FAILED TO DISPATCH ALERT: %v\n", err)
				}
			}
		}(event)
	}

	// 4. Update Banned IPs metric if ban manager is present
	if m.banManager != nil && m.metrics != nil {
		m.metrics.SetBannedIPs(float64(m.banManager.Count()))
	}

	// 5. Record Prometheus metrics
	if m.metrics != nil {
		statusStr := strconv.Itoa(event.StatusCode)
		m.metrics.RecordRequest(event.Method, statusStr, event.Action, event.Latency)
		if event.Action == "block" || event.Action == "ban" {
			m.metrics.RecordBlock(event.Action, event.RuleID)
		}
	}

	// 6. Enqueue in non-blocking ring buffer
	if m.ringBuffer != nil {
		pushed := m.ringBuffer.Push(event)
		if !pushed && m.metrics != nil {
			m.metrics.RecordTelemetryDropped(1)
		}
	}
}

func (m *Middleware) lookupGeo(ip net.IP) telemetry.GeoData {
	if m.geoIPReader == nil || ip == nil {
		return telemetry.GeoData{}
	}
	g := m.geoIPReader.Lookup(ip)
	return telemetry.GeoData{
		Country:   g.Country,
		Continent: g.Continent,
		City:      g.City,
		ASN:       g.ASN,
		ASOrg:     g.ASOrg,
		Latitude:  g.Latitude,
		Longitude: g.Longitude,
	}
}

func extractHeadersMap(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	res := make(map[string]string, len(h))
	for k, v := range h {
		if len(v) > 0 {
			res[k] = v[0]
		}
	}
	return res
}

// normalizePayloadLocation maps WAF verdict surfaces to the canonical forensic location enum.
func normalizePayloadLocation(location string) string {
	switch strings.ToLower(location) {
	case "query":
		return "QUERY"
	case "body":
		return "BODY"
	case "path":
		return "URLPATH"
	case "cookie":
		return "COOKIE"
	case "":
		return ""
	default:
		return "HEADER"
	}
}

// cloneHeaderMap deep-copies a multi-value header map for forensic response capture.
func cloneHeaderMap(h http.Header) map[string][]string {
	if len(h) == 0 {
		return nil
	}
	res := make(map[string][]string, len(h))
	for k, v := range h {
		res[k] = append([]string(nil), v...)
	}
	return res
}
