package caddy

import (
	"fmt"
	"strings"
)

// Validate ensures the middleware configuration is valid.
func (m *Middleware) Validate() error {
	if !m.runMode.IsValid() {
		return fmt.Errorf("invalid run mode: %s", m.runMode)
	}
	if m.BlockStatusCode != 0 && (m.BlockStatusCode < 200 || m.BlockStatusCode > 599) {
		return fmt.Errorf("invalid block_status_code: %d (must be between 200 and 599)", m.BlockStatusCode)
	}
	if m.OfflineStatusCode != 0 && (m.OfflineStatusCode < 200 || m.OfflineStatusCode > 599) {
		return fmt.Errorf("invalid offline_status_code: %d (must be between 200 and 599)", m.OfflineStatusCode)
	}
	if m.BotDefense != "" {
		switch strings.ToLower(m.BotDefense) {
		case "defense", "challenge", "strict", "audit", "off", "disabled":
			// valid
		default:
			return fmt.Errorf("invalid bot_defense: %s (must be defense, challenge, strict, audit, or off)", m.BotDefense)
		}
	}
	if m.PoWDifficulty < 0 {
		return fmt.Errorf("invalid pow_difficulty: %d (must be non-negative)", m.PoWDifficulty)
	}
	if m.RateLimitConfig != nil {
		if st := strings.ToLower(m.RateLimitConfig.StorageType); st != "" && st != "memory" && st != "redis" {
			return fmt.Errorf("invalid rate_limit storage type: %s (must be memory or redis)", m.RateLimitConfig.StorageType)
		}
		if m.RateLimitConfig.Tier1Rate < 0 {
			return fmt.Errorf("invalid tier1_rate: %d (must be non-negative)", m.RateLimitConfig.Tier1Rate)
		}
		if m.RateLimitConfig.Tier1Burst < 0 {
			return fmt.Errorf("invalid tier1_burst: %d (must be non-negative)", m.RateLimitConfig.Tier1Burst)
		}
		if m.RateLimitConfig.Tier2Threshold < 0 {
			return fmt.Errorf("invalid tier2_threshold: %d (must be non-negative)", m.RateLimitConfig.Tier2Threshold)
		}
		if m.RateLimitConfig.Tier3Threshold < 0 {
			return fmt.Errorf("invalid tier3_threshold: %d (must be non-negative)", m.RateLimitConfig.Tier3Threshold)
		}
	}
	if m.WaitingRoomConfig != nil {
		if m.WaitingRoomConfig.MaxConcurrentInFlight < 0 {
			return fmt.Errorf("invalid max_concurrent: %d (must be non-negative)", m.WaitingRoomConfig.MaxConcurrentInFlight)
		}
		if m.WaitingRoomConfig.MaxQueueDepth < 0 {
			return fmt.Errorf("invalid max_queue_depth: %d (must be non-negative)", m.WaitingRoomConfig.MaxQueueDepth)
		}
		if m.WaitingRoomConfig.AdmissionRate < 0 {
			return fmt.Errorf("invalid admission_rate: %d (must be non-negative)", m.WaitingRoomConfig.AdmissionRate)
		}
	}
	if m.TelemetryConfig != nil {
		if st := strings.ToLower(m.TelemetryConfig.StorageType); st != "" && st != "sqlite" && st != "clickhouse" {
			return fmt.Errorf("invalid telemetry storage type: %s (must be sqlite or clickhouse)", m.TelemetryConfig.StorageType)
		}
		if m.TelemetryConfig.BufferSize < 0 {
			return fmt.Errorf("invalid buffer_size: %d (must be non-negative)", m.TelemetryConfig.BufferSize)
		}
	}
	return nil
}
