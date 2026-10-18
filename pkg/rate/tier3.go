package rate

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// DefaultTier3Threshold is the default scanner error threshold (20 errors).
const DefaultTier3Threshold int64 = 20

// DefaultTier3Window is the default sliding window (30 seconds).
const DefaultTier3Window = 30 * time.Second

// DefaultTier3BanDuration is the auto-ban duration for scanners (24 hours).
const DefaultTier3BanDuration = 24 * time.Hour

// DefaultTier3StatusCodes defines the status codes that trip the scanner trap.
var DefaultTier3StatusCodes = []int{http.StatusNotFound, http.StatusForbidden}

// Tier3Config configures Tier3ScannerTrap.
type Tier3Config struct {
	Threshold   int64
	Window      time.Duration
	BanDuration time.Duration
	StatusCodes []int
	StaticExts  []string
	CookieName  string
	Storage     RateStorage
	BanManager  *BanManager
	Logger      *zap.Logger
}

// Tier3ScannerTrap intercepts reverse proxy responses and neutralizes automated reconnaissance.
type Tier3ScannerTrap struct {
	limiter     RateLimiter
	banManager  *BanManager
	banDuration time.Duration
	statusCodes map[int]struct{}
	staticExts  []string
	cookieName  string
	logger      *zap.Logger
}

// NewTier3ScannerTrap initializes a new Tier3ScannerTrap.
func NewTier3ScannerTrap(cfg Tier3Config) *Tier3ScannerTrap {
	threshold := cfg.Threshold
	if threshold <= 0 {
		threshold = DefaultTier3Threshold
	}
	window := cfg.Window
	if window <= 0 {
		window = DefaultTier3Window
	}
	banDur := cfg.BanDuration
	if banDur <= 0 {
		banDur = DefaultTier3BanDuration
	}

	storage := cfg.Storage
	if storage == nil {
		storage = NewMemoryStorage()
	}

	limiter := NewGCRALimiter(storage, RateLimitConfig{
		Rate:   threshold,
		Period: window,
		Burst:  threshold - 1,
	})

	banMgr := cfg.BanManager
	if banMgr == nil {
		banMgr = NewBanManager(cfg.Logger)
	}

	statusMap := make(map[int]struct{})
	codes := cfg.StatusCodes
	if len(codes) == 0 {
		codes = DefaultTier3StatusCodes
	}
	for _, code := range codes {
		statusMap[code] = struct{}{}
	}

	return &Tier3ScannerTrap{
		limiter:     limiter,
		banManager:  banMgr,
		banDuration: banDur,
		statusCodes: statusMap,
		staticExts:  cfg.StaticExts,
		cookieName:  cfg.CookieName,
		logger:      cfg.Logger,
	}
}

// InspectResponse evaluates an upstream HTTP response and counts reconnaissance errors.
// If the threshold is breached, the scanner is immediately auto-banned in BanManager.
func (t3 *Tier3ScannerTrap) InspectResponse(ctx context.Context, r *http.Request, ip net.IP, ja4 string, statusCode int) (bool, *BanEntry, error) {
	// 1. Only process configured status codes (typically 404 and 403)
	if _, matches := t3.statusCodes[statusCode]; !matches {
		return false, nil, nil
	}

	// 2. Filter out static asset paths to avoid false positives on missing images/css
	if r != nil && IsStaticAssetPath(r.URL.Path, t3.staticExts) {
		return false, nil, nil
	}

	// 3. Track errors by composite key (IP + JA4 + Cookie)
	key := fmt.Sprintf("t3:%s", BuildCompositeKey(ip, ja4, r, t3.cookieName))
	res, err := t3.limiter.Allow(ctx, key, 1)
	if err != nil {
		return false, nil, fmt.Errorf("tier3 rate limit check error: %w", err)
	}

	if !res.Allowed {
		// Scanner threshold breached: trigger auto-ban
		path := ""
		if r != nil && r.URL != nil {
			path = r.URL.Path
		}
		banReason := fmt.Sprintf("tier3_scanner_reconnaissance_exceeded: status=%d path=%s", statusCode, path)
		entry := t3.banManager.Ban(ip, ja4, t3.banDuration, banReason)

		if t3.logger != nil {
			t3.logger.Warn("Tier 3 scanner reconnaissance trap triggered, auto-banned client",
				zap.String("client_ip", entry.ClientIP),
				zap.String("ja4", entry.JA4),
				zap.Int("status_code", statusCode),
				zap.String("path", path),
				zap.Duration("ban_duration", t3.banDuration),
			)
		}
		return true, entry, nil
	}

	return false, nil, nil
}

// BanManager returns the active BanManager.
func (t3 *Tier3ScannerTrap) BanManager() *BanManager {
	return t3.banManager
}

// Close releases allocated limiter resources.
func (t3 *Tier3ScannerTrap) Close() error {
	_ = t3.limiter.Close()
	return t3.banManager.Close()
}
