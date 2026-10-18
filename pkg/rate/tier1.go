package rate

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/Panharoth06/raiwall/pkg/bot"
)

// DefaultTier1Rate is the default rate limit (100 req per 10s).
const DefaultTier1Rate int64 = 100

// DefaultTier1Period is the default rate window (10 seconds).
const DefaultTier1Period = 10 * time.Second

// DefaultTier1Burst is the default burst capacity (20).
const DefaultTier1Burst int64 = 20

// Tier1Config contains configuration parameters for Tier 1 Access Velocity Limiter.
type Tier1Config struct {
	Limiter          RateLimiter
	Rate             int64
	Period           time.Duration
	Burst            int64
	CookieName       string
	Storage          RateStorage
	RouteClassifier  *bot.RouteClassifier
	PoWEngine        *bot.PoWEngine
	ClearanceManager *bot.ClearanceManager
}

// Tier1APIErrorResponse is the structured JSON returned on HTTP 429 for API routes.
type Tier1APIErrorResponse struct {
	Error      string `json:"error"`
	Message    string `json:"message"`
	RetryAfter int    `json:"retry_after"`
}

// Tier1VelocityLimiter enforces access velocity limits at the entrance of the proxy pipeline.
type Tier1VelocityLimiter struct {
	limiter         RateLimiter
	routeClassifier *bot.RouteClassifier
	powEngine       *bot.PoWEngine
	clearanceMgr    *bot.ClearanceManager
	cookieName      string
}

// NewTier1VelocityLimiter initializes a new Tier1VelocityLimiter.
func NewTier1VelocityLimiter(cfg Tier1Config) *Tier1VelocityLimiter {
	rate := cfg.Rate
	if rate <= 0 {
		rate = DefaultTier1Rate
	}
	period := cfg.Period
	if period <= 0 {
		period = DefaultTier1Period
	}
	burst := cfg.Burst
	if burst < 0 {
		burst = DefaultTier1Burst
	}

	limiter := cfg.Limiter
	if limiter == nil {
		storage := cfg.Storage
		if storage == nil {
			storage = NewMemoryStorage()
		}
		limiter = NewGCRALimiter(storage, RateLimitConfig{
			Rate:   rate,
			Period: period,
			Burst:  burst,
		})
	}

	rc := cfg.RouteClassifier
	if rc == nil {
		rc = bot.NewRouteClassifier(nil)
	}

	return &Tier1VelocityLimiter{
		limiter:         limiter,
		routeClassifier: rc,
		powEngine:       cfg.PoWEngine,
		clearanceMgr:    cfg.ClearanceManager,
		cookieName:      cfg.CookieName,
	}
}

// Check evaluates the rate limit for the incoming request without writing a response.
func (t1 *Tier1VelocityLimiter) Check(ctx context.Context, r *http.Request, ip net.IP, ja4 string) (*RateResult, bot.RouteType, error) {
	key := BuildCompositeKey(ip, ja4, r, t1.cookieName)
	route := t1.routeClassifier.Classify(r)

	res, err := t1.limiter.Allow(ctx, key, 1)
	if err != nil {
		return nil, route, fmt.Errorf("tier1 rate limit check error: %w", err)
	}
	return res, route, nil
}

// Enforce evaluates velocity rate limits and applies route-aware enforcement.
// Returns true if the request is permitted, or false if blocked/challenged.
func (t1 *Tier1VelocityLimiter) Enforce(w http.ResponseWriter, r *http.Request, ip net.IP, ja4 string) (bool, error) {
	res, route, err := t1.Check(r.Context(), r, ip, ja4)
	if err != nil {
		// On internal limiter error, fail-open to preserve availability
		return true, err
	}

	if res.Allowed {
		return true, nil
	}

	// Request exceeded velocity threshold
	return false, t1.HandleRateLimited(w, r, ip, ja4, res, route)
}

// HandleRateLimited writes route-appropriate enforcement response:
// - API/machine routes receive HTTP 429 Too Many Requests with JSON error and Retry-After.
// - Already verified browsers receive HTTP 429 Too Many Requests to prevent infinite challenge loops.
// - Unverified browser routes receive an HTTP 468 Altcha PoW challenge page.
func (t1 *Tier1VelocityLimiter) HandleRateLimited(w http.ResponseWriter, r *http.Request, ip net.IP, ja4 string, res *RateResult, route bot.RouteType) error {
	retryAfterSec := int(math.Ceil(res.RetryAfter.Seconds()))
	if retryAfterSec <= 0 {
		retryAfterSec = 1
	}

	// 1. Machine & API routes: issue standard HTTP 429 + JSON
	if bot.ShouldBypassChallenge(route) || route == bot.RouteAPI {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSec))
		w.Header().Set("X-RateLimit-Limit", strconv.FormatInt(res.Limit, 10))
		w.Header().Set("X-RateLimit-Remaining", "0")
		resetSec := int64(math.Ceil(res.ResetAfter.Seconds()))
		if resetSec <= 0 {
			resetSec = 1
		}
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetSec, 10))
		w.WriteHeader(http.StatusTooManyRequests)

		respPayload := Tier1APIErrorResponse{
			Error:      "rate_limit_exceeded",
			Message:    "Too many requests. Please slow down and retry after the specified duration.",
			RetryAfter: retryAfterSec,
		}
		_ = json.NewEncoder(w).Encode(respPayload)
		return nil
	}

	// 2. Verified browser sessions: already solved PoW challenge; do not loop on PoW indefinitely!
	// Deliver standard HTTP 429 Too Many Requests.
	if t1.clearanceMgr != nil && t1.clearanceMgr.ValidateRequest(r, ip, ja4) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSec))
		w.Header().Set("X-RateLimit-Limit", strconv.FormatInt(res.Limit, 10))
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(fmt.Sprintf("<!DOCTYPE html><html><head><title>429 Too Many Requests</title></head><body><h1>429 Too Many Requests</h1><p>You are sending requests too quickly. Please retry after %d seconds.</p></body></html>", retryAfterSec)))
		return nil
	}

	// 3. Unverified browser routes: deliver interactive PoW challenge (HTTP 468)
	if t1.powEngine != nil {
		return t1.powEngine.RenderChallengePage(w, r, r.URL.RequestURI())
	}

	// Fallback when PoWEngine is not configured
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSec))
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte("Rate limit exceeded. Please retry later."))
	return nil
}

// Limiter returns the underlying RateLimiter.
func (t1 *Tier1VelocityLimiter) Limiter() RateLimiter {
	return t1.limiter
}

// SetPoWEngine updates the active PoWEngine.
func (t1 *Tier1VelocityLimiter) SetPoWEngine(p *bot.PoWEngine) {
	t1.powEngine = p
}

// SetClearanceManager updates the active ClearanceManager.
func (t1 *Tier1VelocityLimiter) SetClearanceManager(c *bot.ClearanceManager) {
	t1.clearanceMgr = c
}

// Close releases any allocated limiter resources.
func (t1 *Tier1VelocityLimiter) Close() error {
	return t1.limiter.Close()
}
