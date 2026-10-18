package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/google/uuid"
	"github.com/Panharoth06/raiwall/pkg/bot"
	"github.com/Panharoth06/raiwall/pkg/config"
	"github.com/Panharoth06/raiwall/pkg/engine"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Middleware{})
}

// MaxInspectionBodySize is the maximum body size buffered for threat inspection (1 MB).
const MaxInspectionBodySize = 1024 * 1024

// Middleware is the Caddy HTTP handler implementing Raiwall WAF and Gateway interception.
type Middleware struct {
	Mode                string         `json:"mode,omitempty"`
	BlockStatusCode     int            `json:"block_status_code,omitempty"`
	BlockResponseBody   string         `json:"block_response_body,omitempty"`
	OfflineStatusCode   int            `json:"offline_status_code,omitempty"`
	OfflineResponseBody string         `json:"offline_response_body,omitempty"`
	StripHeaders        []string       `json:"strip_headers,omitempty"`
	ASTTimeout          caddy.Duration `json:"ast_timeout,omitempty"`
	MaxParamSize        int            `json:"max_param_size,omitempty"`

	// Domain 3: Bot Mitigation & Chaos Engine configuration
	BotDefense    string         `json:"bot_defense,omitempty"`
	PoWDifficulty int64          `json:"pow_difficulty,omitempty"`
	ClearanceTTL  caddy.Duration `json:"clearance_ttl,omitempty"`
	HoneypotTrap  *bool          `json:"honeypot_trap,omitempty"`
	PoWSecret     string         `json:"pow_secret,omitempty"`

	engine     engine.WAFEngine
	logger     *zap.Logger
	bufferPool *sync.Pool
	runMode    config.RunMode

	botClassifier *bot.BotClassifier
	routeClass    *bot.RouteClassifier
	powEngine     *bot.PoWEngine
	clearanceMgr  *bot.ClearanceManager
	honeypotInj   *bot.HoneypotInjector
	trapCtrl      *bot.TrapController
}

// CaddyModule returns the Caddy module information.
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.raiwall",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Provision sets up the middleware instance.
func (m *Middleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)

	if m.Mode == "" {
		m.Mode = string(config.ModeDefense)
	}
	parsedMode, err := config.ParseRunMode(m.Mode)
	if err != nil {
		return fmt.Errorf("provision raiwall: %w", err)
	}
	m.runMode = parsedMode

	if m.BlockStatusCode == 0 {
		m.BlockStatusCode = http.StatusForbidden
	}
	if m.BlockResponseBody == "" {
		m.BlockResponseBody = defaultBlockHTML
	}
	if m.OfflineStatusCode == 0 {
		m.OfflineStatusCode = http.StatusServiceUnavailable
	}
	if m.OfflineResponseBody == "" {
		m.OfflineResponseBody = defaultOfflineHTML
	}

	m.StripHeaders = CanonicalizeHeaderList(m.StripHeaders)

	if m.engine == nil {
		var opts []engine.SemanticOption
		if m.ASTTimeout > 0 {
			opts = append(opts, engine.WithASTTimeout(time.Duration(m.ASTTimeout)))
		}
		if m.MaxParamSize > 0 {
			opts = append(opts, engine.WithMaxParamSize(m.MaxParamSize))
		}
		m.engine = engine.NewSemanticEngine(opts...)
	}

	m.bufferPool = &sync.Pool{
		New: func() any {
			return new(bytes.Buffer)
		},
	}

	// Initialize Bot Defense components
	if m.PoWDifficulty <= 0 {
		m.PoWDifficulty = bot.DefaultPoWDifficulty
	}
	if m.ClearanceTTL <= 0 {
		m.ClearanceTTL = caddy.Duration(bot.DefaultClearanceTTL)
	}
	if m.HoneypotTrap == nil {
		enabled := true
		m.HoneypotTrap = &enabled
	}

	if m.botClassifier == nil {
		m.botClassifier = bot.NewBotClassifier()
	}
	if m.routeClass == nil {
		m.routeClass = bot.NewRouteClassifier(nil)
	}
	if m.powEngine == nil {
		m.powEngine = bot.NewPoWEngine(bot.PoWConfig{
			Secret:     m.PoWSecret,
			Difficulty: m.PoWDifficulty,
		})
	}
	if m.clearanceMgr == nil {
		m.clearanceMgr = bot.NewClearanceManager(bot.ClearanceConfig{
			Secret: m.powEngine.Secret(),
			TTL:    time.Duration(m.ClearanceTTL),
		}, m.powEngine)
	}
	if m.honeypotInj == nil {
		m.honeypotInj = bot.NewHoneypotInjector(bot.DefaultTrapPath)
	}
	if m.trapCtrl == nil {
		m.trapCtrl = bot.NewTrapController(nil, bot.DefaultBanDuration, m.logger)
	}

	return nil
}

// SetBotClassifier overrides the bot classifier (used for testing).
func (m *Middleware) SetBotClassifier(c *bot.BotClassifier) {
	m.botClassifier = c
}

// SetPoWEngine overrides the PoW engine (used for testing).
func (m *Middleware) SetPoWEngine(p *bot.PoWEngine) {
	m.powEngine = p
}

// SetClearanceManager overrides the clearance manager (used for testing).
func (m *Middleware) SetClearanceManager(cm *bot.ClearanceManager) {
	m.clearanceMgr = cm
}

// SetTrapController overrides the trap controller (used for testing).
func (m *Middleware) SetTrapController(tc *bot.TrapController) {
	m.trapCtrl = tc
}

// TrapController returns the active TrapController.
func (m *Middleware) TrapController() *bot.TrapController {
	return m.trapCtrl
}

// ClearanceManager returns the active ClearanceManager.
func (m *Middleware) ClearanceManager() *bot.ClearanceManager {
	return m.clearanceMgr
}

// PoWEngine returns the active PoWEngine.
func (m *Middleware) PoWEngine() *bot.PoWEngine {
	return m.powEngine
}

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
	return nil
}

// SetEngine overrides the inspection engine (used for testing or custom engine injection).
func (m *Middleware) SetEngine(eng engine.WAFEngine) {
	m.engine = eng
}

// Engine returns the active inspection engine.
func (m *Middleware) Engine() engine.WAFEngine {
	return m.engine
}

// RunMode returns the current statically configured run mode.
func (m *Middleware) RunMode() config.RunMode {
	return m.runMode
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	startTime := time.Now()

	// 1. Extract real client IP and JA4 fingerprint
	clientIP := ExtractClientIP(r)
	ja4 := bot.ExtractJA4(r)
	ctx := WithClientIP(r.Context(), clientIP)
	if ja4 != "" {
		ctx = bot.WithJA4(ctx, ja4)
	}
	r = r.WithContext(ctx)

	// 2. Fast-Path: Check Auto-Ban state (banned crawlers / botnets)
	if m.trapCtrl != nil {
		if banned, entry := m.trapCtrl.IsClientBanned(clientIP, ja4); banned {
			eventID := uuid.New().String()
			if m.logger != nil {
				m.logger.Warn("Blocked auto-banned client",
					zap.String("event_id", eventID),
					zap.String("client_ip", clientIP.String()),
					zap.String("ja4", ja4),
					zap.String("reason", entry.Reason),
				)
			}
			statusCode := m.BlockStatusCode
			if statusCode == 0 {
				statusCode = http.StatusForbidden
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("X-Raiwall-Event-ID", eventID)
			w.WriteHeader(statusCode)
			banMsg := "<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>Client is blocked due to security violations.</p></body></html>"
			if m.BlockResponseBody != defaultBlockHTML && m.BlockResponseBody != "" {
				banMsg = strings.ReplaceAll(m.BlockResponseBody, "{{EVENT_ID}}", eventID)
			}
			_, _ = w.Write([]byte(banMsg))
			return nil
		}
	}

	// 3. Honeypot Trap Interception (/.raiwall/trap/*)
	if bot.IsTrapRequest(r.URL.Path) {
		if m.trapCtrl != nil {
			m.trapCtrl.HandleTrap(w, r, clientIP, ja4)
			return nil
		}
		w.WriteHeader(http.StatusForbidden)
		return nil
	}

	// 4. Internal Challenge Verification Endpoint (/.raiwall/challenge/verify)
	if r.URL.Path == bot.ChallengeVerifyPath {
		if m.clearanceMgr != nil {
			m.clearanceMgr.HandleChallengeVerify(w, r, clientIP, ja4)
			return nil
		}
	}

	// 5. Resolve operational run mode from in-memory snapshot with fallback
	currentMode := m.runMode
	if !currentMode.IsValid() {
		currentMode = config.ModeDefense
	}

	snap := config.LoadSnapshot()
	var appCfg *config.AppConfig
	if snap != nil {
		if app, found := snap.GetAppForHost(r.Host); found && app != nil && app.Mode.IsValid() {
			appCfg = app
			currentMode = app.Mode
		}
	}

	// 6. Phase 1 - Evaluate Offline Mode immediately
	if currentMode == config.ModeOffline {
		statusCode := m.OfflineStatusCode
		body := m.OfflineResponseBody
		if appCfg != nil {
			if appCfg.OfflineStatusCode != 0 {
				statusCode = appCfg.OfflineStatusCode
			}
			if appCfg.OfflineResponseBody != "" {
				body = appCfg.OfflineResponseBody
			}
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Retry-After", "300")
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(body))
		return nil
	}

	// 7. Domain 3: Bot Mitigation & Route Classification
	botDefenseMode := strings.ToLower(m.BotDefense)
	if botDefenseMode != "" && botDefenseMode != "off" && botDefenseMode != "disabled" {
		if m.routeClass == nil {
			m.routeClass = bot.NewRouteClassifier(nil)
		}
		if m.botClassifier == nil {
			m.botClassifier = bot.NewBotClassifier()
		}

		route := m.routeClass.Classify(r)
		botVerdict := m.botClassifier.Classify(r, ja4)

		if botVerdict != nil {
			if botVerdict.IsSpoofed || botVerdict.Action == engine.ActionBlock {
				if botDefenseMode == "audit" || currentMode == config.ModeAudit {
					if m.logger != nil {
						m.logger.Info("Bot defense audit event (threat detected, not blocked)",
							zap.String("client_ip", clientIP.String()),
							zap.String("ja4", ja4),
							zap.String("user_agent", r.UserAgent()),
							zap.String("reason", botVerdict.Reason),
						)
					}
				} else if currentMode == config.ModeDefense {
					eventID := uuid.New().String()
					if m.logger != nil {
						m.logger.Warn("Bot defense blocked client",
							zap.String("event_id", eventID),
							zap.String("client_ip", clientIP.String()),
							zap.String("ja4", ja4),
							zap.String("user_agent", r.UserAgent()),
							zap.String("reason", botVerdict.Reason),
						)
					}
					statusCode := m.BlockStatusCode
					if botVerdict.StatusCode != 0 {
						statusCode = botVerdict.StatusCode
					}
					if statusCode == 0 {
						statusCode = http.StatusForbidden
					}
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.Header().Set("X-Raiwall-Event-ID", eventID)
					w.WriteHeader(statusCode)
					rendered := strings.ReplaceAll(m.BlockResponseBody, "{{EVENT_ID}}", eventID)
					_, _ = w.Write([]byte(rendered))
					return nil
				}
			}
		}

		// Interactive challenge gate for browser routes
		if !bot.ShouldBypassChallenge(route) {
			isCleared := false
			if m.clearanceMgr != nil {
				isCleared = m.clearanceMgr.ValidateRequest(r, clientIP, ja4)
			}

			if !isCleared && botDefenseMode != "audit" && currentMode != config.ModeAudit {
				shouldChallenge := false
				if botDefenseMode == "challenge" || botDefenseMode == "strict" {
					shouldChallenge = true
				} else if currentMode == config.ModeDefense {
					// In defense mode: challenge if suspicious or bot
					if botVerdict != nil && (botVerdict.IsBot || botVerdict.Confidence >= 0.70) {
						shouldChallenge = true
					}
				}

				if shouldChallenge && m.powEngine != nil {
					if m.logger != nil {
						m.logger.Info("Serving PoW challenge to unverified browser",
							zap.String("client_ip", clientIP.String()),
							zap.String("ja4", ja4),
							zap.String("path", r.URL.Path),
						)
					}
					return m.powEngine.RenderChallengePage(w, r, r.URL.RequestURI())
				}
			}
		}
	}

	// 8. Phase 1 - Request Inspection
	var bodyBytes []byte
	if r.Body != nil {
		if r.ContentLength > MaxInspectionBodySize {
			// Payload exceeds inspection limit: selective streaming directly to upstream
		} else {
			if m.bufferPool == nil {
				m.bufferPool = &sync.Pool{
					New: func() any { return new(bytes.Buffer) },
				}
			}
			buf := m.bufferPool.Get().(*bytes.Buffer)
			buf.Reset()

			var readErr error
			if r.ContentLength > 0 {
				_, readErr = io.Copy(buf, r.Body)
				_ = r.Body.Close()
			} else if r.ContentLength < 0 {
				// Chunked or unknown length: read up to MaxInspectionBodySize + 1
				lr := io.LimitReader(r.Body, MaxInspectionBodySize+1)
				_, readErr = io.Copy(buf, lr)
			}

			if readErr == nil {
				if buf.Len() <= MaxInspectionBodySize {
					bodyBytes = make([]byte, buf.Len())
					copy(bodyBytes, buf.Bytes())
					r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				} else {
					// Exceeded MaxInspectionBodySize while reading chunked stream:
					// Stream remaining to upstream
					bodyBytes = nil
					r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf.Bytes()), r.Body))
				}
			}

			if buf.Cap() <= MaxInspectionBodySize*2 {
				m.bufferPool.Put(buf)
			}
		}
	}

	reqContext := &engine.RequestContext{
		ClientIP:  clientIP,
		Method:    r.Method,
		Host:      r.Host,
		Path:      r.URL.Path,
		Query:     r.URL.RawQuery,
		Headers:   r.Header,
		Body:      bodyBytes,
		UserAgent: r.UserAgent(),
		JA4:       ja4,
		Context:   r.Context(),
	}
	if appCfg != nil {
		reqContext.AppID = appCfg.ID
	}

	if m.engine == nil {
		m.engine = engine.NewPassthroughEngine()
	}

	verdict, err := m.engine.InspectRequest(reqContext)
	if err != nil && m.logger != nil {
		m.logger.Error("WAF inspection error", zap.Error(err))
	}

	// Evaluate verdict according to run mode
	if verdict != nil && verdict.Action == engine.ActionBlock {
		if currentMode == config.ModeDefense {
			eventID := uuid.New().String()
			if m.logger != nil {
				m.logger.Warn("WAF blocked request",
					zap.String("event_id", eventID),
					zap.String("client_ip", clientIP.String()),
					zap.String("path", r.URL.Path),
					zap.String("rule_id", verdict.RuleID),
					zap.String("reason", verdict.Reason),
				)
			}

			statusCode := m.BlockStatusCode
			if verdict.StatusCode != 0 {
				statusCode = verdict.StatusCode
			}
			body := m.BlockResponseBody
			if appCfg != nil {
				if appCfg.BlockStatusCode != 0 {
					statusCode = appCfg.BlockStatusCode
				}
				if appCfg.BlockResponseBody != "" {
					body = appCfg.BlockResponseBody
				}
			}

			rendered := strings.ReplaceAll(body, "{{EVENT_ID}}", eventID)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("X-Raiwall-Event-ID", eventID)
			w.WriteHeader(statusCode)
			_, _ = w.Write([]byte(rendered))
			return nil
		} else if currentMode == config.ModeAudit && m.logger != nil {
			m.logger.Info("WAF audit event (threat detected, not blocked)",
				zap.String("client_ip", clientIP.String()),
				zap.String("path", r.URL.Path),
				zap.String("rule_id", verdict.RuleID),
				zap.String("reason", verdict.Reason),
			)
		}
	}

	// 9. Response Interception & Chaos Honeypot Injection
	interceptor := NewResponseInterceptor(w, m.StripHeaders)
	if m.HoneypotTrap != nil && *m.HoneypotTrap && m.honeypotInj != nil {
		interceptor.SetHoneypotInjector(m.honeypotInj)
	}

	// Forward downstream to next handler
	nextErr := next.ServeHTTP(interceptor, r)

	// Ensure any buffered HTML response is injected and finished
	interceptor.Finish()

	// Post-proxy response inspection
	respContext := &engine.ResponseContext{
		StatusCode: interceptor.StatusCode(),
		Headers:    interceptor.Header(),
		Duration:   time.Since(startTime),
		Context:    r.Context(),
	}

	respVerdict, _ := m.engine.InspectResponse(respContext)
	if respVerdict != nil && respVerdict.Action == engine.ActionBlock {
		if m.logger != nil {
			m.logger.Warn("WAF response verdict block",
				zap.Int("status_code", interceptor.StatusCode()),
				zap.String("rule_id", respVerdict.RuleID),
			)
		}
	}

	return nextErr
}
