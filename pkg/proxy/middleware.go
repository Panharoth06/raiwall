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
	"github.com/raiwall/raiwall/pkg/config"
	"github.com/raiwall/raiwall/pkg/engine"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Middleware{})
}

// MaxInspectionBodySize is the maximum body size buffered for threat inspection (1 MB).
const MaxInspectionBodySize = 1024 * 1024

// Middleware is the Caddy HTTP handler implementing Raiwall WAF and Gateway interception.
type Middleware struct {
	Mode                string   `json:"mode,omitempty"`
	BlockStatusCode     int      `json:"block_status_code,omitempty"`
	BlockResponseBody   string   `json:"block_response_body,omitempty"`
	OfflineStatusCode   int      `json:"offline_status_code,omitempty"`
	OfflineResponseBody string   `json:"offline_response_body,omitempty"`
	StripHeaders        []string `json:"strip_headers,omitempty"`

	engine     engine.WAFEngine
	logger     *zap.Logger
	bufferPool *sync.Pool
	runMode    config.RunMode
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
		m.engine = engine.NewPassthroughEngine()
	}

	m.bufferPool = &sync.Pool{
		New: func() any {
			return new(bytes.Buffer)
		},
	}

	return nil
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

	// 1. Extract real client IP and store in request context
	clientIP := ExtractClientIP(r)
	ctx := WithClientIP(r.Context(), clientIP)
	r = r.WithContext(ctx)

	// 2. Resolve operational run mode from in-memory snapshot with fallback
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

	// 3. Phase 1 - Evaluate Offline Mode immediately
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

	// 4. Phase 1 - Request Inspection
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

	// 5. Phase 2 - Response Interception Wrapper
	interceptor := NewResponseInterceptor(w, m.StripHeaders)

	// Forward downstream to next handler
	nextErr := next.ServeHTTP(interceptor, r)

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
