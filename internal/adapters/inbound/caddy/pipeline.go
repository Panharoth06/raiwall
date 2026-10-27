package caddy

import (
	"net/http"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/bot"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/rate"
	"github.com/Panharoth06/raiwall/internal/core/telemetry"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	startTime := time.Now()

	// 1. Internal WAF routes
	if m.serveInternalRoutes(w, r) {
		return nil
	}

	// 2. Resolve operational run mode & app config from in-memory snapshot
	currentMode := m.runMode
	if !currentMode.IsValid() {
		currentMode = control.ModeDefense
	}

	snap := control.LoadSnapshot()
	var appCfg *control.AppConfig
	if snap != nil {
		if app, found := snap.GetAppForHost(r.Host); found && app != nil {
			appCfg = app
			if app.Mode.IsValid() {
				currentMode = app.Mode
			}
		} else if snap.Version > 1 && snap.DefaultMode.IsValid() {
			currentMode = snap.DefaultMode
		}
	}

	// No site for this host means there is no upstream to protect: send browser
	// navigations to the dashboard instead of a bot challenge or 502.
	if appCfg == nil && snap != nil && m.redirectUnconfiguredHost(w, r) {
		return nil
	}

	// HTTP-to-HTTPS automatic 301 redirection if enabled in proxy settings
	if appCfg != nil && appCfg.ProxySettings != nil && appCfg.ProxySettings.RedirectHTTP {
		isHTTPS := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
		if !isHTTPS {
			target := "https://" + r.Host + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently)
			return nil
		}
	}

	// 3. Extract real client IP and JA4 fingerprint
	clientIPSource := ""
	if appCfg != nil && appCfg.ProxySettings != nil {
		clientIPSource = appCfg.ProxySettings.ClientIPSource
	}
	clientIP := ExtractClientIPWithSource(r, clientIPSource)
	ja4 := bot.ExtractJA4(r)
	ctx := WithClientIP(r.Context(), clientIP)
	if ja4 != "" {
		ctx = bot.WithJA4(ctx, ja4)
	}
	r = r.WithContext(ctx)

	// Enforce X-Forwarded-For rewrite (stripping outer untrusted client headers)
	if appCfg != nil && appCfg.ProxySettings != nil && appCfg.ProxySettings.RewriteXFF && clientIP != nil {
		r.Header.Set("X-Forwarded-For", clientIP.String())
	}

	// Compression policy: when per-site compression is off, strip the client
	// Accept-Encoding upstream so bodies arrive uncompressed and remain fully
	// inspectable by the WAF (and block pages). Enabled keeps native encoding.
	if appCfg != nil && appCfg.ProxySettings != nil && !appCfg.ProxySettings.EnableCompression {
		r.Header.Del("Accept-Encoding")
	}

	// 4. Evaluate Offline Mode immediately
	if currentMode == control.ModeOffline {
		statusCode := m.OfflineStatusCode
		if statusCode == 0 {
			statusCode = 466
		}
		body := m.OfflineResponseBody
		if appCfg != nil {
			if appCfg.OfflineStatusCode != 0 {
				statusCode = appCfg.OfflineStatusCode
			}
			if appCfg.OfflineResponseBody != "" {
				body = appCfg.OfflineResponseBody
			}
		}
		eventID := uuid.New().String()
		clientIPStr := ""
		if clientIP != nil {
			clientIPStr = clientIP.String()
		}
		rendered := m.renderBlockResponse(statusCode, eventID, clientIPStr, r.Host, r.URL.Path, body)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Retry-After", "300")
		w.Header().Set("X-Raiwall-Event-ID", eventID)
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(rendered))
		return nil
	}

	// 5. Fast-Path: Check Auto-Ban state
	if m.banManager != nil {
		if banned, entry := m.banManager.IsBanned(clientIP, ja4); banned {
			if currentMode == control.ModeAudit {
				if m.logger != nil {
					m.logger.Info("Banned client detected in audit mode (not blocked)",
						zap.String("client_ip", clientIP.String()),
						zap.String("ja4", ja4),
						zap.String("reason", entry.Reason),
					)
				}
			} else {
				eventID := uuid.New().String()
				if m.logger != nil {
					m.logger.Warn("Blocked auto-banned client (ban store)",
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
				m.recordTelemetry(&telemetry.ForensicEvent{
					EventID:    eventID,
					Timestamp:  startTime,
					Host:       r.Host,
					Path:       r.URL.RequestURI(),
					Method:     r.Method,
					ClientIP:   clientIP.String(),
					JA4:        ja4,
					GeoData:    m.lookupGeo(clientIP),
					RuleID:     "ban_manager",
					Action:     "ban",
					Severity:   "high",
					Headers:    extractHeadersMap(r.Header),
					Latency:    time.Since(startTime),
					StatusCode: statusCode,
				})
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("X-Raiwall-Event-ID", eventID)
				w.WriteHeader(statusCode)
				banMsg := m.renderBlockResponse(statusCode, eventID, clientIP.String(), r.Host, r.URL.Path, m.BlockResponseBody)
				_, _ = w.Write([]byte(banMsg))
				return nil
			}
		}
	}

	// 6. Waiting Room SSE Endpoint
	if r.URL.Path == rate.WaitingRoomEventsPath {
		if m.waitingRoom != nil {
			m.waitingRoom.HandleSSE(w, r, clientIP, ja4)
			return nil
		}
		http.Error(w, "Waiting room not active", http.StatusNotFound)
		return nil
	}

	// 7. Honeypot Trap Interception
	if m.handleHoneypotTrap(w, r, clientIP, ja4, startTime) {
		return nil
	}

	// 8. Internal Challenge Verification Endpoint
	if m.handleChallengeVerify(w, r, clientIP, ja4) {
		return nil
	}

	// 9. Virtual Waiting Room Gate
	waitingRoomRelease, handledQueue, queueErr := m.handleWaitingRoom(w, r, clientIP, ja4)
	if handledQueue {
		return queueErr
	}
	if waitingRoomRelease != nil {
		defer waitingRoomRelease()
	}

	// 10. Tier 1 Access Velocity Limiter
	if allowed, err := m.enforceTier1(w, r, clientIP, ja4); !allowed {
		return err
	}

	// 11. Bot Mitigation & Route Classification
	if handledBot, err := m.evaluateBotMitigation(w, r, clientIP, ja4, currentMode, startTime); handledBot {
		return err
	}

	// 11b. Zero-Trust Auth Gate (HTTP 467 portal: per-site or portal-wide)
	if handledGate, err := m.evaluateAuthGate(w, r, clientIP, appCfg); handledGate {
		return err
	}

	// 12. Pre-App Auth & Compiled Bytecode ACLs
	aclBypassWAF, handledACL, err := m.evaluateAccessControl(w, r, clientIP, ja4, appCfg, currentMode, startTime)
	if handledACL {
		return err
	}

	// 13. WAF Request Inspection
	verdict, bodyBytes, handledWAF, _ := m.inspectWAFRequest(w, r, clientIP, ja4, appCfg, currentMode, aclBypassWAF, startTime)
	if handledWAF {
		return nil
	}

	// 14. Response Interception & Forwarding
	return m.forwardAndInspectResponse(w, r, clientIP, ja4, appCfg, currentMode, verdict, bodyBytes, startTime, next)
}
