package caddy

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/bot"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/telemetry"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// handleHoneypotTrap handles requests targeted at hidden trap endpoints.
func (m *Middleware) handleHoneypotTrap(w http.ResponseWriter, r *http.Request, clientIP net.IP, ja4 string, startTime time.Time) bool {
	if !bot.IsTrapRequest(r.URL.Path) {
		return false
	}
	if m.trapCtrl != nil {
		m.recordTelemetry(&telemetry.ForensicEvent{
			EventID:    uuid.New().String(),
			Timestamp:  startTime,
			Host:       r.Host,
			Path:       r.URL.RequestURI(),
			Method:     r.Method,
			ClientIP:   clientIP.String(),
			JA4:        ja4,
			GeoData:    m.lookupGeo(clientIP),
			RuleID:     "honeypot_trap",
			Action:     "ban",
			Severity:   "critical",
			Headers:    extractHeadersMap(r.Header),
			Latency:    time.Since(startTime),
			StatusCode: http.StatusForbidden,
		})
		m.trapCtrl.HandleTrap(w, r, clientIP, ja4)
		return true
	}
	w.WriteHeader(http.StatusForbidden)
	return true
}

// handleChallengeVerify handles the verification callback for solved PoW challenges.
func (m *Middleware) handleChallengeVerify(w http.ResponseWriter, r *http.Request, clientIP net.IP, ja4 string) bool {
	if r.URL.Path != bot.ChallengeVerifyPath {
		return false
	}
	if m.clearanceMgr != nil {
		m.clearanceMgr.HandleChallengeVerify(w, r, clientIP, ja4)
		return true
	}
	return false
}

// evaluateBotMitigation inspects client behavior against bot heuristics and PoW challenge gate.
func (m *Middleware) evaluateBotMitigation(w http.ResponseWriter, r *http.Request, clientIP net.IP, ja4 string, currentMode control.RunMode, startTime time.Time) (bool, error) {
	botDefenseMode := strings.ToLower(m.BotDefense)
	if botDefenseMode == "" || botDefenseMode == "off" || botDefenseMode == "disabled" {
		return false, nil
	}

	if m.routeClass == nil {
		m.routeClass = bot.NewRouteClassifier(nil)
	}
	if m.botClassifier == nil {
		m.botClassifier = bot.NewBotClassifier()
	}

	route := m.routeClass.Classify(r)
	botVerdict := m.botClassifier.Classify(r, ja4)

	if botVerdict != nil {
		if botVerdict.IsSpoofed || botVerdict.Action == waf.ActionBlock {
			if botDefenseMode == "audit" || currentMode == control.ModeAudit {
				if m.logger != nil {
					m.logger.Info("Bot defense audit event (threat detected, not blocked)",
						zap.String("client_ip", clientIP.String()),
						zap.String("ja4", ja4),
						zap.String("user_agent", r.UserAgent()),
						zap.String("reason", botVerdict.Reason),
					)
				}
			} else if currentMode == control.ModeDefense {
				if m.tier2Limiter != nil {
					_, _, _ = m.tier2Limiter.RecordAttack(r.Context(), clientIP, ja4, "BOT_SPOOF", botVerdict.Reason)
				}
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
				m.recordTelemetry(&telemetry.ForensicEvent{
					EventID:    eventID,
					Timestamp:  startTime,
					Host:       r.Host,
					Path:       r.URL.RequestURI(),
					Method:     r.Method,
					ClientIP:   clientIP.String(),
					JA4:        ja4,
					GeoData:    m.lookupGeo(clientIP),
					RuleID:     "bot_spoof",
					Action:     "block",
					Severity:   "high",
					Headers:    extractHeadersMap(r.Header),
					Latency:    time.Since(startTime),
					StatusCode: statusCode,
				})
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("X-Raiwall-Event-ID", eventID)
				w.WriteHeader(statusCode)
				rendered := strings.ReplaceAll(m.BlockResponseBody, "{{EVENT_ID}}", eventID)
				_, _ = w.Write([]byte(rendered))
				return true, nil
			}
		}
	}

	// Interactive challenge gate for browser routes
	if !bot.ShouldBypassChallenge(route) {
		isCleared := false
		if m.clearanceMgr != nil {
			isCleared = m.clearanceMgr.ValidateRequest(r, clientIP, ja4)
		}

		if !isCleared && botDefenseMode != "audit" && currentMode != control.ModeAudit {
			shouldChallenge := false
			if botDefenseMode == "challenge" || botDefenseMode == "strict" {
				shouldChallenge = true
			} else if currentMode == control.ModeDefense {
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
				m.recordTelemetry(&telemetry.ForensicEvent{
					EventID:    uuid.New().String(),
					Timestamp:  startTime,
					Host:       r.Host,
					Path:       r.URL.RequestURI(),
					Method:     r.Method,
					ClientIP:   clientIP.String(),
					JA4:        ja4,
					GeoData:    m.lookupGeo(clientIP),
					RuleID:     "pow_challenge",
					Action:     "challenge",
					Severity:   "medium",
					Headers:    extractHeadersMap(r.Header),
					Latency:    time.Since(startTime),
					StatusCode: 468,
				})
				return true, m.powEngine.RenderChallengePage(w, r, r.URL.RequestURI())
			}
		}
	}

	return false, nil
}
