package caddy

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/telemetry"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// forwardAndInspectResponse handles response interception, upstream proxying, scanner trap, and telemetry.
func (m *Middleware) forwardAndInspectResponse(
	w http.ResponseWriter,
	r *http.Request,
	clientIP net.IP,
	ja4 string,
	appCfg *control.AppConfig,
	currentMode control.RunMode,
	verdict *waf.Verdict,
	bodyBytes []byte,
	startTime time.Time,
	next caddyhttp.Handler,
) error {
	interceptor := NewResponseInterceptor(w, m.StripHeaders)
	if m.HoneypotTrap != nil && *m.HoneypotTrap && m.honeypotInj != nil {
		interceptor.SetHoneypotInjector(m.honeypotInj)
	}

	// Apply proxy settings: HSTS & SSE response headers
	if appCfg != nil && appCfg.ProxySettings != nil {
		if appCfg.ProxySettings.HSTS {
			isHTTPS := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
			if isHTTPS {
				interceptor.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
			}
		}
		if appCfg.ProxySettings.EnableSSE && strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
			interceptor.Header().Set("X-Accel-Buffering", "no")
			interceptor.Header().Set("Cache-Control", "no-cache")
		}
	}

	if m.metrics != nil {
		m.metrics.ActiveConnections.Inc()
		defer m.metrics.ActiveConnections.Dec()
	}

	var targetPool *UpstreamPool
	var matchedRule *control.ForwardingRule
	forwardReq := r

	if appCfg != nil && m.upstreamRegistry != nil {
		if len(appCfg.ForwardingRules) > 0 {
			matchedRule = MatchForwardingRule(appCfg.ForwardingRules, r.URL.Path)
			if matchedRule != nil && len(matchedRule.Upstreams) > 0 {
				targetPool = m.upstreamRegistry.GetOrCreatePool(matchedRule.Upstreams)
			}
		}
		if targetPool == nil && len(appCfg.Upstreams) > 0 {
			targetPool = m.upstreamRegistry.GetOrCreatePool(appCfg.Upstreams)
		}
	}

	var nextErr error
	if targetPool != nil {
		backend, err := targetPool.NextBackend()
		if err != nil {
			http.Error(interceptor, "Bad Gateway: "+err.Error(), http.StatusBadGateway)
			nextErr = err
		} else {
			forwardReq = r.Clone(r.Context())
			if matchedRule != nil {
				if matchedRule.StripPrefix && matchedRule.Prefix != "" && matchedRule.Prefix != "/" {
					cleanPrefix := strings.TrimSuffix(matchedRule.Prefix, "/")
					forwardReq.URL.Path = strings.TrimPrefix(forwardReq.URL.Path, cleanPrefix)
					if !strings.HasPrefix(forwardReq.URL.Path, "/") {
						forwardReq.URL.Path = "/" + forwardReq.URL.Path
					}
					if forwardReq.URL.RawPath != "" {
						forwardReq.URL.RawPath = strings.TrimPrefix(forwardReq.URL.RawPath, cleanPrefix)
						if !strings.HasPrefix(forwardReq.URL.RawPath, "/") {
							forwardReq.URL.RawPath = "/" + forwardReq.URL.RawPath
						}
					}
				}
				if matchedRule.HostHeaderOverride != "" {
					forwardReq.Host = matchedRule.HostHeaderOverride
				}
			}
			var transport http.RoundTripper = http.DefaultTransport
			if m.upstreamRegistry != nil && m.upstreamRegistry.SharedTransport() != nil {
				transport = m.upstreamRegistry.SharedTransport()
			}
			nextErr = ProxyToBackend(interceptor, forwardReq, backend.Dial, transport)
		}
	} else if next != nil {
		nextErr = next.ServeHTTP(interceptor, forwardReq)
	} else {
		interceptor.WriteHeader(http.StatusBadGateway)
		_, _ = interceptor.Write([]byte("Raiwall Gateway: No upstream backend configured for this host. Configure protected applications in the Web Dashboard at /.raiwall/#/sites\n"))
	}

	// Record clean transit traffic to passive API cataloger
	if m.discoveryCataloger != nil && appCfg != nil {
		m.discoveryCataloger.RecordRequest(appCfg.ID, r.Method, r.URL.Path, r.Header.Get("Content-Type"))
	}

	// Ensure any buffered HTML response is injected and finished
	interceptor.Finish()

	// Tier 3 Scanner Trap response inspection
	if m.tier3Trap != nil && currentMode == control.ModeDefense {
		_, _, _ = m.tier3Trap.InspectResponse(r.Context(), r, clientIP, ja4, interceptor.StatusCode())
	}

	// Post-proxy response inspection
	respContext := &waf.ResponseContext{
		StatusCode: interceptor.StatusCode(),
		Headers:    interceptor.Header(),
		Duration:   time.Since(startTime),
		Context:    r.Context(),
	}

	respVerdict, _ := m.engine.InspectResponse(respContext)
	if respVerdict != nil && respVerdict.Action == waf.ActionBlock {
		if m.logger != nil {
			m.logger.Warn("WAF response verdict block",
				zap.Int("status_code", interceptor.StatusCode()),
				zap.String("rule_id", respVerdict.RuleID),
			)
		}
	}

	action := "allow"
	severity := "info"
	ruleID := ""
	location, token, category := "", "", ""
	if verdict != nil {
		location, token, category = verdict.PayloadLocation, verdict.MatchedToken, verdict.AttackCategory
	}
	if verdict != nil && verdict.Action == waf.ActionBlock && currentMode == control.ModeAudit {
		action = "audit"
		severity = "medium"
		ruleID = verdict.RuleID
	}
	m.recordTelemetry(&telemetry.ForensicEvent{
		EventID:          uuid.New().String(),
		Timestamp:        startTime,
		Host:             r.Host,
		Path:             r.URL.RequestURI(),
		Method:           r.Method,
		ClientIP:         clientIP.String(),
		JA4:              ja4,
		GeoData:          m.lookupGeo(clientIP),
		RuleID:           ruleID,
		Action:           action,
		Severity:         severity,
		Headers:          extractHeadersMap(r.Header),
		TruncatedPayload: string(bodyBytes),
		Latency:          time.Since(startTime),
		StatusCode:       interceptor.StatusCode(),
		PayloadLocation:  normalizePayloadLocation(location),
		MatchedToken:     token,
		AttackCategory:   category,
		ResponseHeaders:  cloneHeaderMap(interceptor.Header()),
	})

	return nextErr
}
