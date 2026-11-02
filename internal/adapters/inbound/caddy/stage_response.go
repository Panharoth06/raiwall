package caddy

import (
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/telemetry"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/Panharoth06/raiwall/internal/core/waf/bodyinspect"
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
	session any,
	startTime time.Time,
	next caddyhttp.Handler,
) error {
	if session != nil {
		if closer, ok := session.(io.Closer); ok {
			defer closer.Close()
		}
	}
	interceptor := NewResponseInterceptor(w, m.StripHeaders)
	if m.HoneypotTrap != nil && *m.HoneypotTrap && m.honeypotInj != nil {
		interceptor.SetHoneypotInjector(m.honeypotInj)
	}

	snap := control.GetActiveSnapshot()
	appID := ""
	if appCfg != nil {
		appID = appCfg.ID
	}
	respCfg := m.responseConfigFor(snap, appID)
	if respCfg.Enabled {
		interceptor.SetInspectionConfig(ResponseInspectionConfig{
			Enabled:        true,
			InspectHeaders: respCfg.InspectHeaders,
			InspectBody:    respCfg.InspectBody,
			BodyLimit:      respCfg.BodyLimit,
			HardCap:        respCfg.HardCap,
			Decompress:     respCfg.Decompress,
			ContentTypes:   respCfg.ContentTypes,
			Budget:         m.inflightBudget,
		})
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

	routing := control.RoutingProxy
	if appCfg != nil && appCfg.RoutingType != "" {
		routing = appCfg.RoutingType
	}

	var nextErr error
	switch routing {
	case control.RoutingRedirect:
		nextErr = m.serveRedirect(interceptor, r, appCfg)
	case control.RoutingStatic:
		nextErr = m.serveStatic(interceptor, r, appCfg)
	default:
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

		if targetPool != nil {
			clientIPStr := ""
			if clientIP != nil {
				clientIPStr = clientIP.String()
			}
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
			if IsWebSocketUpgrade(forwardReq) {
				// Upgrades cannot be buffered through RoundTrip, so splice the
				// hijacked connection to a single selected backend.
				backend, release, err := targetPool.SelectBackend(appCfg.LoadBalancing, clientIPStr)
				if err != nil {
					http.Error(interceptor, "Bad Gateway: "+err.Error(), http.StatusBadGateway)
					nextErr = err
				} else {
					defer release()
					nextErr = ProxyWebSocket(interceptor, forwardReq, backend.Dial, 0)
				}
			} else {
				nextErr = ProxyWithFailover(interceptor, forwardReq, targetPool, appCfg.LoadBalancing, clientIPStr, transport, defaultProxyAttempts)
			}
		} else if next != nil {
			nextErr = next.ServeHTTP(interceptor, forwardReq)
		} else {
			interceptor.WriteHeader(http.StatusBadGateway)
			_, _ = interceptor.Write([]byte("Raiwall Gateway: No upstream backend configured for this host. Configure protected applications in the Web Dashboard at /.raiwall/#/sites\n"))
		}
	}

	// Record clean transit traffic to passive API cataloger
	if m.discoveryCataloger != nil && appCfg != nil {
		m.discoveryCataloger.RecordRequest(appCfg.ID, r.Method, r.URL.Path, r.Header.Get("Content-Type"))
	}

	// Post-proxy response inspection & DLP
	var respVerdict *waf.Verdict
	redactedBody := false

	if respCfg.Enabled && !interceptor.IsStreamed() {
		inspectBody := interceptor.BufferedBody()
		ct := interceptor.Header().Get("Content-Type")
		if !isInspectableContentType(ct, respCfg.ContentTypes) {
			inspectBody = nil
		}
		ce := strings.ToLower(interceptor.Header().Get("Content-Encoding"))
		isCompressed := ce != "" && ce != "identity"
		if isCompressed && respCfg.Decompress && len(inspectBody) > 0 {
			if decoded, decodeErr := bodyinspect.Decode(inspectBody, ce, int64(respCfg.BodyLimit)); decodeErr == nil {
				inspectBody = decoded
			}
		} else if len(inspectBody) > respCfg.BodyLimit {
			inspectBody = inspectBody[:respCfg.BodyLimit]
		}

		respContext := &waf.ResponseContext{
			StatusCode:       interceptor.StatusCode(),
			Headers:          interceptor.Header(),
			Body:             inspectBody,
			Duration:         time.Since(startTime),
			Context:          r.Context(),
			Session:          session,
			AppID:            appID,
			ContentType:      interceptor.Header().Get("Content-Type"),
			InspectResponse:  true,
			ResponseEligible: len(inspectBody) > 0,
		}

		// 1. Evaluate Coraza outbound rules (paired transaction)
		if m.engine != nil {
			cv, err := m.engine.InspectResponse(respContext)
			if err != nil && m.logger != nil {
				m.logger.Warn("CRS response inspection error", zap.Error(err))
			}
			if cv != nil && cv.Action != waf.ActionAllow {
				respVerdict = cv
			}
		}

		// 2. Evaluate DLP detectors (PAN, secrets, JWT, private keys, headers)
		if respCfg.DLP.Enabled {
			dlpEngine, err := m.dlpEngineFor(respCfg)
			if err != nil && m.logger != nil {
				m.logger.Warn("failed to compile DLP engine", zap.Error(err))
			} else if dlpEngine != nil {
				dlpRes := dlpEngine.Inspect(respContext)
				if dlpRes != nil && len(dlpRes.Findings) > 0 {
					if dlpRes.Redacted && len(dlpRes.Body) > 0 {
						if isCompressed {
							interceptor.Header().Del("Content-Encoding")
						}
						interceptor.ReplaceBody(dlpRes.Body)
						redactedBody = true
					}
					if dlpRes.Verdict != nil && dlpRes.Verdict.Action != waf.ActionAllow {
						if respVerdict == nil || dlpRes.Verdict.Action == waf.ActionBlock {
							respVerdict = dlpRes.Verdict
						}
					}
				}
			}
		}
	}

	// If blocked by response inspection, serve block page instead of upstream body
	if respVerdict != nil && respVerdict.Action == waf.ActionBlock && currentMode == control.ModeDefense {
		eventID := uuid.New().String()
		if m.logger != nil {
			m.logger.Warn("WAF response verdict block",
				zap.String("event_id", eventID),
				zap.Int("status_code", interceptor.StatusCode()),
				zap.String("rule_id", respVerdict.RuleID),
				zap.String("reason", respVerdict.Reason),
			)
		}
		if m.tier2Limiter != nil {
			_, _, _ = m.tier2Limiter.RecordAttack(r.Context(), clientIP, ja4, respVerdict.RuleID, respVerdict.Reason)
		}

		statusCode := m.BlockStatusCode
		if respVerdict.StatusCode != 0 {
			statusCode = respVerdict.StatusCode
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

		rendered := m.renderBlockResponse(statusCode, eventID, clientIP.String(), r.Host, r.URL.Path, body)
		interceptor.WriteBlockResponse(statusCode, rendered, eventID)

		event := &telemetry.ForensicEvent{
			EventID:          eventID,
			Timestamp:        startTime,
			Host:             r.Host,
			Path:             r.URL.RequestURI(),
			Method:           r.Method,
			ClientIP:         clientIP.String(),
			JA4:              ja4,
			GeoData:          m.lookupGeo(clientIP),
			RuleID:           respVerdict.RuleID,
			Action:           "block",
			Severity:         severityForVerdict(respVerdict),
			Headers:          extractHeadersMap(r.Header),
			TruncatedPayload: string(bodyBytes),
			Latency:          time.Since(startTime),
			StatusCode:       statusCode,
			PayloadLocation:  normalizePayloadLocation(respVerdict.PayloadLocation),
			MatchedToken:     respVerdict.MatchedToken,
			AttackCategory:   respVerdict.AttackCategory,
			ResponseHeaders:  map[string][]string{"Content-Type": {"text/html; charset=utf-8"}},
			ResponseBody:     []byte(rendered),
		}
		applyVerdictMetadata(event, respVerdict)
		m.recordTelemetry(event)
		return nil
	}

	// Ensure any buffered response is injected and finished
	interceptor.Finish()

	action := "allow"
	severity := "info"
	ruleID := ""
	location, token, category := "", "", ""
	if verdict != nil {
		location, token, category = verdict.PayloadLocation, verdict.MatchedToken, verdict.AttackCategory
	}
	if respVerdict != nil && (verdict == nil || verdict.Action == waf.ActionAllow) {
		location, token, category = respVerdict.PayloadLocation, respVerdict.MatchedToken, respVerdict.AttackCategory
	}
	switch {
	case verdict != nil && verdict.Action == waf.ActionBlock && currentMode == control.ModeAudit:
		action = "audit"
		severity = "medium"
		ruleID = verdict.RuleID
	case verdict != nil && verdict.Action == waf.ActionAudit:
		action = "audit"
		severity = "low"
		ruleID = verdict.RuleID
	case respVerdict != nil && respVerdict.Action == waf.ActionBlock && currentMode == control.ModeAudit:
		action = "audit"
		severity = severityForVerdict(respVerdict)
		ruleID = respVerdict.RuleID
	case respVerdict != nil && respVerdict.Action == waf.ActionAudit:
		action = "audit"
		if redactedBody {
			action = "redact"
		}
		severity = severityForVerdict(respVerdict)
		ruleID = respVerdict.RuleID
	}

	var respBody []byte
	if interceptor.BufferedBody() != nil {
		buf := interceptor.BufferedBody()
		if len(buf) > 65536 {
			buf = buf[:65536]
		}
		respBody = append([]byte(nil), buf...)
	}

	event := &telemetry.ForensicEvent{
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
		ResponseBody:     respBody,
	}
	metadataVerdict := verdict
	if metadataVerdict == nil {
		metadataVerdict = respVerdict
	}
	applyVerdictMetadata(event, metadataVerdict)
	m.recordTelemetry(event)

	return nextErr
}
