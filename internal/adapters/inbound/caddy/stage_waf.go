package caddy

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/telemetry"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// inspectWAFRequest buffers the request body if within limits and executes WAF threat inspection.
func (m *Middleware) inspectWAFRequest(
	w http.ResponseWriter,
	r *http.Request,
	clientIP net.IP,
	ja4 string,
	appCfg *control.AppConfig,
	currentMode control.RunMode,
	aclBypassWAF bool,
	startTime time.Time,
) (*waf.Verdict, []byte, bool, error) {
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

	reqContext := &waf.RequestContext{
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

	var verdict *waf.Verdict
	var err error
	if !aclBypassWAF {
		if m.engine == nil {
			m.engine = waf.NewPassthroughEngine()
		}

		verdict, err = m.engine.InspectRequest(reqContext)
		if err != nil && m.logger != nil {
			m.logger.Error("WAF inspection error", zap.Error(err))
		}
	}

	if verdict != nil && verdict.Action == waf.ActionBlock {
		if currentMode == control.ModeDefense {
			if m.tier2Limiter != nil {
				_, _, _ = m.tier2Limiter.RecordAttack(r.Context(), clientIP, ja4, verdict.RuleID, verdict.Reason)
			}
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

			rendered := m.renderBlockResponse(statusCode, eventID, clientIP.String(), r.Host, r.URL.Path, body)
			m.recordTelemetry(&telemetry.ForensicEvent{
				EventID:          eventID,
				Timestamp:        startTime,
				Host:             r.Host,
				Path:             r.URL.RequestURI(),
				Method:           r.Method,
				ClientIP:         clientIP.String(),
				JA4:              ja4,
				GeoData:          m.lookupGeo(clientIP),
				RuleID:           verdict.RuleID,
				Action:           "block",
				Severity:         "critical",
				Headers:          extractHeadersMap(r.Header),
				TruncatedPayload: string(bodyBytes),
				Latency:          time.Since(startTime),
				StatusCode:       statusCode,
			})
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("X-Raiwall-Event-ID", eventID)
			w.WriteHeader(statusCode)
			_, _ = w.Write([]byte(rendered))
			return verdict, bodyBytes, true, nil
		} else if currentMode == control.ModeAudit && m.logger != nil {
			m.logger.Info("WAF audit event (threat detected, not blocked)",
				zap.String("client_ip", clientIP.String()),
				zap.String("path", r.URL.Path),
				zap.String("rule_id", verdict.RuleID),
				zap.String("reason", verdict.Reason),
			)
		}
	}

	return verdict, bodyBytes, false, err
}
