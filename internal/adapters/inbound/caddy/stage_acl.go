package caddy

import (
	"net"
	"net/http"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/auth"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/telemetry"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// evaluateAccessControl executes pre-app auth, bytecode ACL rules, and BART threat feed lookups.
func (m *Middleware) evaluateAccessControl(
	w http.ResponseWriter,
	r *http.Request,
	clientIP net.IP,
	ja4 string,
	appCfg *control.AppConfig,
	currentMode control.RunMode,
	startTime time.Time,
) (bypassWAF bool, handled bool, err error) {
	// Pre-Application Authentication is enforced by the shared HTTP 467 gate
	// earlier in the pipeline. Sites without any auth authority still strip
	// untrusted client-supplied identity headers.
	if (appCfg == nil || !appCfg.AuthEnabled) && m.globalAuthGate == nil {
		auth.StripAuthHeaders(r.Header)
	}

	// Compiled Bytecode ACL Rules & Threat Feeds
	if m.aclEngine != nil || m.bartTable != nil {
		aclReqCtx := &waf.RequestContext{
			ClientIP:  clientIP,
			Method:    r.Method,
			Host:      r.Host,
			Path:      r.URL.Path,
			Query:     r.URL.RawQuery,
			Headers:   r.Header,
			UserAgent: r.UserAgent(),
			JA4:       ja4,
			Context:   r.Context(),
		}
		if appCfg != nil {
			aclReqCtx.AppID = appCfg.ID
		}

		if m.aclEngine != nil {
			aclVerdict, evalErr := m.aclEngine.EvaluateRequest(aclReqCtx)
			if evalErr != nil && m.logger != nil {
				m.logger.Error("ACL evaluation error", zap.Error(evalErr))
			}
			if aclVerdict != nil && aclVerdict.Matched {
				switch aclVerdict.Action {
				case acl.ActionBlock:
					if currentMode == control.ModeAudit {
						if m.logger != nil {
							m.logger.Info("ACL block rule matched in audit mode (not blocked)",
								zap.String("client_ip", clientIP.String()),
								zap.String("rule", aclVerdict.RuleName),
								zap.String("reason", aclVerdict.Reason),
							)
						}
						break
					}
					statusCode := aclVerdict.StatusCode
					if statusCode == 0 {
						statusCode = http.StatusForbidden
					}
					eventID := uuid.New().String()
					if m.logger != nil {
						m.logger.Warn("ACL rule blocked request",
							zap.String("event_id", eventID),
							zap.String("client_ip", clientIP.String()),
							zap.String("rule", aclVerdict.RuleName),
							zap.String("reason", aclVerdict.Reason),
						)
					}
					body := m.BlockResponseBody
					if appCfg != nil {
						if appCfg.BlockStatusCode != 0 && aclVerdict.StatusCode == 0 {
							statusCode = appCfg.BlockStatusCode
						}
						if appCfg.BlockResponseBody != "" {
							body = appCfg.BlockResponseBody
						}
					}
					if body == "" {
						body = defaultBlockHTML
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
						RuleID:     aclVerdict.RuleName,
						Action:     "block",
						Severity:   "high",
						Headers:    extractHeadersMap(r.Header),
						Latency:    time.Since(startTime),
						StatusCode: statusCode,
					})
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.Header().Set("X-Raiwall-Event-ID", eventID)
					w.WriteHeader(statusCode)
					rendered := m.renderBlockResponse(statusCode, eventID, clientIP.String(), r.Host, r.URL.Path, body)
					_, _ = w.Write([]byte(rendered))
					return false, true, nil

				case acl.ActionChallenge:
					if currentMode == control.ModeAudit {
						if m.logger != nil {
							m.logger.Info("ACL challenge rule matched in audit mode (not challenged)",
								zap.String("client_ip", clientIP.String()),
								zap.String("rule", aclVerdict.RuleName),
							)
						}
						break
					}
					if m.powEngine != nil {
						m.recordTelemetry(&telemetry.ForensicEvent{
							EventID:    uuid.New().String(),
							Timestamp:  startTime,
							Host:       r.Host,
							Path:       r.URL.RequestURI(),
							Method:     r.Method,
							ClientIP:   clientIP.String(),
							JA4:        ja4,
							GeoData:    m.lookupGeo(clientIP),
							RuleID:     aclVerdict.RuleName,
							Action:     "challenge",
							Severity:   "medium",
							Headers:    extractHeadersMap(r.Header),
							Latency:    time.Since(startTime),
							StatusCode: 468,
						})
						return false, true, m.powEngine.RenderChallengePage(w, r, r.URL.RequestURI())
					}

				case acl.ActionRedirect:
					statusCode := aclVerdict.StatusCode
					if statusCode == 0 {
						statusCode = http.StatusFound
					}
					http.Redirect(w, r, aclVerdict.RedirectURL, statusCode)
					return false, true, nil

				case acl.ActionAllow:
					bypassWAF = true

				case acl.ActionAudit:
					if m.logger != nil {
						m.logger.Info("ACL audit rule matched",
							zap.String("client_ip", clientIP.String()),
							zap.String("rule", aclVerdict.RuleName),
							zap.String("reason", aclVerdict.Reason),
						)
					}
				}
			}
		}

		// Direct BART Threat Feed fast-path check
		if !bypassWAF && m.bartTable != nil {
			if meta, found := m.bartTable.Lookup(clientIP); found && len(meta.Feeds) > 0 {
				var threatFeeds []string
				for _, f := range meta.Feeds {
					if m.ipGroupMgr != nil {
						if grp, ok := m.ipGroupMgr.GetGroup(f); ok {
							if grp.Type == "threat_feed" || grp.Name == "malicious_threat_intel" {
								threatFeeds = append(threatFeeds, f)
							}
							continue
						}
					}
					threatFeeds = append(threatFeeds, f)
				}

				if len(threatFeeds) > 0 {
					if currentMode == control.ModeAudit {
						if m.logger != nil {
							m.logger.Info("Threat feed matched client IP in audit mode (not blocked)",
								zap.String("client_ip", clientIP.String()),
								zap.Strings("feeds", threatFeeds),
							)
						}
					} else {
						eventID := uuid.New().String()
						if m.logger != nil {
							m.logger.Warn("Threat feed blocked client IP",
								zap.String("event_id", eventID),
								zap.String("client_ip", clientIP.String()),
								zap.Strings("feeds", threatFeeds),
							)
						}
						statusCode := m.BlockStatusCode
						if statusCode == 0 {
							statusCode = http.StatusForbidden
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
						if body == "" {
							body = defaultBlockHTML
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
							RuleID:     "threat_feed",
							Action:     "block",
							Severity:   "high",
							Headers:    extractHeadersMap(r.Header),
							Latency:    time.Since(startTime),
							StatusCode: statusCode,
						})
						w.Header().Set("Content-Type", "text/html; charset=utf-8")
						w.Header().Set("X-Raiwall-Event-ID", eventID)
						w.WriteHeader(statusCode)
						rendered := m.renderBlockResponse(statusCode, eventID, clientIP.String(), r.Host, r.URL.Path, body)
						_, _ = w.Write([]byte(rendered))
						return false, true, nil
					}
				}
			}
		}
	}

	return bypassWAF, false, nil
}
