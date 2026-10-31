package api

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/waf"
)

// RuleTestRequest is a synthetic request evaluated against the live WAF
// engine (semantic funnel + CRS if enabled).
type RuleTestRequest struct {
	AppID      string            `json:"app_id,omitempty"`
	Method     string            `json:"method,omitempty"`
	Host       string            `json:"host,omitempty"`
	Path       string            `json:"path,omitempty"`
	Query      string            `json:"query,omitempty"`
	ClientIP   string            `json:"client_ip,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
	BodyBase64 string            `json:"body_base64,omitempty"`
}

// RuleTestResult is the verdict and evaluation latency for a synthetic request.
type RuleTestResult struct {
	Verdict    *waf.Verdict `json:"verdict"`
	DurationMS float64      `json:"duration_ms"`
}

// SetRuleTester installs the engine evaluator used by /rules/test.
func (s *Server) SetRuleTester(fn func(*waf.RequestContext) (*waf.Verdict, error)) {
	s.ruleTester = fn
}

func (s *Server) handleRuleTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.ruleTester == nil {
		respondError(w, http.StatusServiceUnavailable, "rule tester is not configured")
		return
	}

	var req RuleTestRequest
	body := http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	if req.Method == "" {
		req.Method = http.MethodGet
	}
	if req.Path == "" {
		req.Path = "/"
	}
	if req.Host == "" {
		req.Host = "rules.test"
	}

	var payload []byte
	if req.BodyBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(req.BodyBase64)
		if err != nil {
			respondError(w, http.StatusBadRequest, "invalid body_base64: "+err.Error())
			return
		}
		payload = decoded
	} else if req.Body != "" {
		payload = []byte(req.Body)
	}

	headers := make(http.Header, len(req.Headers))
	for key, value := range req.Headers {
		headers.Set(key, value)
	}

	var clientIP net.IP
	if req.ClientIP != "" {
		clientIP = net.ParseIP(req.ClientIP)
		if clientIP == nil {
			respondError(w, http.StatusBadRequest, "invalid client_ip")
			return
		}
	}

	probe := &waf.RequestContext{
		ClientIP: clientIP,
		Method:   req.Method,
		Host:     req.Host,
		Path:     req.Path,
		Query:    req.Query,
		Headers:  headers,
		Body:     payload,
		AppID:    req.AppID,
		Context:  r.Context(),
	}

	start := time.Now()
	verdict, err := s.ruleTester(probe)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "inspect: "+err.Error())
		return
	}
	if verdict == nil {
		verdict = waf.VerdictAllow
	}

	respondJSON(w, http.StatusOK, RuleTestResult{
		Verdict:    verdict,
		DurationMS: float64(time.Since(start).Microseconds()) / 1000,
	})
}
