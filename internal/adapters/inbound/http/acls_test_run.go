package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Panharoth06/raiwall/internal/core/acl"
)

// ACLSampleRequestDTO provides test input fields for expr rule simulation.
type ACLSampleRequestDTO struct {
	IP        string            `json:"ip"`
	ClientIP  string            `json:"client_ip"`
	JA4       string            `json:"ja4"`
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Host      string            `json:"host"`
	Headers   map[string]string `json:"headers"`
	Cookies   map[string]string `json:"cookies"`
	Query     map[string]string `json:"query"`
	UserAgent string            `json:"user_agent"`
}

// ACLTestRequest encapsulates a dry-run test request for expr rules.
type ACLTestRequest struct {
	Expression    string              `json:"expression"`
	SampleRequest ACLSampleRequestDTO `json:"sample_request"`
}

// ACLTestResponse represents the outcome of the expr simulation.
type ACLTestResponse struct {
	Valid   bool   `json:"valid"`
	Matched bool   `json:"matched"`
	Error   string `json:"error,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

func (s *Server) handleTestACL(w http.ResponseWriter, r *http.Request) {
	var raw struct {
		Expression    string              `json:"expression"`
		SampleRequest ACLSampleRequestDTO `json:"sample_request"`
		Request       map[string]any      `json:"request"`
	}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	req := ACLTestRequest{
		Expression:    raw.Expression,
		SampleRequest: raw.SampleRequest,
	}

	if raw.Request != nil {
		for k, v := range raw.Request {
			valStr := fmt.Sprintf("%v", v)
			switch strings.ToLower(k) {
			case "clientip", "client_ip", "ip":
				req.SampleRequest.ClientIP = valStr
				req.SampleRequest.IP = valStr
			case "path":
				req.SampleRequest.Path = valStr
			case "method":
				req.SampleRequest.Method = valStr
			case "host":
				req.SampleRequest.Host = valStr
			case "ja4":
				req.SampleRequest.JA4 = valStr
			case "useragent", "user_agent":
				req.SampleRequest.UserAgent = valStr
			}
		}
	}

	rule := acl.ACLRule{
		Name:       "dry-run-rule",
		Expression: req.Expression,
	}
	if err := rule.Compile(nil); err != nil {
		respondJSON(w, http.StatusOK, ACLTestResponse{
			Valid:   false,
			Matched: false,
			Error:   err.Error(),
			Reason:  "expression compilation failed",
		})
		return
	}

	env := &acl.EvalEnv{
		IP:        req.SampleRequest.IP,
		ClientIP:  req.SampleRequest.ClientIP,
		JA4:       req.SampleRequest.JA4,
		Method:    req.SampleRequest.Method,
		Path:      req.SampleRequest.Path,
		Host:      req.SampleRequest.Host,
		Headers:   req.SampleRequest.Headers,
		Cookies:   req.SampleRequest.Cookies,
		Query:     req.SampleRequest.Query,
		UserAgent: req.SampleRequest.UserAgent,
	}
	if env.ClientIP == "" && env.IP != "" {
		env.ClientIP = env.IP
	}
	if env.IP == "" && env.ClientIP != "" {
		env.IP = env.ClientIP
	}

	matched, err := rule.Eval(env)
	if err != nil {
		respondJSON(w, http.StatusOK, ACLTestResponse{
			Valid:   true,
			Matched: false,
			Error:   err.Error(),
			Reason:  "evaluation error against sample request",
		})
		return
	}

	respondJSON(w, http.StatusOK, ACLTestResponse{
		Valid:   true,
		Matched: matched,
		Reason:  "expression evaluated successfully",
	})
}
