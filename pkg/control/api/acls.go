package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/pkg/acl"
	"github.com/Panharoth06/raiwall/pkg/control/db"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type ACLRuleDTO struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Expression  string    `json:"expression"`
	Action      string    `json:"action"`
	Priority    int       `json:"priority"`
	StatusCode  int       `json:"status_code"`
	RedirectURL string    `json:"redirect_url"`
	IsActive    bool      `json:"is_active"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

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

type ACLTestRequest struct {
	Expression    string              `json:"expression"`
	SampleRequest ACLSampleRequestDTO `json:"sample_request"`
}

type ACLTestResponse struct {
	Valid   bool   `json:"valid"`
	Matched bool   `json:"matched"`
	Error   string `json:"error,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

func (s *Server) handleListACLRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListACLRules(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list ACL rules: "+err.Error())
		return
	}

	result := make([]ACLRuleDTO, 0, len(rules))
	for _, rule := range rules {
		result = append(result, ACLRuleDTO{
			ID:          rule.ID,
			Name:        rule.Name,
			Expression:  rule.Expression,
			Action:      rule.Action,
			Priority:    int(rule.Priority),
			StatusCode:  int(rule.StatusCode),
			RedirectURL: rule.RedirectUrl,
			IsActive:    rule.IsActive == 1,
			Enabled:     rule.IsActive == 1,
			CreatedAt:   rule.CreatedAt,
			UpdatedAt:   rule.UpdatedAt,
		})
	}
	respondJSON(w, http.StatusOK, result)
}

func (s *Server) handleGetACLRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	rule, err := s.store.GetACLRule(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusNotFound, "ACL rule not found")
		return
	}

	respondJSON(w, http.StatusOK, ACLRuleDTO{
		ID:          rule.ID,
		Name:        rule.Name,
		Expression:  rule.Expression,
		Action:      rule.Action,
		Priority:    int(rule.Priority),
		StatusCode:  int(rule.StatusCode),
		RedirectURL: rule.RedirectUrl,
		IsActive:    rule.IsActive == 1,
		Enabled:     rule.IsActive == 1,
		CreatedAt:   rule.CreatedAt,
		UpdatedAt:   rule.UpdatedAt,
	})
}

func (s *Server) handleCreateACLRule(w http.ResponseWriter, r *http.Request) {
	var raw struct {
		ACLRuleDTO
		Enabled  *bool `json:"enabled"`
		IsActive *bool `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	req := raw.ACLRuleDTO

	if req.ID == "" {
		req.ID = "acl-" + uuid.New().String()[:8]
	}
	if req.Action == "" {
		req.Action = string(acl.ActionBlock)
	}
	if req.StatusCode == 0 {
		req.StatusCode = 403
	}

	// Compile expr rule to validate syntax
	rule := acl.ACLRule{
		Name:       req.Name,
		Expression: req.Expression,
	}
	if err := rule.Compile(nil); err != nil {
		respondError(w, http.StatusBadRequest, "invalid expr expression: "+err.Error())
		return
	}

	now := time.Now().UTC()
	isActive := int64(1)
	if raw.Enabled != nil && !*raw.Enabled {
		isActive = 0
	} else if raw.IsActive != nil && !*raw.IsActive {
		isActive = 0
	}
	req.IsActive = isActive == 1
	req.Enabled = isActive == 1

	err := s.store.CreateACLRule(r.Context(), db.CreateACLRuleParams{
		ID:          req.ID,
		Name:        req.Name,
		Expression:  req.Expression,
		Action:      req.Action,
		Priority:    int64(req.Priority),
		StatusCode:  int64(req.StatusCode),
		RedirectUrl: req.RedirectURL,
		IsActive:    isActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create ACL rule: "+err.Error())
		return
	}

	req.CreatedAt = now
	req.UpdatedAt = now
	respondJSON(w, http.StatusCreated, req)
}

func (s *Server) handleUpdateACLRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var raw struct {
		ACLRuleDTO
		Enabled  *bool `json:"enabled"`
		IsActive *bool `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	req := raw.ACLRuleDTO

	rule := acl.ACLRule{
		Name:       req.Name,
		Expression: req.Expression,
	}
	if err := rule.Compile(nil); err != nil {
		respondError(w, http.StatusBadRequest, "invalid expr expression: "+err.Error())
		return
	}

	now := time.Now().UTC()
	isActive := int64(1)
	if raw.Enabled != nil && !*raw.Enabled {
		isActive = 0
	} else if raw.IsActive != nil && !*raw.IsActive {
		isActive = 0
	}
	req.IsActive = isActive == 1
	req.Enabled = isActive == 1

	err := s.store.UpdateACLRule(r.Context(), db.UpdateACLRuleParams{
		ID:          id,
		Name:        req.Name,
		Expression:  req.Expression,
		Action:      req.Action,
		Priority:    int64(req.Priority),
		StatusCode:  int64(req.StatusCode),
		RedirectUrl: req.RedirectURL,
		IsActive:    isActive,
		UpdatedAt:   now,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update ACL rule: "+err.Error())
		return
	}

	req.ID = id
	req.UpdatedAt = now
	respondJSON(w, http.StatusOK, req)
}

func (s *Server) handleDeleteACLRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	err := s.store.DeleteACLRule(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to delete ACL rule: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": id})
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
