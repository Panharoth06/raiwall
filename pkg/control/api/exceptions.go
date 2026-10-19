package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Panharoth06/raiwall/pkg/acl"
	"github.com/Panharoth06/raiwall/pkg/control/db"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type ExceptionDTO struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	Host        string    `json:"host"`
	PathRegex   string    `json:"path_regex"`
	PathPrefix  string    `json:"path_prefix"`
	Method      string    `json:"method"`
	Location    string    `json:"location"`
	ParamName   string    `json:"param_name"`
	ParamRegex  string    `json:"param_regex"`
	RuleID      string    `json:"rule_id"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type ExceptionTestRequest struct {
	Rule          ExceptionDTO           `json:"rule"`
	SampleRequest ExceptionSampleRequest `json:"sample_request"`
}

type ExceptionSampleRequest struct {
	Host      string `json:"host"`
	Path      string `json:"path"`
	Method    string `json:"method"`
	Location  string `json:"location"`
	ParamName string `json:"param_name"`
	RuleID    string `json:"rule_id"`
}

type ExceptionTestResponse struct {
	Matched bool   `json:"matched"`
	Reason  string `json:"reason"`
}

func (s *Server) handleListExceptions(w http.ResponseWriter, r *http.Request) {
	excs, err := s.store.ListExceptions(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list exceptions: "+err.Error())
		return
	}

	result := make([]ExceptionDTO, 0, len(excs))
	for _, e := range excs {
		result = append(result, ExceptionDTO{
			ID:          e.ID,
			Description: e.Description,
			Host:        e.Host,
			PathRegex:   e.PathRegex,
			PathPrefix:  e.PathPrefix,
			Method:      e.Method,
			Location:    e.Location,
			ParamName:   e.ParamName,
			ParamRegex:  e.ParamRegex,
			RuleID:      e.RuleID,
			IsActive:    e.IsActive == 1,
			CreatedAt:   e.CreatedAt,
			UpdatedAt:   e.UpdatedAt,
		})
	}
	respondJSON(w, http.StatusOK, result)
}

func (s *Server) handleGetException(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	e, err := s.store.GetException(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusNotFound, "exception not found")
		return
	}

	respondJSON(w, http.StatusOK, ExceptionDTO{
		ID:          e.ID,
		Description: e.Description,
		Host:        e.Host,
		PathRegex:   e.PathRegex,
		PathPrefix:  e.PathPrefix,
		Method:      e.Method,
		Location:    e.Location,
		ParamName:   e.ParamName,
		ParamRegex:  e.ParamRegex,
		RuleID:      e.RuleID,
		IsActive:    e.IsActive == 1,
		CreatedAt:   e.CreatedAt,
		UpdatedAt:   e.UpdatedAt,
	})
}

func (s *Server) handleCreateException(w http.ResponseWriter, r *http.Request) {
	var req ExceptionDTO
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	if req.ID == "" {
		req.ID = "exc-" + uuid.New().String()[:8]
	}
	if req.Host == "" {
		req.Host = "*"
	}
	if req.Method == "" {
		req.Method = "*"
	}
	if req.Location == "" {
		req.Location = "*"
	}
	if req.RuleID == "" {
		req.RuleID = "*"
	}

	// Validate regex if provided
	rule := acl.ExceptionRule{
		ID:         req.ID,
		PathRegex:  req.PathRegex,
		ParamRegex: req.ParamRegex,
	}
	if err := rule.Compile(); err != nil {
		respondError(w, http.StatusBadRequest, "invalid regex pattern: "+err.Error())
		return
	}

	now := time.Now().UTC()
	isActive := int64(1)
	if !req.IsActive {
		isActive = 0
	}

	err := s.store.CreateException(r.Context(), db.CreateExceptionParams{
		ID:          req.ID,
		Description: req.Description,
		Host:        req.Host,
		PathRegex:   req.PathRegex,
		PathPrefix:  req.PathPrefix,
		Method:      req.Method,
		Location:    req.Location,
		ParamName:   req.ParamName,
		ParamRegex:  req.ParamRegex,
		RuleID:      req.RuleID,
		IsActive:    isActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create exception: "+err.Error())
		return
	}

	req.CreatedAt = now
	req.UpdatedAt = now
	respondJSON(w, http.StatusCreated, req)
}

func (s *Server) handleUpdateException(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req ExceptionDTO
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	rule := acl.ExceptionRule{
		ID:         id,
		PathRegex:  req.PathRegex,
		ParamRegex: req.ParamRegex,
	}
	if err := rule.Compile(); err != nil {
		respondError(w, http.StatusBadRequest, "invalid regex pattern: "+err.Error())
		return
	}

	now := time.Now().UTC()
	isActive := int64(1)
	if !req.IsActive {
		isActive = 0
	}

	err := s.store.UpdateException(r.Context(), db.UpdateExceptionParams{
		ID:          id,
		Description: req.Description,
		Host:        req.Host,
		PathRegex:   req.PathRegex,
		PathPrefix:  req.PathPrefix,
		Method:      req.Method,
		Location:    req.Location,
		ParamName:   req.ParamName,
		ParamRegex:  req.ParamRegex,
		RuleID:      req.RuleID,
		IsActive:    isActive,
		UpdatedAt:   now,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update exception: "+err.Error())
		return
	}

	req.ID = id
	req.UpdatedAt = now
	respondJSON(w, http.StatusOK, req)
}

func (s *Server) handleDeleteException(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	err := s.store.DeleteException(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to delete exception: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": id})
}

func (s *Server) handleTestException(w http.ResponseWriter, r *http.Request) {
	var req ExceptionTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	rule := acl.ExceptionRule{
		ID:          "test-rule",
		Description: req.Rule.Description,
		Host:        req.Rule.Host,
		PathRegex:   req.Rule.PathRegex,
		PathPrefix:  req.Rule.PathPrefix,
		Method:      req.Rule.Method,
		Location:    req.Rule.Location,
		ParamName:   req.Rule.ParamName,
		ParamRegex:  req.Rule.ParamRegex,
		RuleID:      req.Rule.RuleID,
	}

	if err := rule.Compile(); err != nil {
		respondJSON(w, http.StatusOK, ExceptionTestResponse{
			Matched: false,
			Reason:  "regex compilation failed: " + err.Error(),
		})
		return
	}

	matched := rule.Matches(
		req.SampleRequest.Host,
		req.SampleRequest.Path,
		req.SampleRequest.Method,
		req.SampleRequest.Location,
		req.SampleRequest.ParamName,
		req.SampleRequest.RuleID,
	)

	reason := "rule matched criteria successfully"
	if !matched {
		reason = "request criteria did not match rule parameters"
	}

	respondJSON(w, http.StatusOK, ExceptionTestResponse{
		Matched: matched,
		Reason:  reason,
	})
}
