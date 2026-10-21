package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// ExceptionDTO represents a false-positive bypass rule.
type ExceptionDTO struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	Reason      string    `json:"reason,omitempty"`
	Host        string    `json:"host"`
	Path        string    `json:"path,omitempty"`
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

func (s *Server) handleListExceptions(w http.ResponseWriter, r *http.Request) {
	excs, err := s.store.ListExceptions(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list exceptions: "+err.Error())
		return
	}

	result := make([]ExceptionDTO, 0, len(excs))
	for _, e := range excs {
		p := e.PathPrefix
		if p == "" {
			p = e.PathRegex
		}
		result = append(result, ExceptionDTO{
			ID:          e.ID,
			Description: e.Description,
			Reason:      e.Description,
			Host:        e.Host,
			Path:        p,
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

	p := e.PathPrefix
	if p == "" {
		p = e.PathRegex
	}
	respondJSON(w, http.StatusOK, ExceptionDTO{
		ID:          e.ID,
		Description: e.Description,
		Reason:      e.Description,
		Host:        e.Host,
		Path:        p,
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
	var raw struct {
		ExceptionDTO
		Path     string `json:"path"`
		IsActive *bool  `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	req := raw.ExceptionDTO
	if req.PathPrefix == "" && req.PathRegex == "" && raw.Path != "" {
		req.PathPrefix = raw.Path
	}
	if req.Path == "" {
		req.Path = req.PathPrefix
		if req.Path == "" {
			req.Path = req.PathRegex
		}
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
	if raw.IsActive != nil && !*raw.IsActive {
		isActive = 0
	}

	err := s.store.CreateException(r.Context(), control.ExceptionRule{
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
	var raw struct {
		ExceptionDTO
		Path     string `json:"path"`
		IsActive *bool  `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	req := raw.ExceptionDTO
	if req.PathPrefix == "" && req.PathRegex == "" && raw.Path != "" {
		req.PathPrefix = raw.Path
	}
	if req.Path == "" {
		req.Path = req.PathPrefix
		if req.Path == "" {
			req.Path = req.PathRegex
		}
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
	if raw.IsActive != nil && !*raw.IsActive {
		isActive = 0
	} else if !req.IsActive && raw.IsActive == nil {
		isActive = 0
	}

	err := s.store.UpdateException(r.Context(), control.ExceptionRule{
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
