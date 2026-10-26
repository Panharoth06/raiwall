package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/control/declarative"
	"github.com/Panharoth06/raiwall/internal/core/control/templates"
	"github.com/go-chi/chi/v5"
)

// TemplateDTO represents a deterministic response template transfer object.
type TemplateDTO struct {
	ID          string    `json:"id"`
	StatusCode  int       `json:"status_code"`
	Title       string    `json:"title"`
	ContentHTML string    `json:"content_html"`
	CustomCSS   string    `json:"custom_css"`
	BrandName   string    `json:"brand_name"`
	LogoURL     string    `json:"logo_url"`
	IsCustom    bool      `json:"is_custom"`
	Managed     bool      `json:"managed"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// isManagedTemplate reports whether the stored template row is owned by
// raiwall.yaml (templates are keyed by status code, not ID).
func (s *Server) isManagedTemplate(r *http.Request, code int) (bool, error) {
	rec, err := s.store.GetTemplate(r.Context(), code)
	if err != nil {
		return false, err
	}
	return declarative.IsManaged(rec.ID), nil
}

// handleListTemplates lists all deterministic error and challenge response templates.
func (s *Server) handleListTemplates(w http.ResponseWriter, r *http.Request) {
	if s.templateMgr == nil {
		s.templateMgr = templates.NewTemplateManager()
	}

	tmpls := s.templateMgr.ListTemplates()
	result := make([]TemplateDTO, 0, len(tmpls))
	for _, t := range tmpls {
		result = append(result, TemplateDTO{
			ID:          t.ID,
			Managed:     declarative.IsManaged(t.ID),
			StatusCode:  t.StatusCode,
			Title:       t.Title,
			ContentHTML: t.ContentHTML,
			CustomCSS:   t.CustomCSS,
			BrandName:   t.BrandName,
			LogoURL:     t.LogoURL,
			IsCustom:    t.IsCustom,
			CreatedAt:   t.CreatedAt,
			UpdatedAt:   t.UpdatedAt,
		})
	}
	respondJSON(w, http.StatusOK, result)
}

// handleGetTemplate fetches the template for a specific HTTP status code.
func (s *Server) handleGetTemplate(w http.ResponseWriter, r *http.Request) {
	codeStr := chi.URLParam(r, "statusCode")
	code, err := strconv.Atoi(codeStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid status code")
		return
	}

	if s.templateMgr == nil {
		s.templateMgr = templates.NewTemplateManager()
	}

	t, err := s.templateMgr.GetTemplate(code)
	if err != nil {
		respondError(w, http.StatusNotFound, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, TemplateDTO{
		ID:          t.ID,
		Managed:     declarative.IsManaged(t.ID),
		StatusCode:  t.StatusCode,
		Title:       t.Title,
		ContentHTML: t.ContentHTML,
		CustomCSS:   t.CustomCSS,
		BrandName:   t.BrandName,
		LogoURL:     t.LogoURL,
		IsCustom:    t.IsCustom,
		CreatedAt:   t.CreatedAt,
		UpdatedAt:   t.UpdatedAt,
	})
}

// handleUpdateTemplate updates the HTML/CSS response template for a status code.
func (s *Server) handleUpdateTemplate(w http.ResponseWriter, r *http.Request) {
	codeStr := chi.URLParam(r, "statusCode")
	code, err := strconv.Atoi(codeStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid status code")
		return
	}
	if managed, lookupErr := s.isManagedTemplate(r, code); lookupErr == nil && managed {
		respondError(w, http.StatusConflict, "template is managed by the declarative configuration file; edit raiwall.yaml and redeploy")
		return
	}

	var req struct {
		Title       string `json:"title"`
		ContentHTML string `json:"content_html"`
		CustomCSS   string `json:"custom_css"`
		BrandName   string `json:"brand_name"`
		LogoURL     string `json:"logo_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request payload: "+err.Error())
		return
	}

	if s.templateMgr == nil {
		s.templateMgr = templates.NewTemplateManager()
	}

	t, err := s.templateMgr.SetCustomTemplate(code, req.Title, req.ContentHTML, req.CustomCSS, req.BrandName, req.LogoURL)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update template: "+err.Error())
		return
	}

	// Persist to SQLite
	record := control.TemplateRecord{
		ID:          t.ID,
		StatusCode:  t.StatusCode,
		Title:       t.Title,
		ContentHTML: t.ContentHTML,
		CustomCSS:   t.CustomCSS,
		BrandName:   t.BrandName,
		LogoURL:     t.LogoURL,
		IsCustom:    1,
		CreatedAt:   t.CreatedAt,
		UpdatedAt:   t.UpdatedAt,
	}
	_ = s.store.UpsertTemplate(r.Context(), record)

	respondJSON(w, http.StatusOK, TemplateDTO{
		ID:          t.ID,
		Managed:     declarative.IsManaged(t.ID),
		StatusCode:  t.StatusCode,
		Title:       t.Title,
		ContentHTML: t.ContentHTML,
		CustomCSS:   t.CustomCSS,
		BrandName:   t.BrandName,
		LogoURL:     t.LogoURL,
		IsCustom:    t.IsCustom,
		CreatedAt:   t.CreatedAt,
		UpdatedAt:   t.UpdatedAt,
	})
}

// handlePreviewTemplate renders a synthetic live preview of a template with mock parameters.
func (s *Server) handlePreviewTemplate(w http.ResponseWriter, r *http.Request) {
	codeStr := chi.URLParam(r, "statusCode")
	code, err := strconv.Atoi(codeStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid status code")
		return
	}

	var req struct {
		ContentHTML string `json:"content_html"`
		CustomCSS   string `json:"custom_css"`
		BrandName   string `json:"brand_name"`
		LogoURL     string `json:"logo_url"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	if s.templateMgr == nil {
		s.templateMgr = templates.NewTemplateManager()
	}

	rendered := s.templateMgr.RenderPreview(code, req.ContentHTML, req.CustomCSS, req.BrandName, req.LogoURL)
	respondJSON(w, http.StatusOK, map[string]string{
		"rendered_html": rendered,
		"status_code":   codeStr,
	})
}

// handleResetTemplate resets a template back to default.
func (s *Server) handleResetTemplate(w http.ResponseWriter, r *http.Request) {
	codeStr := chi.URLParam(r, "statusCode")
	code, err := strconv.Atoi(codeStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid status code")
		return
	}
	if managed, lookupErr := s.isManagedTemplate(r, code); lookupErr == nil && managed {
		respondError(w, http.StatusConflict, "template is managed by the declarative configuration file; edit raiwall.yaml and redeploy")
		return
	}

	if s.templateMgr == nil {
		s.templateMgr = templates.NewTemplateManager()
	}

	t, err := s.templateMgr.ResetTemplate(code)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Remove from SQLite
	_ = s.store.DeleteTemplate(r.Context(), code)

	respondJSON(w, http.StatusOK, TemplateDTO{
		ID:          t.ID,
		Managed:     declarative.IsManaged(t.ID),
		StatusCode:  t.StatusCode,
		Title:       t.Title,
		ContentHTML: t.ContentHTML,
		CustomCSS:   t.CustomCSS,
		BrandName:   t.BrandName,
		LogoURL:     t.LogoURL,
		IsCustom:    t.IsCustom,
		CreatedAt:   t.CreatedAt,
		UpdatedAt:   t.UpdatedAt,
	})
}
