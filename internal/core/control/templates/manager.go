package templates

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/google/uuid"
)

// ResponseTemplate represents a customized or default response template in memory.
type ResponseTemplate struct {
	ID          string    `json:"id"`
	StatusCode  int       `json:"status_code"`
	Title       string    `json:"title"`
	ContentHTML string    `json:"content_html"`
	CustomCSS   string    `json:"custom_css"`
	BrandName   string    `json:"brand_name"`
	LogoURL     string    `json:"logo_url"`
	IsCustom    bool      `json:"is_custom"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// TemplateData holds variable values for placeholder substitution.
type TemplateData struct {
	EventID    string
	ClientIP   string
	Timestamp  string
	Host       string
	Path       string
	BrandName  string
	LogoURL    string
	StatusCode int
	StatusText string
	Details    string
}

// TemplateManager coordinates deterministic HTML/CSS response templates.
type TemplateManager struct {
	mu        sync.RWMutex
	templates map[int]*ResponseTemplate
	defaults  map[int]DefaultTemplateDef
}

// NewTemplateManager constructs an initialized TemplateManager with default templates.
func NewTemplateManager() *TemplateManager {
	mgr := &TemplateManager{
		templates: make(map[int]*ResponseTemplate),
		defaults:  BuiltinTemplates(),
	}
	mgr.resetToDefaults()
	return mgr
}

func (m *TemplateManager) resetToDefaults() {
	now := time.Now().UTC()
	for code, def := range m.defaults {
		m.templates[code] = &ResponseTemplate{
			ID:          uuid.New().String(),
			StatusCode:  code,
			Title:       def.Title,
			ContentHTML: def.HTML,
			CustomCSS:   def.CSS,
			BrandName:   def.BrandName,
			IsCustom:    false,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
	}
}

// LoadFromStore loads customized templates from persistent storage.
func (m *TemplateManager) LoadFromStore(ctx context.Context, store control.ControlStore) error {
	if store == nil {
		return nil
	}
	records, err := store.ListTemplates(ctx)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, r := range records {
		if r.StatusCode > 0 {
			m.templates[r.StatusCode] = &ResponseTemplate{
				ID:          r.ID,
				StatusCode:  r.StatusCode,
				Title:       r.Title,
				ContentHTML: r.ContentHTML,
				CustomCSS:   r.CustomCSS,
				BrandName:   r.BrandName,
				LogoURL:     r.LogoURL,
				IsCustom:    r.IsCustom == 1,
				CreatedAt:   r.CreatedAt,
				UpdatedAt:   r.UpdatedAt,
			}
		}
	}
	return nil
}

// GetTemplate retrieves a template by status code.
func (m *TemplateManager) GetTemplate(statusCode int) (*ResponseTemplate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tmpl, ok := m.templates[statusCode]
	if !ok {
		return nil, fmt.Errorf("template for status code %d not found", statusCode)
	}
	cp := *tmpl
	return &cp, nil
}

// ListTemplates returns all configured templates sorted by status code.
func (m *TemplateManager) ListTemplates() []*ResponseTemplate {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*ResponseTemplate, 0, len(m.templates))
	for _, t := range m.templates {
		cp := *t
		result = append(result, &cp)
	}
	return result
}

// SetCustomTemplate updates or creates a custom response template.
func (m *TemplateManager) SetCustomTemplate(statusCode int, title, html, css, brandName, logoURL string) (*ResponseTemplate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if brandName == "" {
		brandName = "Raiwall"
	}

	existing, ok := m.templates[statusCode]
	id := uuid.New().String()
	created := time.Now().UTC()
	if ok {
		id = existing.ID
		created = existing.CreatedAt
	}

	tmpl := &ResponseTemplate{
		ID:          id,
		StatusCode:  statusCode,
		Title:       title,
		ContentHTML: html,
		CustomCSS:   css,
		BrandName:   brandName,
		LogoURL:     logoURL,
		IsCustom:    true,
		CreatedAt:   created,
		UpdatedAt:   time.Now().UTC(),
	}
	m.templates[statusCode] = tmpl
	return tmpl, nil
}

// ResetTemplate resets the template for a status code back to factory default.
func (m *TemplateManager) ResetTemplate(statusCode int) (*ResponseTemplate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	def, ok := m.defaults[statusCode]
	if !ok {
		return nil, fmt.Errorf("no factory default for status code %d", statusCode)
	}

	tmpl := &ResponseTemplate{
		ID:          uuid.New().String(),
		StatusCode:  statusCode,
		Title:       def.Title,
		ContentHTML: def.HTML,
		CustomCSS:   def.CSS,
		BrandName:   def.BrandName,
		IsCustom:    false,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	m.templates[statusCode] = tmpl
	return tmpl, nil
}

// Render compiles and renders a template with variable substitution.
func (m *TemplateManager) Render(statusCode int, data TemplateData) (string, error) {
	m.mu.RLock()
	tmpl, ok := m.templates[statusCode]
	m.mu.RUnlock()

	if !ok {
		return fmt.Sprintf("<!DOCTYPE html><html><body><h1>%d %s</h1></body></html>", statusCode, http.StatusText(statusCode)), nil
	}

	if data.StatusCode == 0 {
		data.StatusCode = statusCode
	}
	if data.StatusText == "" {
		data.StatusText = http.StatusText(statusCode)
	}
	if data.BrandName == "" {
		data.BrandName = tmpl.BrandName
	}
	if data.Timestamp == "" {
		data.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	raw := tmpl.ContentHTML
	return SubstituteTemplateVars(raw, tmpl.CustomCSS, data), nil
}

// RenderPreview renders synthetic HTML with provided parameters.
func (m *TemplateManager) RenderPreview(statusCode int, customHTML, customCSS, brandName, logoURL string) string {
	if customHTML == "" {
		m.mu.RLock()
		if def, ok := m.templates[statusCode]; ok {
			customHTML = def.ContentHTML
			if customCSS == "" {
				customCSS = def.CustomCSS
			}
		}
		m.mu.RUnlock()
	}

	data := TemplateData{
		EventID:    "preview-" + uuid.New().String()[:8],
		ClientIP:   "203.0.113.195",
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Host:       "example.com",
		Path:       "/api/v1/sensitive-endpoint",
		BrandName:  brandName,
		LogoURL:    logoURL,
		StatusCode: statusCode,
		StatusText: http.StatusText(statusCode),
	}

	return SubstituteTemplateVars(customHTML, customCSS, data)
}

// SubstituteTemplateVars substitutes template placeholders like {{.EventID}}, {{.ClientIP}}, {{.CustomCSS}}, etc.
func SubstituteTemplateVars(raw string, css string, data TemplateData) string {
	codeStr := strconv.Itoa(data.StatusCode)

	replacements := []struct {
		tag string
		val string
	}{
		{"{{.CustomCSS}}", css},
		{"{{.EventID}}", data.EventID},
		{"{{EVENT_ID}}", data.EventID},
		{"{{.ClientIP}}", data.ClientIP},
		{"{{CLIENT_IP}}", data.ClientIP},
		{"{{.Timestamp}}", data.Timestamp},
		{"{{TIMESTAMP}}", data.Timestamp},
		{"{{.Host}}", data.Host},
		{"{{HOST}}", data.Host},
		{"{{.Path}}", data.Path},
		{"{{PATH}}", data.Path},
		{"{{.BrandName}}", data.BrandName},
		{"{{BRAND_NAME}}", data.BrandName},
		{"{{.LogoURL}}", data.LogoURL},
		{"{{LOGO_URL}}", data.LogoURL},
		{"{{.StatusCode}}", codeStr},
		{"{{STATUS_CODE}}", codeStr},
		{"{{.StatusText}}", data.StatusText},
		{"{{STATUS_TEXT}}", data.StatusText},
		{"{{.Details}}", data.Details},
	}

	res := raw
	for _, r := range replacements {
		res = strings.ReplaceAll(res, r.tag, r.val)
	}
	return res
}
