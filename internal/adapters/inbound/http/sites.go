package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// SiteDTO represents application domain configuration.
type SiteDTO struct {
	ID                  string                   `json:"id"`
	Name                string                   `json:"name"`
	Hostnames           []string                 `json:"hostnames"`
	Mode                string                   `json:"mode"`
	Upstreams           []control.UpstreamTarget `json:"upstreams"`
	ForwardingRules     []control.ForwardingRule `json:"forwarding_rules,omitempty"`
	ProxySettings       *control.ProxySettings   `json:"proxy_settings,omitempty"`
	BlockStatusCode     int                      `json:"block_status_code"`
	BlockResponseBody   string                   `json:"block_response_body"`
	OfflineStatusCode   int                      `json:"offline_status_code"`
	OfflineResponseBody string                   `json:"offline_response_body"`
	CustomHeaders       map[string]string        `json:"custom_headers"`
	AuthEnabled         bool                     `json:"auth_enabled,omitempty"`
	AuthBypassPaths     []string                 `json:"auth_bypass_paths,omitempty"`
	CreatedAt           time.Time                `json:"created_at"`
	UpdatedAt           time.Time                `json:"updated_at"`
}

func (s *Server) handleListSites(w http.ResponseWriter, r *http.Request) {
	apps, err := s.store.ListApps(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list sites: "+err.Error())
		return
	}

	result := make([]SiteDTO, 0, len(apps))
	for _, a := range apps {
		var hostnames []string
		_ = json.Unmarshal([]byte(a.Hostnames), &hostnames)
		var upstreams []control.UpstreamTarget
		_ = json.Unmarshal([]byte(a.Upstreams), &upstreams)
		var headers map[string]string
		_ = json.Unmarshal([]byte(a.CustomHeaders), &headers)
		var proxySettings *control.ProxySettings
		if a.ProxySettings != "" {
			var ps control.ProxySettings
			if err := json.Unmarshal([]byte(a.ProxySettings), &ps); err == nil {
				proxySettings = &ps
			}
		}

		result = append(result, SiteDTO{
			ID:                  a.ID,
			Name:                a.Name,
			Hostnames:           hostnames,
			Mode:                a.Mode,
			Upstreams:           upstreams,
			ProxySettings:       proxySettings,
			BlockStatusCode:     int(a.BlockStatusCode),
			BlockResponseBody:   a.BlockResponseBody,
			OfflineStatusCode:   int(a.OfflineStatusCode),
			OfflineResponseBody: a.OfflineResponseBody,
			CustomHeaders:       headers,
			AuthEnabled:         a.AuthEnabled == 1,
			AuthBypassPaths:     parseBypassPaths(a.AuthBypassPaths),
			CreatedAt:           a.CreatedAt,
			UpdatedAt:           a.UpdatedAt,
		})
	}

	respondJSON(w, http.StatusOK, result)
}

func (s *Server) handleGetSite(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	app, err := s.store.GetApp(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusNotFound, "site not found")
		return
	}

	var hostnames []string
	_ = json.Unmarshal([]byte(app.Hostnames), &hostnames)
	var upstreams []control.UpstreamTarget
	_ = json.Unmarshal([]byte(app.Upstreams), &upstreams)
	var headers map[string]string
	_ = json.Unmarshal([]byte(app.CustomHeaders), &headers)
	var proxySettings *control.ProxySettings
	if app.ProxySettings != "" {
		var ps control.ProxySettings
		if err := json.Unmarshal([]byte(app.ProxySettings), &ps); err == nil {
			proxySettings = &ps
		}
	}

	rules, err := s.store.ListForwardingRulesByApp(r.Context(), id)
	var forwardingRules []control.ForwardingRule
	if err == nil {
		forwardingRules = make([]control.ForwardingRule, 0, len(rules))
		for _, rule := range rules {
			var ruUpstreams []control.UpstreamTarget
			if rule.Upstreams != "" {
				_ = json.Unmarshal([]byte(rule.Upstreams), &ruUpstreams)
			}
			forwardingRules = append(forwardingRules, control.ForwardingRule{
				ID:                 rule.ID,
				AppID:              rule.AppID,
				Prefix:             rule.Prefix,
				Upstreams:          ruUpstreams,
				StripPrefix:        rule.StripPrefix == 1,
				HostHeaderOverride: rule.HostHeaderOverride,
				Comment:            rule.Comment,
				IsActive:           rule.IsActive == 1,
			})
		}
	}

	respondJSON(w, http.StatusOK, SiteDTO{
		ID:                  app.ID,
		Name:                app.Name,
		Hostnames:           hostnames,
		Mode:                app.Mode,
		Upstreams:           upstreams,
		ForwardingRules:     forwardingRules,
		ProxySettings:       proxySettings,
		BlockStatusCode:     int(app.BlockStatusCode),
		BlockResponseBody:   app.BlockResponseBody,
		OfflineStatusCode:   int(app.OfflineStatusCode),
		OfflineResponseBody: app.OfflineResponseBody,
		CustomHeaders:       headers,
		AuthEnabled:         app.AuthEnabled == 1,
		AuthBypassPaths:     parseBypassPaths(app.AuthBypassPaths),
		CreatedAt:           app.CreatedAt,
		UpdatedAt:           app.UpdatedAt,
	})
}

// parseBypassPaths decodes the embedded auth_bypass_paths JSON array.
func parseBypassPaths(raw string) []string {
	var paths []string
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &paths)
	}
	return paths
}

// marshalBypassPaths serializes auth path prefixes for storage (nil → []).
func marshalBypassPaths(paths []string) []byte {
	if paths == nil {
		paths = []string{}
	}
	raw, _ := json.Marshal(paths)
	return raw
}

func (s *Server) handleCreateSite(w http.ResponseWriter, r *http.Request) {
	var req SiteDTO
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	if req.ID == "" {
		req.ID = "site-" + uuid.New().String()[:8]
	}
	if req.Mode == "" {
		req.Mode = string(control.ModeDefense)
	}
	if req.BlockStatusCode == 0 {
		req.BlockStatusCode = 403
	}
	if req.OfflineStatusCode == 0 {
		req.OfflineStatusCode = 503
	}

	hostnamesJSON, _ := json.Marshal(req.Hostnames)
	upstreamsJSON, _ := json.Marshal(req.Upstreams)
	headersJSON, _ := json.Marshal(req.CustomHeaders)
	proxySettingsJSON, _ := json.Marshal(req.ProxySettings)
	bypassPathsJSON := marshalBypassPaths(req.AuthBypassPaths)
	now := time.Now().UTC()

	err := s.store.CreateApp(r.Context(), control.SiteApp{
		ID:                  req.ID,
		Name:                req.Name,
		Hostnames:           string(hostnamesJSON),
		Mode:                req.Mode,
		Upstreams:           string(upstreamsJSON),
		BlockStatusCode:     int64(req.BlockStatusCode),
		BlockResponseBody:   req.BlockResponseBody,
		OfflineStatusCode:   int64(req.OfflineStatusCode),
		OfflineResponseBody: req.OfflineResponseBody,
		CustomHeaders:       string(headersJSON),
		ProxySettings:       string(proxySettingsJSON),
		AuthEnabled:         boolToInt64(req.AuthEnabled),
		AuthBypassPaths:     string(bypassPathsJSON),
		CreatedAt:           now,
		UpdatedAt:           now,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create site: "+err.Error())
		return
	}

	req.CreatedAt = now
	req.UpdatedAt = now
	respondJSON(w, http.StatusCreated, req)
}

func (s *Server) handleUpdateSite(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req SiteDTO
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	hostnamesJSON, _ := json.Marshal(req.Hostnames)
	upstreamsJSON, _ := json.Marshal(req.Upstreams)
	headersJSON, _ := json.Marshal(req.CustomHeaders)
	proxySettingsJSON, _ := json.Marshal(req.ProxySettings)
	bypassPathsJSON := marshalBypassPaths(req.AuthBypassPaths)
	now := time.Now().UTC()

	err := s.store.UpdateApp(r.Context(), control.SiteApp{
		ID:                  id,
		Name:                req.Name,
		Hostnames:           string(hostnamesJSON),
		Mode:                req.Mode,
		Upstreams:           string(upstreamsJSON),
		BlockStatusCode:     int64(req.BlockStatusCode),
		BlockResponseBody:   req.BlockResponseBody,
		OfflineStatusCode:   int64(req.OfflineStatusCode),
		OfflineResponseBody: req.OfflineResponseBody,
		CustomHeaders:       string(headersJSON),
		ProxySettings:       string(proxySettingsJSON),
		AuthEnabled:         boolToInt64(req.AuthEnabled),
		AuthBypassPaths:     string(bypassPathsJSON),
		UpdatedAt:           now,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update site: "+err.Error())
		return
	}

	req.ID = id
	req.UpdatedAt = now
	respondJSON(w, http.StatusOK, req)
}

func (s *Server) handleDeleteSite(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	err := s.store.DeleteApp(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to delete site: "+err.Error())
		return
	}
	_ = s.store.DeleteForwardingRulesByApp(r.Context(), id)
	_ = s.store.DeleteAPIResourcesByApp(r.Context(), id)
	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": id})
}
