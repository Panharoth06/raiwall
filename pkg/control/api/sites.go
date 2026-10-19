package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Panharoth06/raiwall/pkg/config"
	"github.com/Panharoth06/raiwall/pkg/control/db"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type SiteDTO struct {
	ID                  string                  `json:"id"`
	Name                string                  `json:"name"`
	Hostnames           []string                `json:"hostnames"`
	Mode                string                  `json:"mode"`
	Upstreams           []config.UpstreamTarget `json:"upstreams"`
	BlockStatusCode     int                     `json:"block_status_code"`
	BlockResponseBody   string                  `json:"block_response_body"`
	OfflineStatusCode   int                     `json:"offline_status_code"`
	OfflineResponseBody string                  `json:"offline_response_body"`
	CustomHeaders       map[string]string       `json:"custom_headers"`
	CreatedAt           time.Time               `json:"created_at"`
	UpdatedAt           time.Time               `json:"updated_at"`
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
		var upstreams []config.UpstreamTarget
		_ = json.Unmarshal([]byte(a.Upstreams), &upstreams)
		var headers map[string]string
		_ = json.Unmarshal([]byte(a.CustomHeaders), &headers)

		result = append(result, SiteDTO{
			ID:                  a.ID,
			Name:                a.Name,
			Hostnames:           hostnames,
			Mode:                a.Mode,
			Upstreams:           upstreams,
			BlockStatusCode:     int(a.BlockStatusCode),
			BlockResponseBody:   a.BlockResponseBody,
			OfflineStatusCode:   int(a.OfflineStatusCode),
			OfflineResponseBody: a.OfflineResponseBody,
			CustomHeaders:       headers,
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
	var upstreams []config.UpstreamTarget
	_ = json.Unmarshal([]byte(app.Upstreams), &upstreams)
	var headers map[string]string
	_ = json.Unmarshal([]byte(app.CustomHeaders), &headers)

	respondJSON(w, http.StatusOK, SiteDTO{
		ID:                  app.ID,
		Name:                app.Name,
		Hostnames:           hostnames,
		Mode:                app.Mode,
		Upstreams:           upstreams,
		BlockStatusCode:     int(app.BlockStatusCode),
		BlockResponseBody:   app.BlockResponseBody,
		OfflineStatusCode:   int(app.OfflineStatusCode),
		OfflineResponseBody: app.OfflineResponseBody,
		CustomHeaders:       headers,
		CreatedAt:           app.CreatedAt,
		UpdatedAt:           app.UpdatedAt,
	})
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
		req.Mode = string(config.ModeDefense)
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
	now := time.Now().UTC()

	err := s.store.CreateApp(r.Context(), db.CreateAppParams{
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
	now := time.Now().UTC()

	err := s.store.UpdateApp(r.Context(), db.UpdateAppParams{
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
	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": id})
}
