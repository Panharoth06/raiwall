package api

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (s *Server) handleListSites(w http.ResponseWriter, r *http.Request) {
	apps, err := s.store.ListApps(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list sites: "+err.Error())
		return
	}

	result := make([]SiteDTO, 0, len(apps))
	for _, a := range apps {
		result = append(result, siteDTOFromRecord(a))
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

	dto := siteDTOFromRecord(app)
	rules, err := s.store.ListForwardingRulesByApp(r.Context(), id)
	if err == nil {
		dto.ForwardingRules = make([]control.ForwardingRule, 0, len(rules))
		for _, rule := range rules {
			var ruUpstreams []control.UpstreamTarget
			if rule.Upstreams != "" {
				_ = json.Unmarshal([]byte(rule.Upstreams), &ruUpstreams)
			}
			dto.ForwardingRules = append(dto.ForwardingRules, control.ForwardingRule{
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

	respondJSON(w, http.StatusOK, dto)
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

	id := req.ID
	if id == "" {
		id = "site-" + uuid.New().String()[:8]
	}
	now := time.Now().UTC()

	record, err := s.siteRecordFromDTO(r.Context(), req, id, now)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.CreateApp(r.Context(), record); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create site: "+err.Error())
		return
	}
	if record.SSLMode == control.SSLModeAuto {
		if err := s.ensureAutoCertificate(r.Context(), siteDTOFromRecord(record).Hostnames); err != nil {
			respondError(w, http.StatusInternalServerError, "site created but certificate provisioning failed: "+err.Error())
			return
		}
	}

	resp := siteDTOFromRecord(record)
	resp.ID = id
	respondJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleUpdateSite(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	var patch SiteDTO
	if err := json.Unmarshal(body, &patch); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	var provided map[string]json.RawMessage
	_ = json.Unmarshal(body, &provided)

	stored, err := s.store.GetApp(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusNotFound, "site not found")
		return
	}
	req := applySitePatch(siteDTOFromRecord(stored), patch, provided)

	now := time.Now().UTC()
	record, err := s.siteRecordFromDTO(r.Context(), req, id, now)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	record.CreatedAt = time.Time{}
	if err := s.store.UpdateApp(r.Context(), record); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update site: "+err.Error())
		return
	}
	if record.SSLMode == control.SSLModeAuto {
		if err := s.ensureAutoCertificate(r.Context(), siteDTOFromRecord(record).Hostnames); err != nil {
			respondError(w, http.StatusInternalServerError, "site updated but certificate provisioning failed: "+err.Error())
			return
		}
	}

	existing, _ := s.store.GetApp(r.Context(), id)
	respondJSON(w, http.StatusOK, siteDTOFromRecord(existing))
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
