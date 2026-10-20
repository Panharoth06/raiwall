package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/go-chi/chi/v5"
)

// ApplyRequest represents parameters for committing a new configuration snapshot.
type ApplyRequest struct {
	Author      string `json:"author"`
	Description string `json:"description"`
}

// ApplyResponse represents the result of deploying a configuration snapshot.
type ApplyResponse struct {
	Success     bool      `json:"success"`
	Version     uint64    `json:"version"`
	Author      string    `json:"author"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// SnapshotHistoryItem represents historical snapshot metadata.
type SnapshotHistoryItem struct {
	Version     int64     `json:"version"`
	Author      string    `json:"author"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	AppliedAt   time.Time `json:"applied_at"`
}

func (s *Server) handleApplyConfig(w http.ResponseWriter, r *http.Request) {
	var req ApplyRequest
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	authCtx, _ := AuthFromContext(r.Context())
	if req.Author == "" && authCtx != nil {
		req.Author = authCtx.Username
	}
	if req.Author == "" {
		req.Author = "admin"
	}
	if req.Description == "" {
		req.Description = "Applied via control plane API"
	}

	deployed, err := control.DeploySnapshot(r.Context(), s.store, req.Author, req.Description)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if s.clusterPublisher != nil {
		go func(v uint64) {
			_ = s.clusterPublisher.PublishVersion(context.Background(), v)
		}(deployed.Version)
	}

	respondJSON(w, http.StatusOK, ApplyResponse{
		Success:     true,
		Version:     deployed.Version,
		Author:      req.Author,
		Description: req.Description,
		CreatedAt:   deployed.CreatedAt,
	})
}

func (s *Server) handleRollbackConfig(w http.ResponseWriter, r *http.Request) {
	verStr := chi.URLParam(r, "version")
	ver, err := strconv.ParseUint(verStr, 10, 64)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid version number: "+verStr)
		return
	}

	restored, err := control.RollbackToVersion(r.Context(), s.store, ver)
	if err != nil {
		respondError(w, http.StatusBadRequest, "rollback failed: "+err.Error())
		return
	}

	if s.clusterPublisher != nil {
		go func(v uint64) {
			_ = s.clusterPublisher.PublishVersion(context.Background(), v)
		}(restored.Version)
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"success":        true,
		"active_version": restored.Version,
		"message":        fmt.Sprintf("successfully rolled back to version %d", ver),
	})
}

func (s *Server) handleListSnapshots(w http.ResponseWriter, r *http.Request) {
	history, err := control.ListSnapshotHistory(r.Context(), s.store)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list snapshot history: "+err.Error())
		return
	}

	items := make([]SnapshotHistoryItem, 0, len(history))
	for _, h := range history {
		items = append(items, SnapshotHistoryItem{
			Version:     h.Version,
			Author:      h.Author,
			Description: h.Description,
			CreatedAt:   h.CreatedAt,
			AppliedAt:   h.CreatedAt,
		})
	}
	respondJSON(w, http.StatusOK, items)
}
