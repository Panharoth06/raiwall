package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/Panharoth06/raiwall/pkg/config"
	"github.com/go-chi/chi/v5"
)

type ConfigDiffResponse struct {
	HasChanges    bool     `json:"has_changes"`
	ActiveVersion uint64   `json:"active_version"`
	StagedVersion uint64   `json:"staged_version"`
	Added         []string `json:"added"`
	Modified      []string `json:"modified"`
	Removed       []string `json:"removed"`
	Summary       string   `json:"summary"`
}

type ApplyRequest struct {
	Author      string `json:"author"`
	Description string `json:"description"`
}

type ApplyResponse struct {
	Success     bool      `json:"success"`
	Version     uint64    `json:"version"`
	Author      string    `json:"author"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

type SnapshotHistoryItem struct {
	Version     int64     `json:"version"`
	Author      string    `json:"author"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

func (s *Server) handleGetConfigDiff(w http.ResponseWriter, r *http.Request) {
	active := config.GetActiveSnapshot()
	staged, err := config.CompileSnapshot(r.Context(), s.store)
	if err != nil {
		respondError(w, http.StatusBadRequest, "pre-flight validation error in draft config: "+err.Error())
		return
	}

	var activeVer uint64
	if active != nil {
		activeVer = active.Version
	}

	added := make([]string, 0)
	modified := make([]string, 0)
	removed := make([]string, 0)

	// Compare Apps
	if active != nil {
		for id, stagedApp := range staged.Apps {
			activeApp, exists := active.Apps[id]
			if !exists {
				added = append(added, fmt.Sprintf("App: %s (%s)", stagedApp.Name, id))
			} else {
				if activeApp.Name != stagedApp.Name || activeApp.Mode != stagedApp.Mode || len(activeApp.Upstreams) != len(stagedApp.Upstreams) {
					modified = append(modified, fmt.Sprintf("App: %s (%s)", stagedApp.Name, id))
				}
			}
		}
		for id, activeApp := range active.Apps {
			if _, exists := staged.Apps[id]; !exists {
				removed = append(removed, fmt.Sprintf("App: %s (%s)", activeApp.Name, id))
			}
		}
	} else {
		for id, stagedApp := range staged.Apps {
			added = append(added, fmt.Sprintf("App: %s (%s)", stagedApp.Name, id))
		}
	}

	// Compare Exceptions count
	activeExcCount := 0
	if active != nil {
		activeExcCount = len(active.Exceptions)
	}
	if len(staged.Exceptions) > activeExcCount {
		added = append(added, fmt.Sprintf("%d new exception rule(s)", len(staged.Exceptions)-activeExcCount))
	} else if len(staged.Exceptions) < activeExcCount {
		removed = append(removed, fmt.Sprintf("%d exception rule(s) removed", activeExcCount-len(staged.Exceptions)))
	}

	// Compare ACLs count
	activeACLCount := 0
	if active != nil {
		activeACLCount = len(active.ACLRules)
	}
	if len(staged.ACLRules) > activeACLCount {
		added = append(added, fmt.Sprintf("%d new ACL rule(s)", len(staged.ACLRules)-activeACLCount))
	} else if len(staged.ACLRules) < activeACLCount {
		removed = append(removed, fmt.Sprintf("%d ACL rule(s) removed", activeACLCount-len(staged.ACLRules)))
	}

	hasChanges := len(added) > 0 || len(modified) > 0 || len(removed) > 0
	summary := fmt.Sprintf("%d added, %d modified, %d removed", len(added), len(modified), len(removed))
	if !hasChanges {
		summary = "No staged changes detected. Staged draft matches active configuration."
	}

	respondJSON(w, http.StatusOK, ConfigDiffResponse{
		HasChanges:    hasChanges,
		ActiveVersion: activeVer,
		StagedVersion: staged.Version,
		Added:         added,
		Modified:      modified,
		Removed:       removed,
		Summary:       summary,
	})
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

	deployed, err := config.DeploySnapshot(r.Context(), s.store, req.Author, req.Description)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Cluster broadcast hook if cluster engine is mounted
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

	restored, err := config.RollbackToVersion(r.Context(), s.store, ver)
	if err != nil {
		respondError(w, http.StatusBadRequest, "rollback failed: "+err.Error())
		return
	}

	// Cluster broadcast hook if cluster engine is mounted
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
	history, err := config.ListSnapshotHistory(r.Context(), s.store)
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
		})
	}
	respondJSON(w, http.StatusOK, items)
}
