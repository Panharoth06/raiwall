package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/control/declarative"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// IPGroupDTO represents a named IP group transfer object.
type IPGroupDTO struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Type        string            `json:"type"`
	Managed     bool              `json:"managed"`
	EntryCount  int               `json:"entry_count"`
	Entries     []IPGroupEntryDTO `json:"entries,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// IPGroupEntryDTO represents a single CIDR entry in a group.
type IPGroupEntryDTO struct {
	ID        string    `json:"id"`
	GroupID   string    `json:"group_id"`
	CIDR      string    `json:"cidr"`
	Comment   string    `json:"comment"`
	CreatedAt time.Time `json:"created_at"`
}

// handleListIPGroups lists all named IP groups with their entry counts.
func (s *Server) handleListIPGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.store.ListIPGroups(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list IP groups: "+err.Error())
		return
	}

	result := make([]IPGroupDTO, 0, len(groups))
	for _, grp := range groups {
		entries, _ := s.store.ListIPGroupEntries(r.Context(), grp.ID)
		result = append(result, IPGroupDTO{
			ID:          grp.ID,
			Managed:     declarative.IsManaged(grp.ID),
			Name:        grp.Name,
			Description: grp.Description,
			Type:        grp.Type,
			EntryCount:  len(entries),
			CreatedAt:   grp.CreatedAt,
			UpdatedAt:   grp.UpdatedAt,
		})
	}

	respondJSON(w, http.StatusOK, result)
}

func (s *Server) resolveIPGroup(ctx context.Context, idOrName string) (control.IPGroupRecord, error) {
	grp, err := s.store.GetIPGroup(ctx, idOrName)
	if err == nil {
		return grp, nil
	}
	return s.store.GetIPGroupByName(ctx, idOrName)
}

// handleGetIPGroup fetches details and entries for a specific IP group.
func (s *Server) handleGetIPGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	grp, err := s.resolveIPGroup(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusNotFound, "IP group not found")
		return
	}

	entries, _ := s.store.ListIPGroupEntries(r.Context(), grp.ID)
	entriesDTO := make([]IPGroupEntryDTO, 0, len(entries))
	for _, e := range entries {
		entriesDTO = append(entriesDTO, IPGroupEntryDTO{
			ID:        e.ID,
			GroupID:   e.GroupID,
			CIDR:      e.CIDR,
			Comment:   e.Comment,
			CreatedAt: e.CreatedAt,
		})
	}

	respondJSON(w, http.StatusOK, IPGroupDTO{
		ID:          grp.ID,
		Managed:     declarative.IsManaged(grp.ID),
		Name:        grp.Name,
		Description: grp.Description,
		Type:        grp.Type,
		EntryCount:  len(entries),
		Entries:     entriesDTO,
		CreatedAt:   grp.CreatedAt,
		UpdatedAt:   grp.UpdatedAt,
	})
}

// handleCreateIPGroup creates a new named IP group.
func (s *Server) handleCreateIPGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Type        string `json:"type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request payload: "+err.Error())
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		respondError(w, http.StatusBadRequest, "group name cannot be empty")
		return
	}

	if req.Type == "" {
		req.Type = "custom"
	}

	now := time.Now().UTC()
	grp := control.IPGroupRecord{
		ID:          uuid.New().String(),
		Name:        req.Name,
		Description: req.Description,
		Type:        req.Type,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.store.CreateIPGroup(r.Context(), grp); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create IP group: "+err.Error())
		return
	}

	if s.ipGroupMgr != nil {
		_, _ = s.ipGroupMgr.CreateGroup(grp.Name, grp.Description, grp.Type)
	}

	respondJSON(w, http.StatusCreated, IPGroupDTO{
		ID:          grp.ID,
		Managed:     declarative.IsManaged(grp.ID),
		Name:        grp.Name,
		Description: grp.Description,
		Type:        grp.Type,
		CreatedAt:   grp.CreatedAt,
		UpdatedAt:   grp.UpdatedAt,
	})
}

// handleUpdateIPGroup updates an existing IP group metadata.
func (s *Server) handleUpdateIPGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	grp, err := s.resolveIPGroup(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusNotFound, "IP group not found")
		return
	}

	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request payload: "+err.Error())
		return
	}

	if strings.TrimSpace(req.Name) != "" {
		grp.Name = strings.TrimSpace(req.Name)
	}
	grp.Description = req.Description
	grp.UpdatedAt = time.Now().UTC()

	if err := s.store.UpdateIPGroup(r.Context(), grp); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update IP group: "+err.Error())
		return
	}

	respondJSON(w, http.StatusOK, IPGroupDTO{
		ID:          grp.ID,
		Managed:     declarative.IsManaged(grp.ID),
		Name:        grp.Name,
		Description: grp.Description,
		Type:        grp.Type,
		CreatedAt:   grp.CreatedAt,
		UpdatedAt:   grp.UpdatedAt,
	})
}

// handleDeleteIPGroup deletes an IP group and cascades to its entries.
func (s *Server) handleDeleteIPGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	grp, err := s.resolveIPGroup(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusNotFound, "IP group not found")
		return
	}

	if err := s.store.DeleteIPGroup(r.Context(), grp.ID); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to delete IP group: "+err.Error())
		return
	}

	if s.ipGroupMgr != nil {
		_ = s.ipGroupMgr.DeleteGroup(grp.Name)
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleAddIPGroupEntry adds a CIDR/IP prefix to a group dynamically in SQLite and memory BART table.
func (s *Server) handleAddIPGroupEntry(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "id")
	grp, err := s.resolveIPGroup(r.Context(), groupID)
	if err != nil {
		respondError(w, http.StatusNotFound, "IP group not found")
		return
	}

	var req struct {
		CIDR    string `json:"cidr"`
		Comment string `json:"comment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request payload: "+err.Error())
		return
	}

	req.CIDR = strings.TrimSpace(req.CIDR)
	pfx, err := acl.ParsePrefix(req.CIDR)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid IP or CIDR notation: "+err.Error())
		return
	}
	canonicalCIDR := pfx.String()

	entry := control.IPGroupEntryRecord{
		ID:        uuid.New().String(),
		GroupID:   grp.ID,
		CIDR:      canonicalCIDR,
		Comment:   req.Comment,
		CreatedAt: time.Now().UTC(),
	}

	if err := s.store.CreateIPGroupEntry(r.Context(), entry); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to save IP group entry: "+err.Error())
		return
	}

	// Dynamically update in-memory BART table
	if s.ipGroupMgr != nil {
		_, _ = s.ipGroupMgr.AddCIDR(grp.Name, canonicalCIDR, req.Comment)
	}

	respondJSON(w, http.StatusCreated, IPGroupEntryDTO{
		ID:        entry.ID,
		GroupID:   entry.GroupID,
		CIDR:      entry.CIDR,
		Comment:   entry.Comment,
		CreatedAt: entry.CreatedAt,
	})
}

// handleDeleteIPGroupEntry removes a CIDR entry from a group in SQLite and memory BART table.
func (s *Server) handleDeleteIPGroupEntry(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "id")
	entryID := chi.URLParam(r, "entryId")

	grp, err := s.resolveIPGroup(r.Context(), groupID)
	if err != nil {
		respondError(w, http.StatusNotFound, "IP group not found")
		return
	}

	entries, _ := s.store.ListIPGroupEntries(r.Context(), grp.ID)
	var targetCIDR string
	for _, e := range entries {
		if e.ID == entryID {
			targetCIDR = e.CIDR
			break
		}
	}

	if err := s.store.DeleteIPGroupEntry(r.Context(), entryID); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to delete entry: "+err.Error())
		return
	}

	// Dynamically remove from in-memory BART table
	if s.ipGroupMgr != nil && targetCIDR != "" {
		_ = s.ipGroupMgr.RemoveCIDR(grp.Name, targetCIDR)
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
