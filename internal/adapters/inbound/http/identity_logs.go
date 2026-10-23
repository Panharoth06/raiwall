package api

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
)

// handleListIdentityAuthEvents serves the authentication audit log
// (newest first) for the auth gateway console.
func (s *Server) handleListIdentityAuthEvents(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if raw := chi.URLParam(r, "limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}

	events, err := s.store.ListIdentityAuthEvents(r.Context(), limit)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list auth events: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, events)
}
