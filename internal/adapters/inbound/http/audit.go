package api

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

const (
	auditWriteTimeout = 2 * time.Second
	auditUserAgentMax = 512
)

// auditStatusWriter captures the final status without changing the response.
type auditStatusWriter struct {
	http.ResponseWriter
	status int
}

func (w *auditStatusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *auditStatusWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(body)
}

// AuditMiddleware records every mutating control-plane request. Login/logout are
// recorded explicitly because they occur before a principal exists or after it
// is revoked.
func (s *Server) AuditMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !shouldAuditRequest(r) {
			next.ServeHTTP(w, r)
			return
		}
		recorder := &auditStatusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)

		action, targetType, targetID := classifyAuditRequest(r)
		event := control.AuditEvent{
			Action:     action,
			TargetType: targetType,
			TargetID:   targetID,
			StatusCode: recorder.status,
		}
		if authCtx, ok := AuthFromContext(r.Context()); ok {
			event.ActorType = "user"
			event.ActorID = authCtx.UserID
			event.ActorName = authCtx.Username
			event.Role = authCtx.Role
			if authCtx.IsAPIKey {
				event.ActorType = "api_key"
				event.ActorID = authCtx.KeyID
			}
		}
		s.writeAudit(r, event)
	})
}

// recordDeniedAccess writes an audit row when an authenticated principal is
// refused by CSRF or RBAC. It is wired into AuthManager so denials that occur
// before the audit middleware still leave a trace.
func (s *Server) recordDeniedAccess(r *http.Request, authCtx *AuthContext, status int, reason string) {
	if s == nil || s.store == nil || r == nil {
		return
	}
	_, targetType, targetID := classifyAuditRequest(r)
	event := control.AuditEvent{
		Action:     "access_denied",
		TargetType: targetType,
		TargetID:   targetID,
		StatusCode: status,
		Detail:     reason,
	}
	if authCtx != nil {
		event.ActorType = "user"
		event.ActorID = authCtx.UserID
		event.ActorName = authCtx.Username
		event.Role = authCtx.Role
		if authCtx.IsAPIKey {
			event.ActorType = "api_key"
			event.ActorID = authCtx.KeyID
		}
	}
	s.writeAudit(r, event)
}

// writeAudit fills request metadata and persists the event. Failures are logged
// but never break the request path; security-critical callers may check the
// store directly when fail-closed behavior is required.
func (s *Server) writeAudit(r *http.Request, event control.AuditEvent) {
	if s.store == nil {
		return
	}
	if event.ID == "" {
		event.ID = uuid.NewString()
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now().UTC()
	}
	if event.ClientIP == "" {
		event.ClientIP = clientIPFromRequest(r)
	}
	if event.UserAgent == "" {
		event.UserAgent = truncate(r.UserAgent(), auditUserAgentMax)
	}
	if event.RequestID == "" {
		event.RequestID = middleware.GetReqID(r.Context())
	}
	if event.Method == "" {
		event.Method = r.Method
	}
	if event.Path == "" {
		event.Path = r.URL.Path
	}
	if event.SnapshotVersion == 0 {
		if snapshot := control.GetActiveSnapshot(); snapshot != nil {
			event.SnapshotVersion = snapshot.Version
		}
	}
	if event.ActorType == "" {
		event.ActorType = "system"
	}

	ctx, cancel := context.WithTimeout(context.Background(), auditWriteTimeout)
	defer cancel()
	if err := s.store.CreateAuditEvent(ctx, event); err != nil {
		log.Printf("audit: failed to write event: %v", err)
	}
}

func shouldAuditRequest(r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return false
	}
	relative := apiRelativePath(r.URL.Path)
	if relative == "/auth/login" || relative == "/auth/logout" {
		return false
	}
	if strings.HasSuffix(relative, "/test") || strings.HasSuffix(relative, "/dry-run") {
		return false
	}
	return true
}

func classifyAuditRequest(r *http.Request) (action, targetType, targetID string) {
	relative := apiRelativePath(r.URL.Path)
	segments := strings.Split(strings.Trim(relative, "/"), "/")

	switch {
	case relative == "/config/apply":
		return "apply", "config", ""
	case strings.HasPrefix(relative, "/config/rollback/"):
		return "rollback", "config", strings.TrimPrefix(relative, "/config/rollback/")
	case relative == "/system/auto-apply":
		return "update", "system", ""
	case relative == "/rate/bans/release":
		return "unban", "ban", ""
	case relative == "/rate/bans/release-all":
		return "unban_all", "ban", ""
	case len(segments) >= 2 && segments[0] == "users":
		id := segments[1]
		switch {
		case len(segments) == 3 && segments[2] == "password":
			return "password_reset", "operator", id
		case len(segments) == 4 && segments[2] == "sessions":
			return "session_revoke", "operator", id
		case r.Method == http.MethodDelete:
			return "deactivate", "operator", id
		}
		return methodAction(r.Method), "operator", id
	}

	targetType = ""
	if len(segments) > 0 && segments[0] != "" {
		targetType = strings.TrimSuffix(segments[0], "s")
	}
	if len(segments) > 1 {
		targetID = segments[1]
	}
	return methodAction(r.Method), targetType, targetID
}

func methodAction(method string) string {
	switch method {
	case http.MethodPost:
		return "create"
	case http.MethodPut, http.MethodPatch:
		return "update"
	case http.MethodDelete:
		return "delete"
	default:
		return "mutate"
	}
}

// handleListAuditEvents returns audit records newest first (admin only).
func (s *Server) handleListAuditEvents(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireOperatorAdmin(w, r); !ok {
		return
	}
	query := r.URL.Query()
	filter := control.AuditFilter{Actor: query.Get("actor"), Action: query.Get("action")}
	if value := query.Get("from"); value != "" {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			respondError(w, http.StatusBadRequest, "from must be RFC3339")
			return
		}
		filter.From = parsed
	}
	if value := query.Get("to"); value != "" {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			respondError(w, http.StatusBadRequest, "to must be RFC3339")
			return
		}
		filter.To = parsed
	}
	if value := query.Get("limit"); value != "" {
		limit, err := strconv.Atoi(value)
		if err != nil || limit <= 0 {
			respondError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		filter.Limit = limit
	}
	if value := query.Get("offset"); value != "" {
		offset, err := strconv.Atoi(value)
		if err != nil || offset < 0 {
			respondError(w, http.StatusBadRequest, "offset must be a non-negative integer")
			return
		}
		filter.Offset = offset
	}

	events, err := s.store.ListAuditEvents(r.Context(), filter)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list audit events: "+err.Error())
		return
	}
	if events == nil {
		events = []control.AuditEvent{}
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"events": events,
		"limit":  filter.Normalized().Limit,
		"offset": filter.Normalized().Offset,
	})
}

// handleVerifyAuditChain re-hashes the audit chain and checks its Ed25519
// anchors (admin only). Verification is read-only.
func (s *Server) handleVerifyAuditChain(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireOperatorAdmin(w, r); !ok {
		return
	}
	report, err := s.store.VerifyAuditChain(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to verify audit chain: "+err.Error())
		return
	}
	respondJSON(w, http.StatusOK, report)
}
