package api

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// AutoApplyMiddleware promotes configuration to the live data plane after every
// successful mutation of a resource compiled into the snapshot. The handler
// response is buffered so that an apply failure is reported to the operator
// instead of leaving the data plane silently stale.
func (s *Server) AutoApplyMiddleware(next http.Handler) http.Handler {
	// Auto-apply is toggled after NewServer builds the router, so the flag is
	// read per request rather than captured during route registration.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.autoApply || !isSnapshotMutation(r.Method, r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		buffered := newBufferedResponse()
		next.ServeHTTP(buffered, r)

		if buffered.status < http.StatusOK || buffered.status >= http.StatusMultipleChoices {
			buffered.writeTo(w)
			return
		}

		author := "system"
		if authCtx, ok := AuthFromContext(r.Context()); ok && authCtx.Username != "" {
			author = authCtx.Username
		}
		description := fmt.Sprintf("Auto-applied after %s %s", r.Method, r.URL.Path)

		s.applyMu.Lock()
		snapshot, err := control.DeploySnapshot(r.Context(), s.store, author, description)
		s.applyMu.Unlock()
		if err != nil {
			respondError(w, http.StatusInternalServerError,
				"change saved but failed to apply to the live data plane: "+err.Error())
			return
		}

		s.publishVersion(snapshot.Version)
		buffered.Header().Set("X-Raiwall-Config-Version", strconv.FormatUint(snapshot.Version, 10))
		buffered.writeTo(w)
	})
}

// isSnapshotMutation reports whether a request changes a resource that the
// snapshot compiler reads. Simulation endpoints, runtime state (bans, API
// keys), certificates, templates, IP groups, and identity records are managed
// outside the snapshot and are deliberately excluded.
func isSnapshotMutation(method, path string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return false
	}

	path = apiRelativePath(path)
	switch {
	case path == "/sites":
		return true
	case strings.HasPrefix(path, "/sites/"):
		// Discovered API resources are catalog metadata, not routing config.
		rest := strings.TrimPrefix(path, "/sites/")
		return !strings.Contains(rest, "/resources")
	case path == "/exceptions/test", path == "/exceptions/dry-run",
		path == "/acls/test", path == "/acls/dry-run":
		return false
	case path == "/exceptions", strings.HasPrefix(path, "/exceptions/"):
		return true
	case path == "/acls", strings.HasPrefix(path, "/acls/"):
		return true
	case path == "/policies", strings.HasPrefix(path, "/policies/"):
		return true
	case path == "/detector", strings.HasPrefix(path, "/detector/"):
		return true
	case path == "/inner-rules", strings.HasPrefix(path, "/inner-rules/"):
		return true
	default:
		return false
	}
}

// apiRelativePath strips the versioned prefixes the router serves the API on.
func apiRelativePath(path string) string {
	for _, prefix := range []string{"/.raiwall/api/v1", "/api/v1"} {
		if strings.HasPrefix(path, prefix) {
			path = strings.TrimPrefix(path, prefix)
			break
		}
	}
	return strings.TrimSuffix(path, "/")
}

// bufferedResponse captures a handler response until the snapshot apply that
// follows it succeeds.
type bufferedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newBufferedResponse() *bufferedResponse {
	return &bufferedResponse{header: make(http.Header)}
}

func (b *bufferedResponse) Header() http.Header {
	return b.header
}

func (b *bufferedResponse) WriteHeader(status int) {
	if b.status == 0 {
		b.status = status
	}
}

func (b *bufferedResponse) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	return b.body.Write(p)
}

// Flush satisfies http.Flusher; mutating control-plane responses are buffered.
func (b *bufferedResponse) Flush() {}

func (b *bufferedResponse) writeTo(w http.ResponseWriter) {
	for key, values := range b.header {
		w.Header()[key] = append([]string(nil), values...)
	}
	status := b.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(b.body.Bytes())
}

// compile-time assertion that the buffered writer supports flushing.
var _ http.Flusher = (*bufferedResponse)(nil)
