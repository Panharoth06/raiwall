package caddy

import (
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"go.uber.org/zap"
)

// serveStatic answers a site configured with static routing from its document root.
// Directory listings are never generated, and resolved paths (including symlinks)
// must stay inside the configured root.
func (m *Middleware) serveStatic(w http.ResponseWriter, r *http.Request, app *control.AppConfig) error {
	root, err := filepath.Abs(strings.TrimSpace(app.DocumentRoot))
	if err != nil {
		return m.staticError(w, app, "invalid document root", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return m.staticError(w, app, "document root is not accessible", err)
	}

	rel := path.Clean("/" + r.URL.Path)
	requested := filepath.Join(root, filepath.FromSlash(rel))
	resolved, err := filepath.EvalSymlinks(requested)
	if err != nil {
		http.NotFound(w, r)
		return nil
	}
	if resolved != root && !strings.HasPrefix(resolved, root+string(os.PathSeparator)) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return nil
	}

	info, err := os.Stat(resolved)
	if err != nil {
		http.NotFound(w, r)
		return nil
	}
	if info.IsDir() {
		index := filepath.Join(resolved, "index.html")
		indexInfo, indexErr := os.Stat(index)
		if indexErr != nil || indexInfo.IsDir() {
			http.NotFound(w, r)
			return nil
		}
		resolved = index
	}

	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Raiwall-Route", "static")
	http.ServeFile(w, r, resolved)
	return nil
}

func (m *Middleware) staticError(w http.ResponseWriter, app *control.AppConfig, message string, err error) error {
	if m.logger != nil {
		m.logger.Error(message, zap.String("app_id", app.ID), zap.String("document_root", app.DocumentRoot), zap.Error(err))
	}
	http.Error(w, "Raiwall Gateway: "+message, http.StatusInternalServerError)
	return nil
}
