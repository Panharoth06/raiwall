package proxy

import (
	"io"
	"io/fs"
	"net/http"
	"strings"

	"github.com/Panharoth06/raiwall/web"
)

// UIHandler serves the embedded Vue 3 SPA admin dashboard under /.raiwall/ with HTML5 history fallback.
type UIHandler struct {
	distFS     fs.FS
	fileServer http.Handler
	indexHTML  []byte
}

// NewUIHandler constructs an SPA UIHandler using embedded static assets.
func NewUIHandler() (*UIHandler, error) {
	distSub, err := fs.Sub(web.DistFS, "dist")
	if err != nil {
		return nil, err
	}

	indexFile, err := distSub.Open("index.html")
	var indexData []byte
	if err == nil {
		indexData, _ = io.ReadAll(indexFile)
		_ = indexFile.Close()
	}

	return &UIHandler{
		distFS:     distSub,
		fileServer: http.FileServer(http.FS(distSub)),
		indexHTML:  indexData,
	}, nil
}

// ServeHTTP handles requests to /.raiwall and subpaths with SPA fallback.
func (h *UIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqPath := r.URL.Path

	// Strip the /.raiwall prefix
	relPath := strings.TrimPrefix(reqPath, "/.raiwall")
	relPath = strings.TrimPrefix(relPath, "/")

	if relPath == "" || relPath == "index.html" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(h.indexHTML)
		return
	}

	// Check if the requested file exists in embedded assets
	f, err := h.distFS.Open(relPath)
	if err == nil {
		_ = f.Close()
		// Serve static asset with original request URL stripped
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/" + relPath
		h.fileServer.ServeHTTP(w, r2)
		return
	}

	// SPA fallback: return index.html for unknown client-side routes
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(h.indexHTML)
}
