package caddy

import (
	"fmt"
	html "html"
	"net/http"
	"strings"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"go.uber.org/zap"
)

// serveRedirect answers a site configured with redirect routing.
func (m *Middleware) serveRedirect(w http.ResponseWriter, r *http.Request, app *control.AppConfig) error {
	target := strings.TrimSpace(app.RedirectURL)
	if !control.IsValidRedirectTarget(target) {
		if m.logger != nil {
			m.logger.Error("invalid redirect target in active snapshot",
				zap.String("app_id", app.ID), zap.String("target", target))
		}
		http.Error(w, "Raiwall Gateway: invalid redirect target configured for this host", http.StatusInternalServerError)
		return nil
	}

	status := app.RedirectStatus
	if !control.IsValidRedirectStatus(status) {
		status = http.StatusFound
	}

	w.Header().Set("Location", target)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Raiwall-Route", "redirect")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><title>Redirecting</title></head><body><p>Redirecting to <a href="%s">%s</a>.</p></body></html>`,
		html.EscapeString(target), html.EscapeString(target))
	return nil
}
