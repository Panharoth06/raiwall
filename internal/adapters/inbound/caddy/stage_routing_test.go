package caddy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

func routingApp(routing, root, target string, status int) *control.AppConfig {
	return &control.AppConfig{
		ID:             "site-test",
		Name:           "Test",
		Hostnames:      []string{"app.test.local"},
		RoutingType:    routing,
		DocumentRoot:   root,
		RedirectURL:    target,
		RedirectStatus: status,
	}
}

func TestServeStaticServesIndexAndAssets(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("<h1>hello</h1>"), 0o644); err != nil {
		t.Fatalf("write index: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "assets"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "assets", "app.css"), []byte("body{}"), 0o644); err != nil {
		t.Fatalf("write asset: %v", err)
	}

	m := &Middleware{}
	app := routingApp(control.RoutingStatic, root, "", 0)

	for _, tc := range []struct{ path, want string }{
		{"/", "<h1>hello</h1>"},
		{"/assets/app.css", "body{}"},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://app.test.local"+tc.path, nil)
		if err := m.serveStatic(rec, req, app); err != nil {
			t.Fatalf("serveStatic(%s): %v", tc.path, err)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("serveStatic(%s) status = %d, want 200", tc.path, rec.Code)
		}
		if got := rec.Body.String(); got != tc.want {
			t.Errorf("serveStatic(%s) body = %q, want %q", tc.path, got, tc.want)
		}
		if rec.Header().Get("X-Raiwall-Route") != "static" {
			t.Errorf("missing static route marker for %s", tc.path)
		}
	}
}

func TestServeStaticRejectsTraversal(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "public")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(parent, "secret.txt"), []byte("secret"), 0o644); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	m := &Middleware{}
	app := routingApp(control.RoutingStatic, root, "", 0)

	for _, target := range []string{"/../secret.txt", "/..%2fsecret.txt", "/%2e%2e/secret.txt"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://app.test.local/", nil)
		req.URL.Path = target
		if err := m.serveStatic(rec, req, app); err != nil {
			t.Fatalf("serveStatic(%s): %v", target, err)
		}
		if rec.Code == http.StatusOK && rec.Body.String() == "secret" {
			t.Fatalf("path traversal served: %s", target)
		}
	}
}

func TestServeStaticMissingFileReturns404(t *testing.T) {
	root := t.TempDir()
	m := &Middleware{}
	app := routingApp(control.RoutingStatic, root, "", 0)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://app.test.local/missing", nil)
	if err := m.serveStatic(rec, req, app); err != nil {
		t.Fatalf("serveStatic: %v", err)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestServeStaticUnreadableRootReturns500(t *testing.T) {
	m := &Middleware{}
	app := routingApp(control.RoutingStatic, "/definitely/not/a/real/path", "", 0)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://app.test.local/", nil)
	if err := m.serveStatic(rec, req, app); err != nil {
		t.Fatalf("serveStatic: %v", err)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestServeRedirect(t *testing.T) {
	m := &Middleware{}
	app := routingApp(control.RoutingRedirect, "", "https://example.com/landing", http.StatusPermanentRedirect)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://app.test.local/old", nil)
	if err := m.serveRedirect(rec, req, app); err != nil {
		t.Fatalf("serveRedirect: %v", err)
	}
	if rec.Code != http.StatusPermanentRedirect {
		t.Fatalf("status = %d, want 308", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "https://example.com/landing" {
		t.Errorf("Location = %q", got)
	}
	if got := rec.Header().Get("X-Raiwall-Route"); got != "redirect" {
		t.Errorf("X-Raiwall-Route = %q", got)
	}
}

func TestServeRedirectFallsBackTo302AndRejectsInvalidTarget(t *testing.T) {
	m := &Middleware{}
	app := routingApp(control.RoutingRedirect, "", "/login", 200)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://app.test.local/", nil)
	if err := m.serveRedirect(rec, req, app); err != nil {
		t.Fatalf("serveRedirect: %v", err)
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 fallback", rec.Code)
	}

	app.RedirectURL = "javascript:alert(1)"
	rec = httptest.NewRecorder()
	if err := m.serveRedirect(rec, req, app); err != nil {
		t.Fatalf("serveRedirect: %v", err)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for invalid target", rec.Code)
	}
	if rec.Header().Get("Location") != "" {
		t.Error("invalid target must not be reflected into Location")
	}
}
