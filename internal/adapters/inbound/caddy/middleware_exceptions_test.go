package caddy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	caddyv2 "github.com/caddyserver/caddy/v2"
)

func TestMiddleware_ExceptionEngine_ServeHTTP(t *testing.T) {
	control.StoreSnapshot(control.NewConfigSnapshot(100, control.ModeDefense, nil))
	t.Cleanup(func() {
		control.StoreSnapshot(control.NewConfigSnapshot(0, control.ModeDefense, nil))
	})

	// Create ExceptionEngine whitelisting parameter 'q' on path '/search'
	exEng, err := acl.NewExceptionEngine(&acl.ExceptionRule{
		ID:         "EX_SEARCH_QUERY",
		Host:       "example.com",
		PathPrefix: "/search",
		Method:     "GET",
		Location:   "query",
		ParamName:  "q",
		RuleID:     "*",
	})
	if err != nil {
		t.Fatalf("failed to create ExceptionEngine: %v", err)
	}

	semEng := waf.NewSemanticEngine(waf.WithExceptionEngine(exEng))

	mw := &Middleware{
		Mode: "defense",
	}
	caddyCtx, cancel := caddyv2.NewContext(caddyv2.Context{Context: context.Background()})
	defer cancel()
	if err := mw.Provision(caddyCtx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	mw.engine = semEng
	mw.SetExceptionEngine(exEng)

	t.Run("Excepted parameter with SQLi bypasses WAF", func(t *testing.T) {
		// ' UNION SELECT 1,2,3-- in parameter 'q' is excepted
		req := httptest.NewRequest(http.MethodGet, "http://example.com/search?q=%27+UNION+SELECT+1%2C2%2C3--", nil)
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		err := mw.ServeHTTP(rec, req, next)
		if err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if !next.invoked {
			t.Error("expected request with excepted parameter to pass to upstream")
		}
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rec.Code)
		}
	})

	t.Run("Non-excepted parameter with SQLi is blocked", func(t *testing.T) {
		// ' UNION SELECT 1,2,3-- in parameter 'category' is NOT excepted
		req := httptest.NewRequest(http.MethodGet, "http://example.com/search?category=%27+UNION+SELECT+1%2C2%2C3--", nil)
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		err := mw.ServeHTTP(rec, req, next)
		if err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if next.invoked {
			t.Error("expected non-excepted attack parameter to be blocked")
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden, got %d", rec.Code)
		}
	})

	t.Run("Cookie parameter exception bypasses WAF while other cookies blocked", func(t *testing.T) {
		_ = exEng.AddRule(&acl.ExceptionRule{
			ID:        "EX_COOKIE_AUTH",
			Host:      "example.com",
			Location:  "cookie",
			ParamName: "exempt_cookie",
			RuleID:    "SEMANTIC_SQLI",
		})

		// A. Whitelisted cookie passes
		req := httptest.NewRequest(http.MethodGet, "http://example.com/search", nil)
		req.AddCookie(&http.Cookie{Name: "exempt_cookie", Value: "1' OR '1'='1"})
		rec := httptest.NewRecorder()
		next := &mockNextHandler{}

		err := mw.ServeHTTP(rec, req, next)
		if err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if !next.invoked {
			t.Error("expected excepted cookie parameter to be allowed")
		}
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d", rec.Code)
		}

		// B. Non-whitelisted cookie with attack is blocked
		req2 := httptest.NewRequest(http.MethodGet, "http://example.com/search", nil)
		req2.AddCookie(&http.Cookie{Name: "malicious_cookie", Value: "1' OR '1'='1"})
		rec2 := httptest.NewRecorder()
		next2 := &mockNextHandler{}

		err = mw.ServeHTTP(rec2, req2, next2)
		if err != nil {
			t.Fatalf("ServeHTTP error: %v", err)
		}
		if next2.invoked {
			t.Error("expected non-excepted malicious cookie to be blocked")
		}
		if rec2.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden, got %d", rec2.Code)
		}
	})
}
