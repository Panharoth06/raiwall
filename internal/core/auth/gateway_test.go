package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAuthGateway_EndpointsAndProtection(t *testing.T) {
	simple := NewSimpleAuth(SimpleUser{
		Username:     "alice",
		PasswordHash: "secretpass",
		Email:        "alice@corp.com",
		Roles:        []string{"manager"},
	})
	session := NewSessionManager("very-secure-gateway-session-key-32b",
		WithCookieSecure(false), // For tests
	)

	gateway := NewAuthGateway(GatewayConfig{
		SimpleAuth: simple,
		SessionMgr: session,
		BypassPaths: []string{
			"/public/*",
			"/healthz",
			"/webhook/stripe",
		},
	})

	// 1. Bypass check
	if !gateway.IsBypass("/public/styles.css") {
		t.Errorf("expected /public/styles.css to be bypassed")
	}
	if !gateway.IsBypass("/healthz") {
		t.Errorf("expected /healthz to be bypassed")
	}
	if !gateway.IsBypass("/webhook/stripe") {
		t.Errorf("expected /webhook/stripe to be bypassed")
	}
	if gateway.IsBypass("/admin/dashboard") {
		t.Errorf("expected /admin/dashboard NOT to be bypassed")
	}

	// 2. Unauthenticated request to protected route
	recUnauth := httptest.NewRecorder()
	reqUnauth := httptest.NewRequest("GET", "/admin/dashboard", nil)
	ident, allowed := gateway.AuthenticateRequest(recUnauth, reqUnauth)
	if allowed || ident != nil {
		t.Errorf("expected unauthenticated request to be rejected")
	}
	if recUnauth.Code != http.StatusFound {
		t.Errorf("expected browser to be redirected to login, got %d", recUnauth.Code)
	}

	// 3. Unauthenticated API request gets 401 JSON
	recAPI := httptest.NewRecorder()
	reqAPI := httptest.NewRequest("GET", "/api/v1/protected", nil)
	_, allowedAPI := gateway.AuthenticateRequest(recAPI, reqAPI)
	if allowedAPI {
		t.Errorf("expected API request without session to be blocked")
	}
	if recAPI.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for API, got %d", recAPI.Code)
	}

	// 4. Login POST with valid credentials
	form := url.Values{
		"username": {"alice"},
		"password": {"secretpass"},
		"redirect": {"/admin/dashboard"},
	}
	reqLogin := httptest.NewRequest("POST", "/.raiwall/auth/login", strings.NewReader(form.Encode()))
	reqLogin.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recLogin := httptest.NewRecorder()

	gateway.HandleLogin(recLogin, reqLogin)

	if recLogin.Code != http.StatusFound {
		t.Fatalf("expected redirect 302, got %d", recLogin.Code)
	}
	if recLogin.Header().Get("Location") != "/admin/dashboard" {
		t.Errorf("expected redirect to /admin/dashboard, got %s", recLogin.Header().Get("Location"))
	}

	resCookies := recLogin.Result().Cookies()
	if len(resCookies) == 0 {
		t.Fatalf("expected session cookie in response")
	}
	sessionCookie := resCookies[0]

	// 5. Authenticated request to protected route
	recAuth := httptest.NewRecorder()
	reqAuth := httptest.NewRequest("GET", "/admin/dashboard", nil)
	reqAuth.AddCookie(sessionCookie)
	ident, allowed = gateway.AuthenticateRequest(recAuth, reqAuth)
	if !allowed || ident == nil || ident.Subject != "alice" {
		t.Errorf("expected authenticated request to be allowed, got allowed=%v, ident=%+v", allowed, ident)
	}

	// 6. Header injection: strip untrusted client headers and inject claims
	spoofedHeader := http.Header{
		"X-Auth-Subject": []string{"attacker"},
		"X-Auth-Email":   []string{"evil@hacker.com"},
		"X-Auth-Roles":   []string{"root"},
		"User-Agent":     []string{"curl"},
	}
	InjectIdentityHeaders(spoofedHeader, ident)

	if spoofedHeader.Get("X-Auth-Subject") != "alice" {
		t.Errorf("expected Subject 'alice', got %q", spoofedHeader.Get("X-Auth-Subject"))
	}
	if spoofedHeader.Get("X-Auth-Email") != "alice@corp.com" {
		t.Errorf("expected Email 'alice@corp.com', got %q", spoofedHeader.Get("X-Auth-Email"))
	}
	if spoofedHeader.Get("X-Auth-Roles") != "manager" {
		t.Errorf("expected Roles 'manager', got %q", spoofedHeader.Get("X-Auth-Roles"))
	}
	if spoofedHeader.Get("User-Agent") != "curl" {
		t.Errorf("expected other headers to be preserved")
	}

	// 7. Logout endpoint
	reqLogout := httptest.NewRequest("GET", "/.raiwall/auth/logout", nil)
	recLogout := httptest.NewRecorder()
	gateway.HandleLogout(recLogout, reqLogout)
	if recLogout.Code != http.StatusFound {
		t.Errorf("expected redirect on logout, got %d", recLogout.Code)
	}

	// 8. OIDC callback mock
	mockOIDC := NewMockOIDCClient(OIDCConfig{
		IssuerURL: "https://idp.mock",
		ClientID:  "mock-client",
	}, func(ctx context.Context, code string) (*UserIdentity, error) {
		return &UserIdentity{
			Subject:  "oidc:bob",
			Email:    "bob@idp.mock",
			Roles:    []string{"user"},
			Provider: "oidc",
		}, nil
	})
	gatewayOIDC := NewAuthGateway(GatewayConfig{
		OIDCClient: mockOIDC,
		SessionMgr: session,
	})

	state := mockOIDC.GenerateState("/profile")
	reqCallback := httptest.NewRequest("GET", "/.raiwall/auth/callback?code=mock-code&state="+state, nil)
	recCallback := httptest.NewRecorder()
	gatewayOIDC.HandleCallback(recCallback, reqCallback)

	if recCallback.Code != http.StatusFound {
		t.Fatalf("expected callback redirect, got %d", recCallback.Code)
	}
	if recCallback.Header().Get("Location") != "/profile" {
		t.Errorf("expected redirect to /profile, got %s", recCallback.Header().Get("Location"))
	}
}

func TestAuthGateway_OpenRedirectProtection(t *testing.T) {
	gateway := NewAuthGateway(GatewayConfig{
		SimpleAuth: NewSimpleAuth(SimpleUser{
			Username:     "alice",
			PasswordHash: "secretpass",
		}),
	})

	maliciousTargets := []string{
		"javascript:alert(1)",
		"//evil.com/phish",
		"/\\evil.com/phish",
		"\\evil.com",
		"http://evil.com",
		"https://evil.com",
		"data:text/html,<script>alert(1)</script>",
	}

	for _, target := range maliciousTargets {
		form := url.Values{
			"username":  {"alice"},
			"password":  {"secretpass"},
			"redirect":  {target},
			"auth_type": {"simple"},
		}
		req := httptest.NewRequest("POST", "/.raiwall/auth/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		gateway.HandleLogin(rec, req)

		if rec.Code != http.StatusFound {
			t.Fatalf("expected redirect (302), got %d", rec.Code)
		}
		loc := rec.Header().Get("Location")
		if loc != "/" {
			t.Errorf("expected safe fallback redirect '/', got %q for malicious target %q", loc, target)
		}
	}
}

func TestOIDCClient_StatePruning(t *testing.T) {
	client := NewMockOIDCClient(OIDCConfig{
		IssuerURL: "https://idp.mock",
		ClientID:  "test-client",
	}, nil)

	// Generate state and manually simulate expiration
	state := client.GenerateState("/secret")
	client.states.Store(state, stateEntry{
		TargetURL: "/secret",
		CreatedAt: time.Now().Add(-15 * time.Minute),
	})

	// Generating a new state should trigger pruning of expired state
	_ = client.GenerateState("/new")

	if _, ok := client.VerifyAndConsumeState(state); ok {
		t.Errorf("expected expired state to be pruned")
	}
}
