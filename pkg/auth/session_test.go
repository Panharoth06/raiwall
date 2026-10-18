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

func TestSessionManager_Lifecycle(t *testing.T) {
	sm := NewSessionManager("super-secret-key-at-least-32-bytes!!",
		WithCookieName("test_session"),
		WithCookieTTL(1*time.Hour),
		WithCookieSecure(true),
	)

	identity := &UserIdentity{
		Subject:  "user:123",
		Email:    "user@example.com",
		Name:     "Alice",
		Roles:    []string{"admin"},
		Provider: "simple",
	}

	// 1. Issue and validate token
	tokenStr, err := sm.CreateSessionToken(identity)
	if err != nil {
		t.Fatalf("CreateSessionToken error: %v", err)
	}

	valIdent, err := sm.ValidateSessionToken(tokenStr)
	if err != nil {
		t.Fatalf("ValidateSessionToken error: %v", err)
	}
	if valIdent.Subject != "user:123" || valIdent.Email != "user@example.com" {
		t.Errorf("identity mismatch: %+v", valIdent)
	}

	// 2. Tampered token
	tampered := tokenStr + "tamper"
	_, err = sm.ValidateSessionToken(tampered)
	if err == nil {
		t.Errorf("expected error for tampered token")
	}

	// 3. Different signing key
	smOther := NewSessionManager("different-secret-key-32-bytes-long!",
		WithCookieName("test_session"),
	)
	_, err = smOther.ValidateSessionToken(tokenStr)
	if err == nil {
		t.Errorf("expected error for token signed with different key")
	}

	// 4. Create and Validate session cookie
	cookie, err := sm.CreateSessionCookie(identity)
	if err != nil {
		t.Fatalf("CreateSessionCookie error: %v", err)
	}
	if cookie.Name != "test_session" || !cookie.HttpOnly || !cookie.Secure {
		t.Errorf("unexpected cookie attributes: %+v", cookie)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookie)
	extracted, err := sm.ValidateSessionCookie(req)
	if err != nil {
		t.Fatalf("ValidateSessionCookie error: %v", err)
	}
	if extracted.Subject != "user:123" {
		t.Errorf("extracted subject mismatch: %s", extracted.Subject)
	}

	// 5. Clear cookie
	clearCookie := sm.ClearSessionCookie()
	if clearCookie.MaxAge != -1 || clearCookie.Value != "" {
		t.Errorf("expected MaxAge: -1 cookie, got %+v", clearCookie)
	}
}

func TestSessionManager_Expiration(t *testing.T) {
	sm := NewSessionManager("secret-key-32-bytes-long-for-testing",
		WithCookieTTL(10*time.Millisecond),
	)

	identity := &UserIdentity{
		Subject:   "user:temp",
		ExpiresAt: time.Now().Add(10 * time.Millisecond),
	}
	tokenStr, _ := sm.CreateSessionToken(identity)

	time.Sleep(30 * time.Millisecond)

	_, err := sm.ValidateSessionToken(tokenStr)
	if err == nil {
		t.Errorf("expected expiration error for expired token")
	}
}

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
	if !allowed || ident == nil || ident.Subject != "local:alice" {
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

	if spoofedHeader.Get("X-Auth-Subject") != "local:alice" {
		t.Errorf("expected Subject 'local:alice', got %q", spoofedHeader.Get("X-Auth-Subject"))
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
