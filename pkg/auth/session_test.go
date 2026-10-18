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

	// 5. Validate session via Authorization Bearer header
	reqBearer := httptest.NewRequest("GET", "/api/data", nil)
	reqBearer.Header.Set("Authorization", "Bearer "+tokenStr)
	bearerIdent, err := sm.ValidateSessionCookie(reqBearer)
	if err != nil {
		t.Fatalf("ValidateSessionCookie with Bearer token error: %v", err)
	}
	if bearerIdent.Subject != "user:123" {
		t.Errorf("bearer subject mismatch: %s", bearerIdent.Subject)
	}

	// 6. Clear cookie
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

func TestAuthGateway_BypassPathSecurity(t *testing.T) {
	gateway := NewAuthGateway(GatewayConfig{
		BypassPaths: []string{"/public/*", "/healthz"},
	})

	// Legitimate bypass paths
	if !gateway.IsBypass("/public") {
		t.Errorf("expected /public to be bypassed")
	}
	if !gateway.IsBypass("/public/") {
		t.Errorf("expected /public/ to be bypassed")
	}
	if !gateway.IsBypass("/public/resource") {
		t.Errorf("expected /public/resource to be bypassed")
	}
	if !gateway.IsBypass("/healthz") {
		t.Errorf("expected /healthz to be bypassed")
	}

	// Security: Sibling prefixes must NOT be bypassed
	if gateway.IsBypass("/public-admin") {
		t.Errorf("SECURITY RISK: /public-admin must NOT match /public/*")
	}
	if gateway.IsBypass("/publicity") {
		t.Errorf("SECURITY RISK: /publicity must NOT match /public/*")
	}
	if gateway.IsBypass("/public_secrets") {
		t.Errorf("SECURITY RISK: /public_secrets must NOT match /public/*")
	}
	if gateway.IsBypass("/healthz-extended") {
		t.Errorf("SECURITY RISK: /healthz-extended must NOT match /healthz")
	}
}

func TestAuthGateway_AuthenticatedUserOnBypassRoute(t *testing.T) {
	sm := NewSessionManager("test-secret-key-that-is-32-bytes")
	gateway := NewAuthGateway(GatewayConfig{
		SessionMgr:  sm,
		BypassPaths: []string{"/public/*"},
	})

	ident := &UserIdentity{
		Subject: "alice",
		Email:   "alice@example.com",
		Roles:   []string{"admin"},
	}
	cookie, err := sm.CreateSessionCookie(ident)
	if err != nil {
		t.Fatalf("failed to create session cookie: %v", err)
	}

	req := httptest.NewRequest("GET", "/public/profile", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	identity, ok := gateway.AuthenticateRequest(rec, req)
	if !ok || identity == nil {
		t.Fatalf("expected request to succeed with authenticated identity")
	}
	if identity.Subject != "alice" {
		t.Errorf("expected identity subject 'alice', got %q", identity.Subject)
	}
	if req.Header.Get(HeaderAuthSubject) != "alice" {
		t.Errorf("expected upstream X-Auth-Subject to be injected on bypass route for authenticated user")
	}
}

func TestSessionManager_CustomTTLEnforcement(t *testing.T) {
	// 1 hour custom TTL
	sm := NewSessionManager("test-secret-key-that-is-32-bytes", WithCookieTTL(1*time.Hour))

	// Identity has 24 hour DefaultSessionTTL
	ident := &UserIdentity{
		Subject:   "bob",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	tokenStr, err := sm.CreateSessionToken(ident)
	if err != nil {
		t.Fatalf("CreateSessionToken error: %v", err)
	}

	claims, err := sm.ValidateSessionToken(tokenStr)
	if err != nil {
		t.Fatalf("ValidateSessionToken error: %v", err)
	}

	// Token expiration should be within ~1 hour, NOT 24 hours
	expectedMax := time.Now().Add(65 * time.Minute)
	if claims.ExpiresAt.After(expectedMax) {
		t.Errorf("token ExpiresAt %v exceeds configured 1h TTL (max %v)", claims.ExpiresAt, expectedMax)
	}
}

func TestSimpleAuth_EmptyPasswordRejection(t *testing.T) {
	sa := NewSimpleAuth(SimpleUser{
		Username:     "empty_hash_user",
		PasswordHash: "",
	})

	if _, err := sa.Authenticate("empty_hash_user", ""); err == nil {
		t.Errorf("SECURITY RISK: Authenticate should fail with empty password and empty hash")
	}

	validUser := SimpleUser{
		Username: "valid_user",
	}
	_ = sa.SetUser(validUser.Username, "realpass", "", "", nil)

	if _, err := sa.Authenticate("valid_user", ""); err == nil {
		t.Errorf("SECURITY RISK: Authenticate should fail with empty password against valid user")
	}
}

