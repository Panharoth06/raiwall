package auth

import (
	"net/http/httptest"
	"testing"
)

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
