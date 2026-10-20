package auth

import (
	"net/http/httptest"
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
