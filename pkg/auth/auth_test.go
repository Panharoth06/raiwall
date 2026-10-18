package auth

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestSimpleAuth(t *testing.T) {
	hashedPassword, err := HashPassword("secret123")
	if err != nil {
		t.Fatalf("HashPassword error: %v", err)
	}

	sa := NewSimpleAuth(
		SimpleUser{
			Username:     "admin",
			PasswordHash: hashedPassword,
			Email:        "admin@example.com",
			Name:         "Admin User",
			Roles:        []string{"admin", "editor"},
		},
		SimpleUser{
			Username:     "testuser",
			PasswordHash: "plainpassword", // Plaintext fallback
			Email:        "test@example.com",
			Roles:        []string{"viewer"},
		},
	)

	// 1. Successful bcrypt authentication
	identity, err := sa.Authenticate("admin", "secret123")
	if err != nil {
		t.Fatalf("unexpected auth error: %v", err)
	}
	if identity.Subject != "admin" || identity.Email != "admin@example.com" {
		t.Errorf("unexpected identity: %+v", identity)
	}
	if len(identity.Roles) != 2 || identity.Roles[0] != "admin" {
		t.Errorf("unexpected roles: %v", identity.Roles)
	}

	// 2. Invalid bcrypt password
	_, err = sa.Authenticate("admin", "wrongpass")
	if err == nil {
		t.Errorf("expected error for wrong password")
	}

	// 3. Successful plaintext authentication
	identity2, err := sa.Authenticate("testuser", "plainpassword")
	if err != nil {
		t.Fatalf("unexpected plain auth error: %v", err)
	}
	if identity2.Subject != "testuser" {
		t.Errorf("expected testuser, got %s", identity2.Subject)
	}

	// 4. Non-existent user
	_, err = sa.Authenticate("ghost", "pass")
	if err == nil {
		t.Errorf("expected error for unknown user")
	}

	// 5. User management: SetUser, GetUser, DeleteUser
	err = sa.SetUser("newuser", "newpass", "new@example.com", "Newbie", []string{"guest"})
	if err != nil {
		t.Fatalf("SetUser error: %v", err)
	}
	u, ok := sa.GetUser("newuser")
	if !ok || u.Email != "new@example.com" {
		t.Errorf("GetUser failed: ok=%v, u=%+v", ok, u)
	}
	identNew, err := sa.Authenticate("newuser", "newpass")
	if err != nil || identNew == nil {
		t.Fatalf("Authenticate newuser error: %v", err)
	}

	if !sa.DeleteUser("newuser") {
		t.Errorf("DeleteUser should return true")
	}
	if _, ok := sa.GetUser("newuser"); ok {
		t.Errorf("user should be deleted")
	}
}

func TestOIDCClient_MockFlow(t *testing.T) {
	cfg := OIDCConfig{
		IssuerURL:    "https://idp.example.com",
		ClientID:     "raiwall-client",
		ClientSecret: "raiwall-secret",
		RedirectURL:  "https://gateway.example.com/.raiwall/auth/callback",
		Scopes:       []string{"openid", "profile", "email"},
	}

	client := NewMockOIDCClient(cfg, func(ctx context.Context, code string) (*UserIdentity, error) {
		if code == "valid-auth-code" {
			return &UserIdentity{
				Subject:   "oidc-user-123",
				Email:     "oidc@example.com",
				Name:      "OIDC User",
				Roles:     []string{"sso-user"},
				Provider:  "oidc",
				IssuedAt:  time.Now(),
				ExpiresAt: time.Now().Add(1 * time.Hour),
			}, nil
		}
		return nil, fmt.Errorf("invalid authorization code: %s", code)
	})

	// 1. State generation and consumption
	targetURL := "/dashboard/analytics"
	state := client.GenerateState(targetURL)
	if state == "" {
		t.Fatalf("expected non-empty state token")
	}

	authURL := client.AuthCodeURL(state)
	expectedPrefix := "https://idp.example.com/auth?client_id=raiwall-client"
	if len(authURL) < len(expectedPrefix) || authURL[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("unexpected authURL: %s", authURL)
	}

	consumedTarget, ok := client.VerifyAndConsumeState(state)
	if !ok || consumedTarget != targetURL {
		t.Errorf("VerifyAndConsumeState failed: ok=%v, target=%s", ok, consumedTarget)
	}

	// State should only be consumable once
	_, ok = client.VerifyAndConsumeState(state)
	if ok {
		t.Errorf("state should be invalidated after first use")
	}

	// 2. Code exchange
	ctx := context.Background()
	identity, err := client.Exchange(ctx, "valid-auth-code")
	if err != nil {
		t.Fatalf("Exchange error: %v", err)
	}
	if identity.Subject != "oidc-user-123" || identity.Email != "oidc@example.com" {
		t.Errorf("unexpected identity: %+v", identity)
	}

	// Invalid code exchange
	_, err = client.Exchange(ctx, "invalid-code")
	if err == nil {
		t.Errorf("expected error for invalid auth code")
	}
}
