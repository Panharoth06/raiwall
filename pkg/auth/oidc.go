package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCConfig configures OpenID Connect Single Sign-On.
type OIDCConfig struct {
	IssuerURL     string   `json:"issuer_url"`
	ClientID      string   `json:"client_id"`
	ClientSecret  string   `json:"client_secret"`
	RedirectURL   string   `json:"redirect_url"`
	Scopes        []string `json:"scopes,omitempty"`
	InsecureSkip  bool     `json:"insecure_skip,omitempty"`
}

type stateEntry struct {
	TargetURL string
	CreatedAt time.Time
}

// OIDCClient handles OpenID Connect discovery, redirect generation, and code exchange.
type OIDCClient struct {
	cfg          OIDCConfig
	provider     *oidc.Provider
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
	states       sync.Map // state string -> stateEntry

	// mockExchange allows testing token exchange in isolated environments
	mockExchange func(ctx context.Context, code string) (*UserIdentity, error)
}

// NewOIDCClient initializes an OIDC provider and OAuth2 client from issuer discovery.
func NewOIDCClient(ctx context.Context, cfg OIDCConfig) (*OIDCClient, error) {
	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("issuer_url is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %q: %w", cfg.IssuerURL, err)
	}

	oauthConfig := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	verifierConfig := &oidc.Config{
		ClientID: cfg.ClientID,
	}
	if cfg.InsecureSkip {
		verifierConfig.SkipIssuerCheck = true
	}

	verifier := provider.Verifier(verifierConfig)

	return &OIDCClient{
		cfg:          cfg,
		provider:     provider,
		oauth2Config: oauthConfig,
		verifier:     verifier,
	}, nil
}

// NewMockOIDCClient creates a test OIDCClient without contacting an external IdP.
func NewMockOIDCClient(cfg OIDCConfig, exchangeFn func(ctx context.Context, code string) (*UserIdentity, error)) *OIDCClient {
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}

	oauthConfig := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  cfg.IssuerURL + "/auth",
			TokenURL: cfg.IssuerURL + "/token",
		},
		Scopes: scopes,
	}

	return &OIDCClient{
		cfg:          cfg,
		oauth2Config: oauthConfig,
		mockExchange: exchangeFn,
	}
}

// GenerateState generates a secure random state tied to an optional target return URL.
func (c *OIDCClient) GenerateState(targetURL string) string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	state := base64.RawURLEncoding.EncodeToString(b)

	c.states.Store(state, stateEntry{
		TargetURL: targetURL,
		CreatedAt: time.Now(),
	})

	return state
}

// VerifyAndConsumeState verifies a received state token and returns the original target URL.
func (c *OIDCClient) VerifyAndConsumeState(state string) (string, bool) {
	if state == "" {
		return "", false
	}
	v, ok := c.states.LoadAndDelete(state)
	if !ok {
		return "", false
	}
	entry := v.(stateEntry)
	if time.Since(entry.CreatedAt) > 10*time.Minute {
		return "", false
	}
	return entry.TargetURL, true
}

// AuthCodeURL produces the IdP redirect URL for user authentication.
func (c *OIDCClient) AuthCodeURL(state string) string {
	if c.oauth2Config == nil {
		return ""
	}
	return c.oauth2Config.AuthCodeURL(state)
}

// Exchange swaps an authorization code for an ID token and returns the verified UserIdentity.
func (c *OIDCClient) Exchange(ctx context.Context, code string) (*UserIdentity, error) {
	if c.mockExchange != nil {
		return c.mockExchange(ctx, code)
	}

	if c.oauth2Config == nil || c.verifier == nil {
		return nil, fmt.Errorf("oidc client not properly initialized")
	}

	oauth2Token, err := c.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("missing id_token in token response")
	}

	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify id_token: %w", err)
	}

	var claims struct {
		Subject     string         `json:"sub"`
		Email       string         `json:"email"`
		Name        string         `json:"name"`
		Groups      []string       `json:"groups"`
		Roles       []string       `json:"roles"`
		RealmAccess map[string]any `json:"realm_access"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("parse id_token claims: %w", err)
	}

	// Consolidate roles from various IdP conventions (Keycloak, Okta, standard)
	roles := claims.Roles
	if len(roles) == 0 {
		roles = claims.Groups
	}
	if len(roles) == 0 && claims.RealmAccess != nil {
		if rawRoles, ok := claims.RealmAccess["roles"].([]any); ok {
			for _, r := range rawRoles {
				if str, ok := r.(string); ok {
					roles = append(roles, str)
				}
			}
		}
	}

	name := claims.Name
	if name == "" {
		name = claims.Email
	}
	if name == "" {
		name = claims.Subject
	}

	now := time.Now()
	return &UserIdentity{
		Subject:   claims.Subject,
		Email:     claims.Email,
		Name:      name,
		Roles:     roles,
		Provider:  "oidc",
		IssuedAt:  now,
		ExpiresAt: now.Add(DefaultSessionTTL),
	}, nil
}

// Config returns the active OIDCConfig.
func (c *OIDCClient) Config() OIDCConfig {
	return c.cfg
}

// MarshalJSON helper for serializing config
func (c *OIDCConfig) MarshalJSON() ([]byte, error) {
	type Alias OIDCConfig
	return json.Marshal(&struct {
		*Alias
		ClientSecret string `json:"client_secret,omitempty"`
	}{
		Alias:        (*Alias)(c),
		ClientSecret: strings.Repeat("*", len(c.ClientSecret)),
	})
}
