package auth

import (
	"context"
	"encoding/json"
	"fmt"
)

// Provider type identifiers for the unified directory backends.
const (
	ProviderTypeSimple = "simple"
	ProviderTypeOIDC   = "oidc"
	ProviderTypeLDAP   = "ldap"
	ProviderTypeGitHub = "github"
)

// IdentityProvider is the unified contract every directory backend fulfills.
// Password-capable backends (simple, LDAP) implement Authenticate; redirect
// flows (OIDC, GitHub OAuth2) additionally implement CodeIdentityProvider.
type IdentityProvider interface {
	// Type returns the provider backend identifier.
	Type() string
	// Name is the operator-facing instance label.
	Name() string
	// Authenticate verifies a username/password credential pair.
	Authenticate(ctx context.Context, username, password string) (*UserIdentity, error)
}

// CodeIdentityProvider is the optional capability for redirect-flow providers.
type CodeIdentityProvider interface {
	// AuthCodeURL builds the provider redirect URL for a CSRF state token.
	AuthCodeURL(state string) string
	// ExchangeCode swaps the OAuth2 authorization code for verified claims.
	ExchangeCode(ctx context.Context, code string) (*UserIdentity, error)
}

// errCodeFlowUnsupported is returned by password-only backends.
var errCodeFlowUnsupported = fmt.Errorf("provider does not support the authorization-code flow")

// simpleProvider wraps the local bcrypt credential adapter.
type simpleProvider struct {
	name string
	auth *SimpleAuth
}

func (p *simpleProvider) Type() string { return ProviderTypeSimple }
func (p *simpleProvider) Name() string { return p.name }

func (p *simpleProvider) Authenticate(_ context.Context, username, password string) (*UserIdentity, error) {
	return p.auth.Authenticate(username, password)
}

// NewSimpleProvider adapts SimpleAuth into the unified provider contract.
func NewSimpleProvider(name string, sa *SimpleAuth) IdentityProvider {
	return &simpleProvider{name: name, auth: sa}
}

// oidcProvider adapts OIDCClient.
type oidcProvider struct {
	name   string
	client *OIDCClient
}

func (p *oidcProvider) Type() string { return ProviderTypeOIDC }
func (p *oidcProvider) Name() string { return p.name }

func (p *oidcProvider) Authenticate(context.Context, string, string) (*UserIdentity, error) {
	return nil, errCodeFlowUnsupported
}

func (p *oidcProvider) AuthCodeURL(state string) string { return p.client.AuthCodeURL(state) }

func (p *oidcProvider) ExchangeCode(ctx context.Context, code string) (*UserIdentity, error) {
	return p.client.Exchange(ctx, code)
}

// IdentityProviderSpec is the persisted provider directive: type + instance
// label + backend-specific JSON payload (raiwall_identity_providers row).
type IdentityProviderSpec struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	ConfigJSON string `json:"config"`
}

// NewIdentityProvider instantiates the unified provider for a stored spec.
// simple must be wired in (local directory users live outside config blobs).
func NewIdentityProvider(spec IdentityProviderSpec, simple *SimpleAuth) (IdentityProvider, error) {
	switch spec.Type {
	case ProviderTypeSimple:
		if simple == nil {
			return nil, fmt.Errorf("simple provider requires the local directory adapter")
		}
		return NewSimpleProvider(spec.Name, simple), nil
	case ProviderTypeOIDC:
		var cfg OIDCConfig
		if err := json.Unmarshal([]byte(spec.ConfigJSON), &cfg); err != nil {
			return nil, fmt.Errorf("parse oidc config: %w", err)
		}
		client, err := NewOIDCClient(context.Background(), cfg)
		if err != nil {
			return nil, fmt.Errorf("init oidc client: %w", err)
		}
		return &oidcProvider{name: spec.Name, client: client}, nil
	case ProviderTypeLDAP:
		var cfg LDAPConfig
		if err := json.Unmarshal([]byte(spec.ConfigJSON), &cfg); err != nil {
			return nil, fmt.Errorf("parse ldap config: %w", err)
		}
		if err := cfg.validate(); err != nil {
			return nil, fmt.Errorf("invalid ldap config: %w", err)
		}
		return NewLDAPProvider(spec.Name, cfg), nil
	case ProviderTypeGitHub:
		var cfg GitHubConfig
		if err := json.Unmarshal([]byte(spec.ConfigJSON), &cfg); err != nil {
			return nil, fmt.Errorf("parse github config: %w", err)
		}
		return NewGitHubProvider(spec.Name, cfg), nil
	default:
		return nil, fmt.Errorf("unsupported provider type %q", spec.Type)
	}
}

// AsCodeIdentityProvider narrows a provider when it supports redirect flows.
func AsCodeIdentityProvider(p IdentityProvider) (CodeIdentityProvider, bool) {
	cp, ok := p.(CodeIdentityProvider)
	return cp, ok
}
