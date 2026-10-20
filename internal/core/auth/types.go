package auth

import (
	"time"
)

// Well-known HTTP header names injected upstream after identity validation.
const (
	HeaderAuthSubject = "X-Auth-Subject"
	HeaderAuthEmail   = "X-Auth-Email"
	HeaderAuthName    = "X-Auth-Name"
	HeaderAuthRoles   = "X-Auth-Roles"
)

// Well-known auth endpoints and defaults.
const (
	AuthLoginPath            = "/.raiwall/auth/login"
	AuthCallbackPath         = "/.raiwall/auth/callback"
	AuthLogoutPath           = "/.raiwall/auth/logout"
	DefaultSessionCookieName = "rw_session"
	DefaultSessionTTL        = 24 * time.Hour
)

// Provider type constants
const (
	ProviderSimple = "simple"
	ProviderOIDC   = "oidc"
)

// UserIdentity represents an authenticated principal's verified identity claims.
type UserIdentity struct {
	Subject   string    `json:"sub"`
	Email     string    `json:"email,omitempty"`
	Name      string    `json:"name,omitempty"`
	Roles     []string  `json:"roles,omitempty"`
	Provider  string    `json:"provider,omitempty"` // "simple", "oidc"
	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`
}

// UserClaims is an alias for UserIdentity.
type UserClaims = UserIdentity

// SimpleUser holds a local user account for SimpleAuth.
type SimpleUser struct {
	Username     string   `json:"username"`
	PasswordHash string   `json:"password_hash"`
	Email        string   `json:"email,omitempty"`
	Name         string   `json:"name,omitempty"`
	Roles        []string `json:"roles,omitempty"`
}

// UserCredential is an alias for SimpleUser.
type UserCredential = SimpleUser

// AuthConfig configures the overall authentication gateway behavior.
type AuthConfig struct {
	Provider     string      `json:"provider,omitempty"` // simple or oidc
	BypassPaths  []string    `json:"bypass_paths,omitempty"`
	SimpleUsers  []SimpleUser `json:"simple_users,omitempty"`
	OIDC         *OIDCConfig `json:"oidc,omitempty"`
	CookieSecret string      `json:"cookie_secret,omitempty"`
	CookieName   string      `json:"cookie_name,omitempty"`
	CookieTTL    time.Duration `json:"cookie_ttl,omitempty"`
}
