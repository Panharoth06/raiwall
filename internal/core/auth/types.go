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

// Well-known auth defaults.
const (
	DefaultSessionCookieName = "rw_session"
	DefaultSessionTTL        = 24 * time.Hour
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

// SimpleUser holds a local user account for SimpleAuth.
type SimpleUser struct {
	Username     string   `json:"username"`
	PasswordHash string   `json:"password_hash"`
	Email        string   `json:"email,omitempty"`
	Name         string   `json:"name,omitempty"`
	Roles        []string `json:"roles,omitempty"`
}
