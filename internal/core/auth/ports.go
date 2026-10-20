package auth

import (
	"net/http"
)

// AuthGatewayPort defines the driving port for pre-application authentication.
type AuthGatewayPort interface {
	Authenticate(r *http.Request) (*SessionClaims, error)
	StripInjectedHeaders(req *http.Request)
	InjectUpstreamHeaders(req *http.Request, claims *SessionClaims)
}

// SessionPort defines the contract for session cookie management.
type SessionPort interface {
	CreateSessionCookie(identity *UserIdentity) (*http.Cookie, error)
	ValidateSessionCookie(cookie *http.Cookie) (*SessionClaims, error)
	ClearSessionCookie() *http.Cookie
}

// IdentityProviderPort defines the contract for credential verification.
type IdentityProviderPort interface {
	Authenticate(username, password string) (*UserIdentity, error)
}
