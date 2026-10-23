package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// AppAuthCookieName is the clearance cookie issued by every site gate
// (unified SSO: one signed token valid across all authorized sites).
const AppAuthCookieName = "sl_jwt_session"

// ChallengeStatusCode is the proprietary zero-trust challenge status code.
const ChallengeStatusCode = 467

// AppAuthLoginPath is the app-level login submission endpoint (HTTP 467 portal form target).
const AppAuthLoginPath = "/.raiwall/auth/app-login"

// AppAuthLogoutPath is the clearance-exit endpoint.
const AppAuthLogoutPath = "/.raiwall/auth/app-logout"

// AppLoginUser is the minimal directory view the gate verifies against.
type AppLoginUser struct {
	Username       string
	PasswordHash   string
	TOTPSecret     string
	TOTPEnrolled   bool
	Enabled        bool
	AuthorizedApps []string // assigned app IDs
}

// AppLoginStore is the directory lookup port backed by the control store.
type AppLoginStore interface {
	// LookupLogin loads the directory user (nil when unknown) by username.
	LookupLogin(ctx context.Context, username string) (*AppLoginUser, error)
}

// LoginEvent is one authentication attempt record for the audit log.
type LoginEvent struct {
	Username string
	AppID    string
	Host     string
	Method   string // "directory"
	Result   string // "success" | "invalid_password" | "account_disabled" | ...
	ClientIP string
	Country  string
	Detail   string
}

// AppAuthGate evaluates and serves the HTTP 467 challenge for protected sites.
type AppAuthGate struct {
	sessions *SessionManager
	store    AppLoginStore
	// audit receives every attempt result; nil-safe.
	audit func(LoginEvent)
}

// NewAppAuthGate builds the gate with a session manager bound to the
// reserved clearance cookie name.
func NewAppAuthGate(secret string, store AppLoginStore, audit func(LoginEvent)) *AppAuthGate {
	return &AppAuthGate{
		sessions: NewSessionManager(secret, WithCookieName(AppAuthCookieName)),
		store:    store,
		audit:    audit,
	}
}

// SessionManager exposes the underlying clearance session manager.
func (g *AppAuthGate) SessionManager() *SessionManager { return g.sessions }

// ClearCookie builds the logout/clearance-removal cookie.
func (g *AppAuthGate) ClearCookie() *http.Cookie { return g.sessions.ClearSessionCookie() }

// Claims strips untrusted inbound identity headers and, when the request
// carries a valid clearance cookie, injects the verified claims upstream.
func (g *AppAuthGate) Claims(r *http.Request) *UserIdentity {
	StripAuthHeaders(r.Header)
	identity, err := g.sessions.ValidateSessionCookie(r)
	if err != nil {
		return nil
	}
	InjectIdentityHeaders(r.Header, identity)
	return identity
}

// DirectoryLookupFunc adapts a plain function into AppLoginStore.
type DirectoryLookupFunc func(ctx context.Context, username string) (*AppLoginUser, error)

// LookupLogin implements AppLoginStore.
func (f DirectoryLookupFunc) LookupLogin(ctx context.Context, username string) (*AppLoginUser, error) {
	return f(ctx, username)
}

// verifyLogin validates directory credentials and app membership.
func (g *AppAuthGate) verifyLogin(ctx context.Context, username, password, totpCode, appID string) (*UserIdentity, error) {
	if g.store == nil {
		return nil, fmt.Errorf("identity directory is not configured")
	}
	user, err := g.store.LookupLogin(ctx, username)
	if err != nil || user == nil {
		return nil, fmt.Errorf("unknown account")
	}
	login := DirectoryLogin{
		PasswordHash: user.PasswordHash,
		TOTPSecret:   user.TOTPSecret,
		TOTPEnrolled: user.TOTPEnrolled,
		Enabled:      user.Enabled,
	}
	if err := login.Authenticate(password, totpCode); err != nil {
		return nil, err
	}
	if len(user.AuthorizedApps) == 0 {
		return nil, fmt.Errorf("account is not assigned to any application")
	}
	if appID != "" && !containsString(user.AuthorizedApps, appID) {
		return nil, fmt.Errorf("account is not authorized for this application")
	}
	return &UserIdentity{
		Subject:  user.Username,
		Provider: "directory",
	}, nil
}

// DefaultAPIPrefixes are the transport-level bypass path families.
var DefaultAPIPrefixes = []string{"/api/", "/.raiwall/api/", "/metrics"}

// IsAPITransport reports whether the request should bypass the interactive
// challenge: Bearer tokens, JSON-negotiating clients, XHR, and API prefixes.
func IsAPITransport(path, accept, authorization, xRequestedWith string) bool {
	if strings.TrimSpace(authorization) != "" {
		return true
	}
	if strings.Contains(accept, "application/json") {
		return true
	}
	if strings.EqualFold(xRequestedWith, "XMLHttpRequest") {
		return true
	}
	for _, prefix := range DefaultAPIPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// PathBypassed reports whether a path matches a configured bypass prefix.
func PathBypassed(path string, bypassPrefixes []string) bool {
	for _, prefix := range bypassPrefixes {
		if prefix != "" && strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func containsString(list []string, val string) bool {
	for _, item := range list {
		if strings.EqualFold(strings.TrimSpace(item), val) {
			return true
		}
	}
	return false
}
