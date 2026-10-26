package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AppAuthCookieName is the clearance cookie issued by every site gate
// (unified SSO: one signed token valid across all authorized sites).
const AppAuthCookieName = "sl_jwt_session"

// ChallengeStatusCode is the proprietary zero-trust challenge status code.
const ChallengeStatusCode = 467

// AppAuthLoginPath is the app-level login submission endpoint (HTTP 467 portal form target).
const AppAuthLoginPath = "/.raiwall/auth/app-login"

// LegacyAuthLoginPath is the retired pre-492 gateway route. Bookmarks are
// redirected to the single HTTP 467 portal.
const LegacyAuthLoginPath = "/.raiwall/auth/login"

// AppAuthLogoutPath is the clearance-exit endpoint.
const AppAuthLogoutPath = "/.raiwall/auth/app-logout"

// AppAuthSSOPath starts the external identity-provider redirect flow.
const AppAuthSSOPath = "/.raiwall/auth/app-sso"

// AppAuthCallbackPath completes the external identity-provider redirect flow.
const AppAuthCallbackPath = "/.raiwall/auth/app-callback"

// ssoStateTTL bounds the lifetime of a pending provider redirect.
const ssoStateTTL = 10 * time.Minute

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
	Method   string // "directory" | "simple" | provider name
	Result   string // "success" | "invalid_password" | "account_disabled" | ...
	ClientIP string
	Country  string
	Detail   string
}

// AppAuthGateOption customizes a gate at construction time.
type AppAuthGateOption func(*AppAuthGate)

// WithSimpleAuth adds config-declared local users to the credential chain.
func WithSimpleAuth(sa *SimpleAuth) AppAuthGateOption {
	return func(g *AppAuthGate) {
		if sa != nil {
			g.simple = sa
		}
	}
}

// WithIdentityProviders adds external directory connectors (LDAP, OIDC, GitHub).
func WithIdentityProviders(providers ...IdentityProvider) AppAuthGateOption {
	return func(g *AppAuthGate) {
		g.providers = append(g.providers, providers...)
	}
}

// WithBypassPaths exempts path prefixes from the interactive challenge.
func WithBypassPaths(paths ...string) AppAuthGateOption {
	return func(g *AppAuthGate) {
		g.bypassPaths = append(g.bypassPaths, paths...)
	}
}

// WithSessionTTL overrides the clearance cookie lifetime.
func WithSessionTTL(ttl time.Duration) AppAuthGateOption {
	return func(g *AppAuthGate) {
		g.sessionTTL = ttl
	}
}

// WithSessionSecure overrides the Secure attribute of the clearance cookie.
func WithSessionSecure(secure bool) AppAuthGateOption {
	return func(g *AppAuthGate) {
		g.sessionSecure = &secure
	}
}

// AppAuthGate evaluates and serves the HTTP 467 challenge for protected sites.
type AppAuthGate struct {
	sessions *SessionManager
	store    AppLoginStore
	// simple holds config-declared users; nil when unused.
	simple *SimpleAuth
	// providers holds external directory connectors.
	providers []IdentityProvider
	// bypassPaths exempts operator-configured prefixes.
	bypassPaths []string
	// audit receives every attempt result; nil-safe.
	audit func(LoginEvent)

	sessionTTL    time.Duration
	sessionSecure *bool

	// states holds pending external IdP redirects keyed by CSRF state.
	states sync.Map
}

// NewAppAuthGate builds the gate with a session manager bound to the
// reserved clearance cookie name.
func NewAppAuthGate(secret string, store AppLoginStore, audit func(LoginEvent), opts ...AppAuthGateOption) *AppAuthGate {
	g := &AppAuthGate{
		sessions: NewSessionManager(secret, WithCookieName(AppAuthCookieName)),
		store:    store,
		audit:    audit,
	}
	for _, opt := range opts {
		opt(g)
	}
	if g.sessionTTL > 0 {
		g.sessions.cookieTTL = g.sessionTTL
	}
	if g.sessionSecure != nil {
		g.sessions.secure = *g.sessionSecure
	}
	return g
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

// HasCredentials reports whether any password backend is configured.
func (g *AppAuthGate) HasCredentials() bool {
	if g.store != nil || g.simple != nil {
		return true
	}
	for _, p := range g.providers {
		if _, codeOnly := AsCodeIdentityProvider(p); !codeOnly {
			return true
		}
	}
	return false
}

// SSOButtons lists the code-flow providers the portal can redirect to.
func (g *AppAuthGate) SSOButtons() []SSOButton {
	buttons := make([]SSOButton, 0, len(g.providers))
	for _, p := range g.providers {
		if _, ok := AsCodeIdentityProvider(p); ok {
			buttons = append(buttons, SSOButton{
				Name:  p.Name(),
				Label: providerLabel(p),
			})
		}
	}
	return buttons
}

// DirectoryLookupFunc adapts a plain function into AppLoginStore.
type DirectoryLookupFunc func(ctx context.Context, username string) (*AppLoginUser, error)

// LookupLogin implements AppLoginStore.
func (f DirectoryLookupFunc) LookupLogin(ctx context.Context, username string) (*AppLoginUser, error) {
	return f(ctx, username)
}

// verifyLogin validates credentials and app membership across the configured
// backends: directory first, then simple users, then external providers.
func (g *AppAuthGate) verifyLogin(ctx context.Context, username, password, totpCode, appID string) (*UserIdentity, string, error) {
	lookupMissed := false
	if g.store != nil {
		user, err := g.store.LookupLogin(ctx, username)
		if err != nil {
			return nil, "directory", fmt.Errorf("identity directory unavailable: %w", err)
		}
		if user != nil {
			return g.verifyDirectoryLogin(user, password, totpCode, appID)
		}
		lookupMissed = true
	}

	if g.simple != nil {
		if ident, err := g.simple.Authenticate(username, password); err == nil {
			return ident, "simple", nil
		}
	}

	var lastErr error
	for _, provider := range g.providers {
		ident, err := provider.Authenticate(ctx, username, password)
		if err == nil {
			return ident, provider.Name(), nil
		}
		if err != errCodeFlowUnsupported {
			lastErr = err
		}
	}
	if lastErr != nil {
		return nil, "provider", lastErr
	}
	if lookupMissed {
		return nil, "directory", fmt.Errorf("unknown account")
	}

	return nil, "credential", fmt.Errorf("invalid username or password")
}

// verifyDirectoryLogin enforces password, TOTP, enabled state, and app
// membership for directory-backed accounts.
func (g *AppAuthGate) verifyDirectoryLogin(user *AppLoginUser, password, totpCode, appID string) (*UserIdentity, string, error) {
	login := DirectoryLogin{
		PasswordHash: user.PasswordHash,
		TOTPSecret:   user.TOTPSecret,
		TOTPEnrolled: user.TOTPEnrolled,
		Enabled:      user.Enabled,
	}
	if err := login.Authenticate(password, totpCode); err != nil {
		return nil, "directory", err
	}
	// appID is empty in portal-wide mode, where app bindings do
	// not apply. Per-site mode still enforces membership.
	if appID != "" {
		if len(user.AuthorizedApps) == 0 {
			return nil, "directory", fmt.Errorf("account is not assigned to any application")
		}
		if !containsString(user.AuthorizedApps, appID) {
			return nil, "directory", fmt.Errorf("account is not authorized for this application")
		}
	}
	return &UserIdentity{
		Subject:  user.Username,
		Provider: "directory",
	}, "directory", nil
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

// IsAppAuthEndpoint reports whether the path is served by the portal itself.
func IsAppAuthEndpoint(path string) bool {
	switch path {
	case AppAuthLoginPath, AppAuthLogoutPath, AppAuthSSOPath, AppAuthCallbackPath, LegacyAuthLoginPath:
		return true
	default:
		return false
	}
}

// PathBypassed reports whether a path matches a configured bypass prefix.
func PathBypassed(path string, bypassPrefixes []string) bool {
	for _, pattern := range bypassPrefixes {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if strings.HasSuffix(pattern, "/*") {
			base := strings.TrimSuffix(pattern, "/*")
			if base == "" || path == base || strings.HasPrefix(path, base+"/") {
				return true
			}
			continue
		}
		if strings.HasSuffix(pattern, "*") {
			base := strings.TrimSuffix(pattern, "*")
			if base != "" && strings.HasPrefix(path, base) {
				return true
			}
			continue
		}
		if path == pattern || strings.HasPrefix(path, pattern+"/") {
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

// pendingSSO is one in-flight external IdP redirect.
type pendingSSO struct {
	Provider  string
	Target    string
	AppID     string
	CreatedAt time.Time
}

// newSSOState mints and stores a one-time CSRF state token.
func (g *AppAuthGate) newSSOState(p pendingSSO) string {
	g.pruneSSOStates()
	buf := make([]byte, 24)
	_, _ = rand.Read(buf)
	state := base64.RawURLEncoding.EncodeToString(buf)
	p.CreatedAt = time.Now()
	g.states.Store(state, p)
	return state
}

// consumeSSOState validates and removes a state token.
func (g *AppAuthGate) consumeSSOState(state string) (pendingSSO, bool) {
	if state == "" {
		return pendingSSO{}, false
	}
	v, ok := g.states.LoadAndDelete(state)
	if !ok {
		return pendingSSO{}, false
	}
	p, ok := v.(pendingSSO)
	if !ok || time.Since(p.CreatedAt) > ssoStateTTL {
		return pendingSSO{}, false
	}
	return p, true
}

// pruneSSOStates drops expired pending redirects.
func (g *AppAuthGate) pruneSSOStates() {
	now := time.Now()
	g.states.Range(func(key, value any) bool {
		if p, ok := value.(pendingSSO); ok && now.Sub(p.CreatedAt) > ssoStateTTL {
			g.states.Delete(key)
		}
		return true
	})
}

// AllowsPath reports whether the path matches a gate-configured bypass.
func (g *AppAuthGate) AllowsPath(path string) bool {
	return PathBypassed(path, g.bypassPaths)
}

// providerLabel turns a provider identifier into operator-facing copy.
func providerLabel(p IdentityProvider) string {
	switch p.Type() {
	case ProviderTypeOIDC:
		return "SSO"
	case ProviderTypeGitHub:
		return "GitHub"
	case ProviderTypeLDAP:
		return "LDAP"
	default:
		if p.Name() != "" {
			return p.Name()
		}
		return "SSO"
	}
}
