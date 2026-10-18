package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// AuthGateway coordinates pre-application authentication, session lifecycle,
// client header stripping, and upstream identity injection.
type AuthGateway struct {
	simpleAuth  *SimpleAuth
	oidcClient  *OIDCClient
	sessionMgr  *SessionManager
	bypassPaths []string
	mu          sync.RWMutex
}

// GatewayConfig holds configuration for the AuthGateway.
type GatewayConfig struct {
	SimpleAuth  *SimpleAuth
	OIDCClient  *OIDCClient
	SessionMgr  *SessionManager
	BypassPaths []string
}

// NewAuthGateway constructs an AuthGateway supporting both:
// 1. NewAuthGateway(GatewayConfig)
// 2. NewAuthGateway(*AuthConfig, *SimpleAuth, *OIDCClient, *SessionManager)
func NewAuthGateway(args ...any) *AuthGateway {
	g := &AuthGateway{
		sessionMgr: NewSessionManager(""),
	}

	if len(args) == 0 {
		return g
	}

	switch v := args[0].(type) {
	case GatewayConfig:
		g.simpleAuth = v.SimpleAuth
		g.oidcClient = v.OIDCClient
		if v.SessionMgr != nil {
			g.sessionMgr = v.SessionMgr
		}
		g.bypassPaths = v.BypassPaths
	case *GatewayConfig:
		if v != nil {
			g.simpleAuth = v.SimpleAuth
			g.oidcClient = v.OIDCClient
			if v.SessionMgr != nil {
				g.sessionMgr = v.SessionMgr
			}
			g.bypassPaths = v.BypassPaths
		}
	case *AuthConfig:
		if v != nil {
			g.bypassPaths = v.BypassPaths
			if v.CookieSecret != "" || v.CookieName != "" || v.CookieTTL > 0 {
				g.sessionMgr = NewSessionManager(v.CookieSecret,
					WithCookieName(v.CookieName),
					WithCookieTTL(v.CookieTTL),
				)
			}
		}
		if len(args) > 1 {
			if sa, ok := args[1].(*SimpleAuth); ok {
				g.simpleAuth = sa
			}
		}
		if len(args) > 2 {
			if oidc, ok := args[2].(*OIDCClient); ok {
				g.oidcClient = oidc
			}
		}
		if len(args) > 3 {
			if sm, ok := args[3].(*SessionManager); ok && sm != nil {
				g.sessionMgr = sm
			}
		}
	}

	return g
}

// IsAuthEndpoint checks if path targets an internal authentication route.
func (g *AuthGateway) IsAuthEndpoint(path string) bool {
	return path == AuthLoginPath || path == AuthCallbackPath || path == AuthLogoutPath
}

// IsBypassed is an alias for IsBypass.
func (g *AuthGateway) IsBypassed(path string) bool {
	return g.IsBypass(path)
}

// IsBypass reports whether the path is exempt from authentication.
func (g *AuthGateway) IsBypass(path string) bool {
	if g.IsAuthEndpoint(path) {
		return true
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	for _, pattern := range g.bypassPaths {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if strings.HasSuffix(pattern, "/*") {
			prefix := strings.TrimSuffix(pattern, "*") // e.g. "/public/"
			if strings.HasPrefix(path, prefix) || path == strings.TrimSuffix(prefix, "/") {
				return true
			}
		} else if strings.HasSuffix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if strings.HasPrefix(path, prefix) {
				return true
			}
		} else if path == pattern {
			return true
		}
	}

	return false
}

// ServeHTTP handles auth endpoint requests directly.
func (g *AuthGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case AuthLoginPath:
		g.HandleLogin(w, r)
	case AuthCallbackPath:
		g.HandleCallback(w, r)
	case AuthLogoutPath:
		g.HandleLogout(w, r)
	default:
		http.NotFound(w, r)
	}
}

// isSafeRedirect validates that a redirect target is a safe local relative URL.
// Prevents Open Redirect and XSS via javascript:/data: pseudo-protocols
// or protocol-relative //evil.com / \evil.com bypasses.
func isSafeRedirect(urlStr string) bool {
	if urlStr == "" {
		return false
	}
	if !strings.HasPrefix(urlStr, "/") || strings.HasPrefix(urlStr, "//") || strings.HasPrefix(urlStr, "/\\") || strings.HasPrefix(urlStr, "\\") {
		return false
	}
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	if u.Scheme != "" || u.Host != "" {
		return false
	}
	for _, b := range []byte(urlStr) {
		if b < 0x20 || b == 0x7f {
			return false
		}
	}
	return true
}

// HandleLogin processes GET (render login UI) and POST (submit local credentials or trigger SSO).
func (g *AuthGateway) HandleLogin(w http.ResponseWriter, r *http.Request) {
	targetRedirect := r.URL.Query().Get("redirect")
	if targetRedirect == "" {
		targetRedirect = r.FormValue("redirect")
	}
	if !isSafeRedirect(targetRedirect) {
		targetRedirect = "/"
	}

	if r.Method == http.MethodGet {
		data := LoginTemplateData{
			TargetURL:      targetRedirect,
			ShowSimpleAuth: g.simpleAuth != nil,
			ShowOIDC:       g.oidcClient != nil,
		}
		if g.oidcClient != nil {
			data.OIDCProviderName = "SSO"
		}
		_ = RenderLoginPage(w, data)
		return
	}

	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		authType := r.FormValue("auth_type")

		if authType == "oidc" && g.oidcClient != nil {
			state := g.oidcClient.GenerateState(targetRedirect)
			authURL := g.oidcClient.AuthCodeURL(state)
			http.Redirect(w, r, authURL, http.StatusFound)
			return
		}

		if g.simpleAuth != nil {
			username := r.FormValue("username")
			password := r.FormValue("password")

			identity, err := g.simpleAuth.Authenticate(username, password)
			if err != nil {
				data := LoginTemplateData{
					TargetURL:      targetRedirect,
					ErrorMessage:   "Invalid username or password",
					ShowSimpleAuth: g.simpleAuth != nil,
					ShowOIDC:       g.oidcClient != nil,
				}
				_ = RenderLoginPage(w, data)
				return
			}

			cookie, err := g.sessionMgr.CreateSessionCookie(identity)
			if err != nil {
				http.Error(w, "Failed to create session", http.StatusInternalServerError)
				return
			}

			http.SetCookie(w, cookie)
			http.Redirect(w, r, targetRedirect, http.StatusFound)
			return
		}

		http.Error(w, "No authentication method available", http.StatusBadRequest)
	}
}

// HandleCallback processes OIDC code exchange and sets session cookie.
func (g *AuthGateway) HandleCallback(w http.ResponseWriter, r *http.Request) {
	if g.oidcClient == nil {
		http.Error(w, "OIDC authentication not configured", http.StatusBadRequest)
		return
	}

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	targetURL, ok := g.oidcClient.VerifyAndConsumeState(state)
	if !ok {
		http.Error(w, "Invalid or expired state token", http.StatusBadRequest)
		return
	}
	if !isSafeRedirect(targetURL) {
		targetURL = "/"
	}

	identity, err := g.oidcClient.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, fmt.Sprintf("Authentication failed: %v", err), http.StatusUnauthorized)
		return
	}

	cookie, err := g.sessionMgr.CreateSessionCookie(identity)
	if err != nil {
		http.Error(w, "Failed to create session cookie", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, cookie)
	http.Redirect(w, r, targetURL, http.StatusFound)
}

// HandleLogout clears session cookie and redirects.
func (g *AuthGateway) HandleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, g.sessionMgr.ClearSessionCookie())
	http.Redirect(w, r, AuthLoginPath, http.StatusFound)
}

// StripAuthHeaders deletes any client-supplied X-Auth-* headers to prevent identity spoofing.
func StripAuthHeaders(headers http.Header) {
	if headers == nil {
		return
	}
	headers.Del(HeaderAuthSubject)
	headers.Del(HeaderAuthEmail)
	headers.Del(HeaderAuthName)
	headers.Del(HeaderAuthRoles)
}

// InjectIdentityHeaders strips untrusted X-Auth-* headers and injects verified claims.
func InjectIdentityHeaders(headers http.Header, identity *UserIdentity) {
	if headers == nil || identity == nil {
		return
	}
	StripAuthHeaders(headers)
	headers.Set(HeaderAuthSubject, identity.Subject)
	if identity.Email != "" {
		headers.Set(HeaderAuthEmail, identity.Email)
	}
	if identity.Name != "" {
		headers.Set(HeaderAuthName, identity.Name)
	}
	if len(identity.Roles) > 0 {
		headers.Set(HeaderAuthRoles, strings.Join(identity.Roles, ","))
	}
}

// AuthenticateRequest verifies session and manages redirection or identity injection.
// Supports:
// 1. AuthenticateRequest(w http.ResponseWriter, r *http.Request) (*UserIdentity, bool)
// 2. AuthenticateRequest(r *http.Request) (*UserIdentity, bool)
func (g *AuthGateway) AuthenticateRequest(args ...any) (*UserIdentity, bool) {
	var w http.ResponseWriter
	var r *http.Request

	if len(args) == 1 {
		r = args[0].(*http.Request)
	} else if len(args) >= 2 {
		w = args[0].(http.ResponseWriter)
		r = args[1].(*http.Request)
	} else {
		return nil, false
	}

	// 1. Strip untrusted client identity headers unconditionally
	StripAuthHeaders(r.Header)

	// 2. Internal auth endpoint routing
	if g.IsAuthEndpoint(r.URL.Path) {
		if w != nil {
			switch r.URL.Path {
			case AuthLoginPath:
				g.HandleLogin(w, r)
			case AuthCallbackPath:
				g.HandleCallback(w, r)
			case AuthLogoutPath:
				g.HandleLogout(w, r)
			}
		}
		return nil, false
	}

	// 3. Validate session cookie if present
	identity, err := g.sessionMgr.ValidateSessionCookie(r)
	if err == nil && identity != nil {
		// Valid session: inject verified identity upstream
		InjectIdentityHeaders(r.Header, identity)
		return identity, true
	}

	// 4. Bypass routes (e.g. /public/*, /healthz)
	if g.IsBypass(r.URL.Path) {
		return nil, true
	}

	// If no ResponseWriter passed, return unauthenticated without writing response
	if w == nil {
		return nil, false
	}

	// 5. Unauthenticated: route API requests to 401 JSON and browsers to login page
	isAPI := strings.Contains(r.Header.Get("Accept"), "application/json") ||
		strings.HasPrefix(r.URL.Path, "/api/") ||
		r.Header.Get("Authorization") != ""

	if isAPI {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("WWW-Authenticate", `Bearer realm="raiwall"`)
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":     "unauthorized",
			"login_url": AuthLoginPath,
		})
		return nil, false
	}

	// Browser request: redirect to login page with return URL
	loginRedirect := fmt.Sprintf("%s?redirect=%s", AuthLoginPath, url.QueryEscape(r.URL.RequestURI()))
	http.Redirect(w, r, loginRedirect, http.StatusFound)
	return nil, false
}

// SessionManager returns the underlying session manager.
func (g *AuthGateway) SessionManager() *SessionManager {
	return g.sessionMgr
}

// SimpleAuth returns the underlying simple auth store.
func (g *AuthGateway) SimpleAuth() *SimpleAuth {
	return g.simpleAuth
}

// OIDCClient returns the underlying OIDC client.
func (g *AuthGateway) OIDCClient() *OIDCClient {
	return g.oidcClient
}
