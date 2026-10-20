package auth

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

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
