package auth

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
)

// ChallengeOptions carries per-site context into the HTTP 467 portal.
type ChallengeOptions struct {
	AppID    string
	Host     string
	Target   string // safe local redirect after clearance
	ClientIP string
	Country  string
}

// LoginAttemptOutcome classifies an audited attempt result.
const (
	LoginResultSuccess          = "success"
	LoginResultInvalidPassword  = "invalid_password"
	LoginResultTOTPFailed       = "totp_failed"
	LoginResultAccountDisabled  = "account_disabled"
	LoginResultUnknownUser      = "unknown_user"
	LoginResultAppUnauthorized  = "app_unauthorized"
	LoginResultNoAppsAssigned   = "no_apps_assigned"
	LoginResultDirectoryMissing = "directory_unconfigured"
	LoginResultProviderError    = "provider_error"
)

// HandleChallenge renders the branded HTTP 467 login portal (GET + error POSTs).
func (g *AppAuthGate) HandleChallenge(w http.ResponseWriter, r *http.Request, opts ChallengeOptions, errMessage string) {
	data := challengeTemplateData{
		AppID:        html.EscapeString(opts.AppID),
		Host:         html.EscapeString(opts.Host),
		Target:       html.EscapeString(opts.Target),
		ClientIP:     html.EscapeString(opts.ClientIP),
		ErrorMsg:     html.EscapeString(errMessage),
		LoginPath:    AppAuthLoginPath,
		SSOPath:      AppAuthSSOPath,
		SSOProviders: g.ssoTemplateButtons(),
		HasPassword:  g.HasCredentials(),
		TOTPNeeded:   errMessage != "" && strings.Contains(errMessage, "totp"),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("WWW-Authenticate", `Bearer realm="raiwall"`)
	w.WriteHeader(ChallengeStatusCode)
	_, _ = fmt.Fprint(w, renderChallengeTemplate(data))
}

// ssoTemplateButtons escapes provider labels for safe HTML rendering.
func (g *AppAuthGate) ssoTemplateButtons() []ssoButton {
	buttons := g.SSOButtons()
	out := make([]ssoButton, 0, len(buttons))
	for _, b := range buttons {
		out = append(out, ssoButton{
			Name:  html.EscapeString(b.Name),
			Label: html.EscapeString(b.Label),
		})
	}
	return out
}

// HandleLogin processes GET (portal render) and POST (directory credential
// submission) for the app-level gate and issues the clearance cookie.
func (g *AppAuthGate) HandleLogin(w http.ResponseWriter, r *http.Request, appID string, clientIP, country string) {
	target := requestTargetRedirect(r)

	emitResult := func(method, result, detail string) {
		if g.audit == nil {
			return
		}
		user := strings.TrimSpace(r.FormValue("username"))
		g.audit(LoginEvent{
			Username: user,
			AppID:    appID,
			Host:     r.Host,
			Method:   method,
			Result:   result,
			ClientIP: clientIP,
			Country:  country,
			Detail:   detail,
		})
	}

	if r.Method == http.MethodGet {
		g.HandleChallenge(w, r, ChallengeOptions{
			AppID:    appID,
			Host:     r.Host,
			Target:   target,
			ClientIP: clientIP,
		}, "")
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	totpCode := strings.TrimSpace(r.FormValue("totp"))

	identity, method, err := g.verifyLogin(r.Context(), username, password, totpCode, appID)
	if err != nil {
		result := classifyLoginError(err)
		emitResult(method, result, err.Error())
		g.HandleChallenge(w, r, ChallengeOptions{
			AppID:    appID,
			Host:     r.Host,
			Target:   target,
			ClientIP: clientIP,
		}, friendlyLoginError(err))
		return
	}

	emitResult(method, LoginResultSuccess, "clearance issued")
	g.issueClearance(w, r, identity, target)
}

// HandleSSOStart redirects the browser to a configured code-flow provider.
func (g *AppAuthGate) HandleSSOStart(w http.ResponseWriter, r *http.Request, appID string) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("provider"))
	target := requestTargetRedirect(r)

	for _, provider := range g.providers {
		if provider.Name() != name {
			continue
		}
		codeProvider, ok := AsCodeIdentityProvider(provider)
		if !ok {
			break
		}
		state := g.newSSOState(pendingSSO{
			Provider: name,
			Target:   target,
			AppID:    appID,
		})
		authURL := codeProvider.AuthCodeURL(state)
		if authURL == "" {
			break
		}
		http.Redirect(w, r, authURL, http.StatusFound)
		return
	}
	http.Error(w, "identity provider unavailable", http.StatusBadRequest)
}

// HandleSSOCallback completes the provider redirect and issues clearance.
func (g *AppAuthGate) HandleSSOCallback(w http.ResponseWriter, r *http.Request) {
	pending, ok := g.consumeSSOState(r.URL.Query().Get("state"))
	if !ok {
		http.Error(w, "invalid or expired sign-in state", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	var provider IdentityProvider
	for _, candidate := range g.providers {
		if candidate.Name() == pending.Provider {
			provider = candidate
			break
		}
	}
	codeProvider, ok := AsCodeIdentityProvider(provider)
	if !ok {
		http.Error(w, "identity provider unavailable", http.StatusBadRequest)
		return
	}

	identity, err := codeProvider.ExchangeCode(r.Context(), code)
	if err != nil {
		if g.audit != nil {
			g.audit(LoginEvent{
				AppID:  pending.AppID,
				Host:   r.Host,
				Method: pending.Provider,
				Result: LoginResultProviderError,
				Detail: err.Error(),
			})
		}
		g.HandleChallenge(w, r, ChallengeOptions{
			AppID:  pending.AppID,
			Host:   r.Host,
			Target: pending.Target,
		}, "Identity provider sign-in failed. Try again.")
		return
	}
	if g.audit != nil {
		g.audit(LoginEvent{
			Username: identity.Subject,
			AppID:    pending.AppID,
			Host:     r.Host,
			Method:   pending.Provider,
			Result:   LoginResultSuccess,
			Detail:   "clearance issued",
		})
	}
	g.issueClearance(w, r, identity, pending.Target)
}

// issueClearance signs and sets the clearance cookie, then redirects back.
func (g *AppAuthGate) issueClearance(w http.ResponseWriter, r *http.Request, identity *UserIdentity, target string) {
	cookie, err := g.sessions.CreateSessionCookie(identity)
	if err != nil {
		http.Error(w, "failed to create clearance cookie", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, target, http.StatusFound)
}

// WriteUnauthorizedAPI emits the JSON contract for API transports that must
// not receive an interactive HTML challenge (portal-wide mode).
func WriteUnauthorizedAPI(w http.ResponseWriter, loginURL string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="raiwall"`)
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":     "unauthorized",
		"login_url": loginURL,
	})
}

// requestTargetRedirect resolves a safe local redirect destination.
func requestTargetRedirect(r *http.Request) string {
	target := r.FormValue("redirect")
	if target == "" {
		target = r.URL.Query().Get("redirect")
	}
	if !isSafeRedirect(target) {
		target = "/"
	}
	return target
}

// classifyLoginError maps verification failures onto audit result codes.
func classifyLoginError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "identity directory unavailable"):
		return LoginResultDirectoryMissing
	case strings.Contains(msg, "account is disabled"):
		return LoginResultAccountDisabled
	case strings.Contains(msg, "unknown account"):
		return LoginResultUnknownUser
	case strings.Contains(msg, "not authorized for this application"):
		return LoginResultAppUnauthorized
	case strings.Contains(msg, "not assigned to any application"):
		return LoginResultNoAppsAssigned
	case strings.Contains(msg, "totp"):
		return LoginResultTOTPFailed
	case strings.Contains(msg, "not configured"):
		return LoginResultDirectoryMissing
	case strings.Contains(msg, "invalid username or password"):
		return LoginResultInvalidPassword
	default:
		return LoginResultInvalidPassword
	}
}

// friendlyLoginError converts internal diagnostics into safe portal copy.
func friendlyLoginError(err error) string {
	switch classifyLoginError(err) {
	case LoginResultAccountDisabled:
		return "This account is disabled. Contact your administrator."
	case LoginResultAppUnauthorized:
		return "This account is not authorized for this application."
	case LoginResultNoAppsAssigned:
		return "This account is not assigned to any application."
	case LoginResultTOTPFailed:
		return "Invalid verification code."
	case LoginResultDirectoryMissing:
		return "Identity directory is unavailable. Try again or contact your administrator."
	default:
		return "Invalid username or password."
	}
}

// ServeLogout clears the clearance cookie and returns to the portal.
func (g *AppAuthGate) ServeLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, g.sessions.ClearSessionCookie())
	http.Redirect(w, r, AppAuthLoginPath+"?redirect="+url.QueryEscape("/"), http.StatusFound)
}
