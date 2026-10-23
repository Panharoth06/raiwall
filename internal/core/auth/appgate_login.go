package auth

import (
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
)

// HandleChallenge renders the branded HTTP 467 login portal (GET + error POSTs).
func (g *AppAuthGate) HandleChallenge(w http.ResponseWriter, r *http.Request, opts ChallengeOptions, errMessage string) {
	data := challengeTemplateData{
		AppID:      html.EscapeString(opts.AppID),
		Host:       html.EscapeString(opts.Host),
		Target:     html.EscapeString(opts.Target),
		ClientIP:   html.EscapeString(opts.ClientIP),
		ErrorMsg:   html.EscapeString(errMessage),
		LoginPath:  AppAuthLoginPath,
		TOTPNeeded: errMessage != "" && strings.Contains(errMessage, "totp"),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("WWW-Authenticate", `Bearer realm="raiwall"`)
	w.WriteHeader(ChallengeStatusCode)
	_, _ = fmt.Fprint(w, renderChallengeTemplate(data))
}

// HandleLogin processes GET (portal render) and POST (directory credential
// submission) for the app-level gate and issues the clearance cookie.
func (g *AppAuthGate) HandleLogin(w http.ResponseWriter, r *http.Request, appID string, clientIP, country string) {
	target := requestTargetRedirect(r)

	emitResult := func(result, detail string) {
		if g.audit == nil {
			return
		}
		user := strings.TrimSpace(r.FormValue("username"))
		g.audit(LoginEvent{
			Username: user,
			AppID:    appID,
			Host:     r.Host,
			Method:   "directory",
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

	identity, err := g.verifyLogin(r.Context(), username, password, totpCode, appID)
	if err != nil {
		result := classifyLoginError(err)
		emitResult(result, err.Error())
		g.HandleChallenge(w, r, ChallengeOptions{
			AppID:    appID,
			Host:     r.Host,
			Target:   target,
			ClientIP: clientIP,
		}, friendlyLoginError(err))
		return
	}

	emitResult(LoginResultSuccess, "clearance issued")
	cookie, err := g.sessions.CreateSessionCookie(identity)
	if err != nil {
		http.Error(w, "failed to create clearance cookie", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, target, http.StatusFound)
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
	default:
		return LoginResultInvalidPassword
	}
}

func defaultLoginResult(err error) string { return classifyLoginError(err) }

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
		return "Identity directory is not configured."
	default:
		return "Invalid username or password."
	}
}

// ServeLogout clears the clearance cookie and returns to the portal.
func (g *AppAuthGate) ServeLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, g.sessions.ClearSessionCookie())
	http.Redirect(w, r, AppAuthLoginPath+"?redirect="+url.QueryEscape("/"), http.StatusFound)
}
