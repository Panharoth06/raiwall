package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

// fakeGateStore is an in-memory directory backing the gate.
type fakeGateStore struct {
	users map[string]*AppLoginUser
}

func (f *fakeGateStore) LookupLogin(_ context.Context, username string) (*AppLoginUser, error) {
	if u, ok := f.users[username]; ok {
		return u, nil
	}
	return nil, nil
}

func newTestGate(t *testing.T) (*AppAuthGate, *fakeGateStore, *[]LoginEvent) {
	t.Helper()
	hash, err := HashPassword("SuperSecret123!")
	require.NoError(t, err)
	totpSecret, _, err := GenerateTOTPSecret(TOTPIssuer, "ops@corp.example")
	require.NoError(t, err)

	store := &fakeGateStore{users: map[string]*AppLoginUser{
		"walter": {
			Username:       "walter",
			PasswordHash:   hash,
			Enabled:        true,
			AuthorizedApps: []string{"app-frontend"},
		},
		"jesse": {
			Username:       "jesse",
			PasswordHash:   hash,
			Enabled:        true,
			AuthorizedApps: []string{"app-frontend", "app-api"},
		},
		"locked": {
			Username:       "locked",
			PasswordHash:   hash,
			Enabled:        false,
			AuthorizedApps: []string{"app-frontend"},
		},
		"enrolled": {
			Username:       "enrolled",
			PasswordHash:   hash,
			TOTPSecret:     totpSecret,
			TOTPEnrolled:   true,
			Enabled:        true,
			AuthorizedApps: []string{"app-frontend"},
		},
		"unassigned": {
			Username:       "unassigned",
			PasswordHash:   hash,
			Enabled:        true,
			AuthorizedApps: nil,
		},
	}}

	var events []LoginEvent
	gate := NewAppAuthGate("0123456789abcdef0123456789abcdef", store, func(e LoginEvent) {
		events = append(events, e)
	})
	return gate, store, &events
}

// TestAppAuthGate_ChallengeRenders467 proves unauthenticated browsers get the
// branded portal with the proprietary status code.
func TestAppAuthGate_ChallengeRenders467(t *testing.T) {
	gate, _, _ := newTestGate(t)

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/dashboard?page=2", nil)
	rec := httptest.NewRecorder()
	gate.HandleChallenge(rec, req, ChallengeOptions{
		AppID:    "app-frontend",
		Host:     "app.example.com",
		Target:   "/dashboard?page=2",
		ClientIP: "203.0.113.7",
	}, "")

	require.Equal(t, 467, rec.Code)
	require.Contains(t, rec.Header().Get("Content-Type"), "text/html")
	body := rec.Body.String()
	require.Contains(t, body, "HTTP 467")
	require.Contains(t, body, "app.example.com")
	require.Contains(t, body, AppAuthLoginPath)
	require.Contains(t, body, "/dashboard?page=2")
	require.NotContains(t, body, "invalid-password-banner")
}

// TestAppAuthGate_LoginSuccess proves a correct directory login issues the
// sl_jwt_session clearance cookie and redirects back to the target.
func TestAppAuthGate_LoginSuccess(t *testing.T) {
	gate, _, events := newTestGate(t)

	form := url.Values{"username": {"walter"}, "password": {"SuperSecret123!"}, "redirect": {"/dashboard"}}
	req := httptest.NewRequest(http.MethodPost, "http://app.example.com"+AppAuthLoginPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	gate.HandleLogin(rec, req, "app-frontend", "203.0.113.7", "US")

	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	require.Equal(t, "/dashboard", rec.Header().Get("Location"))

	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	require.Equal(t, AppAuthCookieName, cookies[0].Name)
	require.NotEmpty(t, cookies[0].Value)
	require.True(t, cookies[0].HttpOnly, "clearance cookie must be HttpOnly")

	// The issued cookie must validate as a cleared session on subsequent requests.
	req2 := httptest.NewRequest(http.MethodGet, "http://app.example.com/dashboard", nil)
	req2.AddCookie(cookies[0])
	require.NotNil(t, gate.Claims(req2), "issued clearance cookie must validate")

	require.Len(t, *events, 1)
	require.Equal(t, LoginResultSuccess, (*events)[0].Result)
	require.Equal(t, "walter", (*events)[0].Username)
	require.Equal(t, "app-frontend", (*events)[0].AppID)
	require.Equal(t, "US", (*events)[0].Country)
}

// TestAppAuthGate_LoginFailures drives wrong password, disabled account,
// unknown user, and app-membership denials through the portal.
func TestAppAuthGate_LoginFailures(t *testing.T) {
	tests := []struct {
		name       string
		username   string
		password   string
		appID      string
		wantResult string
		wantCopy   string
	}{
		{"wrong password", "walter", "nope", "app-frontend", LoginResultInvalidPassword, "Invalid username or password"},
		{"disabled account", "locked", "SuperSecret123!", "app-frontend", LoginResultAccountDisabled, "account is disabled"},
		{"unknown user", "ghost", "whatever", "app-frontend", LoginResultUnknownUser, "Invalid username or password"},
		{"wrong app", "jesse", "SuperSecret123!", "app-not-mine", LoginResultAppUnauthorized, "not authorized for this application"},
		{"no app assigned", "unassigned", "SuperSecret123!", "app-frontend", LoginResultNoAppsAssigned, "not assigned to any application"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gate, _, events := newTestGate(t)

			form := url.Values{"username": {tc.username}, "password": {tc.password}, "redirect": {"/"}}
			req := httptest.NewRequest(http.MethodPost, "http://app.example.com"+AppAuthLoginPath, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()

			gate.HandleLogin(rec, req, tc.appID, "203.0.113.7", "US")

			require.Equal(t, 467, rec.Code, "failed logins re-render the challenge")
			require.Contains(t, rec.Body.String(), tc.wantCopy)
			require.Len(t, *events, 1)
			require.Equal(t, tc.wantResult, (*events)[0].Result)
		})
	}
}

// TestAppAuthGate_TOTP proves enrolled accounts fail closed without a code
// and pass with a freshly generated one.
func TestAppAuthGate_TOTP(t *testing.T) {
	gate, _, events := newTestGate(t)

	post := func(code string) *httptest.ResponseRecorder {
		form := url.Values{"username": {"enrolled"}, "password": {"SuperSecret123!"}, "totp": {code}, "redirect": {"/"}}
		req := httptest.NewRequest(http.MethodPost, "http://app.example.com"+AppAuthLoginPath, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		gate.HandleLogin(rec, req, "app-frontend", "203.0.113.7", "US")
		return rec
	}

	// Missing code fails closed with the TOTP hint surfaced.
	rec := post("")
	require.Equal(t, 467, rec.Code)
	require.Contains(t, rec.Body.String(), "verification code")
	require.Equal(t, LoginResultTOTPFailed, (*events)[0].Result)

	// Wrong code fails closed.
	rec = post("000000")
	require.Equal(t, 467, rec.Code)
	require.Len(t, *events, 2)

	// Fresh valid code clears the session.
	gate2, store, _ := newTestGate(t)
	code, err := totp.GenerateCode(store.users["enrolled"].TOTPSecret, time.Now())
	require.NoError(t, err)
	form := url.Values{"username": {"enrolled"}, "password": {"SuperSecret123!"}, "totp": {code}, "redirect": {"/"}}
	req := httptest.NewRequest(http.MethodPost, "http://app.example.com"+AppAuthLoginPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec2 := httptest.NewRecorder()
	gate2.HandleLogin(rec2, req, "app-frontend", "203.0.113.7", "US")
	require.Equal(t, http.StatusFound, rec2.Code, rec2.Body.String())
}

// TestAppAuthGate_OpenRedirectGuard proves unsafe redirect targets collapse
// to "/" after login.
func TestAppAuthGate_OpenRedirectGuard(t *testing.T) {
	gate, _, _ := newTestGate(t)

	form := url.Values{"username": {"walter"}, "password": {"SuperSecret123!"}, "redirect": {"//evil.example.com"}}
	req := httptest.NewRequest(http.MethodPost, "http://app.example.com"+AppAuthLoginPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	gate.HandleLogin(rec, req, "app-frontend", "203.0.113.7", "US")
	require.Equal(t, http.StatusFound, rec.Code)
	require.Equal(t, "/", rec.Header().Get("Location"))
}

// TestIsAPITransport proves the bypass covers Bearer, JSON negotiation, XHR,
// and API path prefixes — but not plain browser navigation.
func TestIsAPITransport(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		accept  string
		authz   string
		xrw     string
		apiPath bool
	}{
		{"bearer token", "/data", "text/html", "Bearer xyz", "", true},
		{"json accept", "/data", "application/json", "", "", true},
		{"xhr", "/data", "text/html", "", "XMLHttpRequest", true},
		{"api prefix", "/api/v1/things", "text/html", "", "", true},
		{"raiwall internal", "/.raiwall/api/v1/sites", "text/html", "", "", true},
		{"metrics", "/metrics", "text/html", "", "", true},
		{"browser navigation", "/dashboard", "text/html", "", "", false},
		{"browser assets", "/assets/app.js", "text/html", "", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.apiPath, IsAPITransport(tc.path, tc.accept, tc.authz, tc.xrw))
		})
	}
}

// TestPathBypassed covers configured prefix bypasses.
func TestPathBypassed(t *testing.T) {
	require.True(t, PathBypassed("/healthz/live", []string{"/healthz"}))
	require.True(t, PathBypassed("/public/logo.png", []string{"/assets", "/public"}))
	require.False(t, PathBypassed("/admin", []string{"/public"}))
	require.False(t, PathBypassed("/anything", nil))
	require.False(t, PathBypassed("/anything", []string{""}))
}

// TestAppAuthGate_LogoutClears proves the endpoint removes the clearance cookie.
func TestAppAuthGate_LogoutClears(t *testing.T) {
	gate, _, _ := newTestGate(t)

	cookie, err := gate.SessionManager().CreateSessionCookie(&UserIdentity{Subject: "walter"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com"+AppAuthLogoutPath, nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	gate.ServeLogout(rec, req)

	require.Equal(t, http.StatusFound, rec.Code)
	require.True(t, strings.HasPrefix(rec.Header().Get("Location"), AppAuthLoginPath))

	var clearCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == AppAuthCookieName {
			clearCookie = c
		}
	}
	require.NotNil(t, clearCookie, "logout must clear sl_jwt_session")
	require.True(t, clearCookie.MaxAge < 0 || clearCookie.Expires.Before(time.Now()))

	// The clear cookie no longer validates.
	req2 := httptest.NewRequest(http.MethodGet, "http://app.example.com/dashboard", nil)
	req2.AddCookie(clearCookie)
	require.Nil(t, gate.Claims(req2))
}

// TestAppAuthGate_SecretRotationInvalidates proves sessions stop validating
// when the gate is rebuilt with a rotated secret.
func TestAppAuthGate_SecretRotationInvalidates(t *testing.T) {
	t.Helper()
	hash, err := HashPassword("SuperSecret123!")
	require.NoError(t, err)
	store := &fakeGateStore{users: map[string]*AppLoginUser{
		"walter": {Username: "walter", PasswordHash: hash, Enabled: true,
			AuthorizedApps: []string{"app"}},
	}}

	oldGate := NewAppAuthGate("old-secret-0123456789abcdef012345", store, nil)
	cookie, err := oldGate.SessionManager().CreateSessionCookie(&UserIdentity{Subject: "walter"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	req.AddCookie(cookie)
	require.NotNil(t, oldGate.Claims(req))

	newGate := NewAppAuthGate("new-secret-fedcba9876543210fedcba", store, nil)
	req2 := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	req2.AddCookie(cookie)
	require.Nil(t, newGate.Claims(req2), "rotated secret must invalidate prior clearances")
}

// TestChallengeTemplateForm ensures the portal form round-trips through JSON
// embedding to keep template data serializable.
func TestChallengeTemplateForm(t *testing.T) {
	raw, err := json.Marshal(challengeTemplateData{AppID: "a", Host: "h", Target: "/", LoginPath: AppAuthLoginPath})
	require.NoError(t, err)
	require.Contains(t, string(raw), AppAuthLoginPath)
}

// TestAppAuthGate_SimpleUserLogin proves Caddyfile-style local users share the
// same portal and clearance cookie as directory users.
func TestAppAuthGate_SimpleUserLogin(t *testing.T) {
	simple := NewSimpleAuth(SimpleUser{
		Username:     "legacy",
		PasswordHash: "legacy-pass",
		Email:        "legacy@corp.example",
		Roles:        []string{"ops"},
	})
	gate := NewAppAuthGate("0123456789abcdef0123456789abcdef",
		nil, nil, WithSimpleAuth(simple))

	form := url.Values{"username": {"legacy"}, "password": {"legacy-pass"}, "redirect": {"/portal"}}
	req := httptest.NewRequest(http.MethodPost, "http://app.example.com"+AppAuthLoginPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	gate.HandleLogin(rec, req, "", "203.0.113.7", "US")

	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	require.Equal(t, "/portal", rec.Header().Get("Location"))
	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	require.Equal(t, AppAuthCookieName, cookies[0].Name)

	cleared := httptest.NewRequest(http.MethodGet, "http://app.example.com/portal", nil)
	cleared.AddCookie(cookies[0])
	identity := gate.Claims(cleared)
	require.NotNil(t, identity)
	require.Equal(t, "legacy", identity.Subject)
	require.Equal(t, "legacy@corp.example", cleared.Header.Get(HeaderAuthEmail))
}

// TestAppAuthGate_GlobalModeAllowsDirectoryUserWithoutAppBinding proves the
// portal-wide mode skips per-app membership checks.
func TestAppAuthGate_GlobalModeAllowsDirectoryUserWithoutAppBinding(t *testing.T) {
	hash, err := HashPassword("GlobalPass123!")
	require.NoError(t, err)
	store := &fakeGateStore{users: map[string]*AppLoginUser{
		"global": {Username: "global", PasswordHash: hash, Enabled: true},
	}}
	gate := NewAppAuthGate("0123456789abcdef0123456789abcdef", store, nil)

	form := url.Values{"username": {"global"}, "password": {"GlobalPass123!"}, "redirect": {"/"}}
	req := httptest.NewRequest(http.MethodPost, "http://portal.example.com"+AppAuthLoginPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	gate.HandleLogin(rec, req, "", "", "")

	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
}

// TestPathBypassed_SiblingPrefixSecurity prevents prefix-adjacent bypasses.
func TestPathBypassed_SiblingPrefixSecurity(t *testing.T) {
	bypass := []string{"/public/*", "/healthz"}
	allowed := []string{"/public", "/public/", "/public/resource", "/healthz"}
	for _, path := range allowed {
		require.True(t, PathBypassed(path, bypass), "expected %q to bypass", path)
	}
	denied := []string{"/public-admin", "/publicity", "/public_secrets", "/healthz-extended"}
	for _, path := range denied {
		require.False(t, PathBypassed(path, bypass), "SECURITY: %q must not bypass", path)
	}
}

// TestAppAuthGate_OpenRedirectProtection keeps external redirect targets out.
func TestAppAuthGate_OpenRedirectProtection(t *testing.T) {
	simple := NewSimpleAuth(SimpleUser{Username: "alice", PasswordHash: "secretpass"})
	gate := NewAppAuthGate("0123456789abcdef0123456789abcdef",
		nil, nil, WithSimpleAuth(simple))

	targets := []string{
		"javascript:alert(1)",
		"//evil.com/phish",
		"/\\evil.com/phish",
		"\\evil.com",
		"http://evil.com",
		"https://evil.com",
		"data:text/html,<script>alert(1)</script>",
	}
	for _, target := range targets {
		form := url.Values{"username": {"alice"}, "password": {"secretpass"}, "redirect": {target}}
		req := httptest.NewRequest(http.MethodPost, "http://app.example.com"+AppAuthLoginPath, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		gate.HandleLogin(rec, req, "app-1", "", "")

		require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
		require.Equal(t, "/", rec.Header().Get("Location"), "unsafe target %q", target)
	}
}

// TestAppAuthGate_SSORedirectFlow proves code-flow providers render a button,
// receive a one-time state, and issue clearance after exchange.
func TestAppAuthGate_SSORedirectFlow(t *testing.T) {
	client := NewMockOIDCClient(OIDCConfig{
		IssuerURL:   "https://idp.mock",
		ClientID:    "mock-client",
		RedirectURL: "https://app.example.com" + AppAuthCallbackPath,
	}, func(_ context.Context, code string) (*UserIdentity, error) {
		require.Equal(t, "mock-code", code)
		return &UserIdentity{Subject: "oidc:bob", Email: "bob@idp.mock", Provider: "oidc"}, nil
	}).SetName("SSO")

	gate := NewAppAuthGate("0123456789abcdef0123456789abcdef", nil, nil,
		WithIdentityProviders(client))
	require.Len(t, gate.SSOButtons(), 1)

	startForm := url.Values{"provider": {"SSO"}, "redirect": {"/dashboard"}}
	start := httptest.NewRequest(http.MethodPost, "http://app.example.com"+AppAuthSSOPath, strings.NewReader(startForm.Encode()))
	start.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	startRec := httptest.NewRecorder()
	gate.HandleSSOStart(startRec, start, "app-1")
	require.Equal(t, http.StatusFound, startRec.Code)

	location, err := url.Parse(startRec.Header().Get("Location"))
	require.NoError(t, err)
	state := location.Query().Get("state")
	require.NotEmpty(t, state)

	callback := httptest.NewRequest(http.MethodGet,
		"http://app.example.com"+AppAuthCallbackPath+"?code=mock-code&state="+url.QueryEscape(state), nil)
	callbackRec := httptest.NewRecorder()
	gate.HandleSSOCallback(callbackRec, callback)

	require.Equal(t, http.StatusFound, callbackRec.Code, callbackRec.Body.String())
	require.Equal(t, "/dashboard", callbackRec.Header().Get("Location"))
	cookies := callbackRec.Result().Cookies()
	require.Len(t, cookies, 1)
	require.Equal(t, AppAuthCookieName, cookies[0].Name)

	// State is single-use.
	replay := httptest.NewRecorder()
	gate.HandleSSOCallback(replay, callback)
	require.Equal(t, http.StatusBadRequest, replay.Code)
}

// TestAppAuthGate_SSOStateExpiry rejects stale redirect states.
func TestAppAuthGate_SSOStateExpiry(t *testing.T) {
	gate := NewAppAuthGate("0123456789abcdef0123456789abcdef", nil, nil)
	state := gate.newSSOState(pendingSSO{Provider: "SSO", Target: "/"})
	gate.states.Store(state, pendingSSO{
		Provider:  "SSO",
		Target:    "/",
		CreatedAt: time.Now().Add(-time.Hour),
	})
	_, ok := gate.consumeSSOState(state)
	require.False(t, ok)
}
