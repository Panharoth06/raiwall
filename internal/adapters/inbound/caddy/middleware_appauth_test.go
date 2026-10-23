package caddy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/sqlite"
	"github.com/Panharoth06/raiwall/internal/core/auth"
	"github.com/Panharoth06/raiwall/internal/core/control"
	caddy "github.com/caddyserver/caddy/v2"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

// setupAppAuthFixture provisions a middleware backed by a live fake-driver
// control store with one directory user bound to the app. Callers install
// their own snapshot.
type appAuthFixture struct {
	mw    *Middleware
	store *sqlite.Store
	// secret mirrors the snapshot token used in tests.
	secret string
}

func setupAppAuthFixture(t *testing.T) *appAuthFixture {
	t.Helper()

	store, err := sqlite.InitDB(fmt.Sprintf("file:test_appauth_%d.db", time.Now().UnixNano()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	hash, err := auth.HashPassword("SuperSecret123!")
	require.NoError(t, err)
	require.NoError(t, store.UpsertIdentityUser(context.Background(), control.IdentityUserRecord{
		ID:           "idusr-apptest",
		Username:     "walter",
		PasswordHash: hash,
		AppIDs:       `["app-1"]`,
		Enabled:      1,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}))

	secret := "0123456789abcdef0123456789abcdef0123"
	require.NoError(t, store.PutSetting(context.Background(), "app_auth_session_secret", secret))

	app := &control.AppConfig{
		ID:              "app-1",
		Name:            "Frontend",
		Hostnames:       []string{"app.example.com"},
		Mode:            control.ModeDefense,
		AuthEnabled:     true,
		AuthBypassPaths: []string{"/public"},
	}
	snap := control.NewConfigSnapshot(42, control.ModeDefense, []*control.AppConfig{app})
	snap.AppAuthSessionSecret = secret
	control.StoreSnapshot(snap)
	t.Cleanup(func() {
		control.StoreSnapshot(control.NewConfigSnapshot(0, control.ModeDefense, nil))
	})

	m := &Middleware{
		Mode:            "defense",
		BlockStatusCode: 403,
		controlStore:    store,
	}
	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	require.NoError(t, m.Provision(caddyCtx))

	return &appAuthFixture{mw: m, store: store, secret: secret}
}

func cookiesNamed(rec *httptest.ResponseRecorder, name string) []*http.Cookie {
	var found []*http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			found = append(found, c)
		}
	}
	return found
}

func TestMiddleware_AppAuthGate_FullFlow(t *testing.T) {
	f := setupAppAuthFixture(t)

	// 1. Unauthenticated browser gets HTTP 467 with the branded portal.
	next := &mockNextHandler{}
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/dashboard", nil)
	rec := httptest.NewRecorder()
	require.NoError(t, f.mw.ServeHTTP(rec, req, next))
	require.False(t, next.invoked, "protected pages must not reach upstream pre-auth")
	require.Equal(t, 467, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "HTTP 467")
	require.Contains(t, rec.Body.String(), auth.AppAuthLoginPath)
	require.Contains(t, rec.Body.String(), `value="/dashboard"`)

	// 2. Configured bypass prefix passes through without clearance.
	next = &mockNextHandler{}
	req = httptest.NewRequest(http.MethodGet, "http://app.example.com/public/logo.png", nil)
	rec = httptest.NewRecorder()
	require.NoError(t, f.mw.ServeHTTP(rec, req, next))
	require.True(t, next.invoked, "bypass prefix must reach upstream")

	// 3. API transports bypass transparently.
	next = &mockNextHandler{}
	req = httptest.NewRequest(http.MethodGet, "http://app.example.com/api/things", nil)
	rec = httptest.NewRecorder()
	require.NoError(t, f.mw.ServeHTTP(rec, req, next))
	require.True(t, next.invoked, "API path must bypass the challenge")

	next = &mockNextHandler{}
	req = httptest.NewRequest(http.MethodGet, "http://app.example.com/data", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec = httptest.NewRecorder()
	require.NoError(t, f.mw.ServeHTTP(rec, req, next))
	require.True(t, next.invoked, "Bearer callers must bypass the 467 challenge")

	// 4. Wrong password re-renders the challenge (no cookie issued).
	form := url.Values{"username": {"walter"}, "password": {"wrong"}, "redirect": {"/dashboard"}}
	req = httptest.NewRequest(http.MethodPost, "http://app.example.com"+auth.AppAuthLoginPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	require.NoError(t, f.mw.ServeHTTP(rec, req, &mockNextHandler{}))
	require.Equal(t, 467, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "Invalid username or password")
	require.Empty(t, cookiesNamed(rec, auth.AppAuthCookieName))

	// 5. Correct credentials issue the clearance cookie and redirect back.
	form = url.Values{"username": {"walter"}, "password": {"SuperSecret123!"}, "redirect": {"/dashboard"}}
	req = httptest.NewRequest(http.MethodPost, "http://app.example.com"+auth.AppAuthLoginPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	require.NoError(t, f.mw.ServeHTTP(rec, req, &mockNextHandler{}))
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	require.Equal(t, "/dashboard", rec.Header().Get("Location"))
	clearance := cookiesNamed(rec, auth.AppAuthCookieName)
	require.Len(t, clearance, 1)

	// 6. Cleared browser reaches upstream with identity headers injected.
	next = &mockNextHandler{}
	req = httptest.NewRequest(http.MethodGet, "http://app.example.com/dashboard", nil)
	req.AddCookie(clearance[0])
	rec = httptest.NewRecorder()
	require.NoError(t, f.mw.ServeHTTP(rec, req, next))
	require.True(t, next.invoked, "cleared session must reach upstream")
	require.Equal(t, "walter", req.Header.Get(auth.HeaderAuthSubject))

	// 7. The audit log captured both attempts (newest first).
	events, err := f.store.ListIdentityAuthEvents(context.Background(), 10)
	require.NoError(t, err)
	require.Len(t, events, 2)
	require.Equal(t, "success", events[0].Result)
	require.Equal(t, "invalid_password", events[1].Result)
	require.Equal(t, "app-1", events[1].AppID)
	require.Equal(t, "walter", events[1].Username)

	// 8. Logout invalidates the clearance.
	req = httptest.NewRequest(http.MethodGet, "http://app.example.com"+auth.AppAuthLogoutPath, nil)
	req.AddCookie(clearance[0])
	rec = httptest.NewRecorder()
	require.NoError(t, f.mw.ServeHTTP(rec, req, &mockNextHandler{}))
	require.Equal(t, http.StatusFound, rec.Code)
	require.Len(t, cookiesNamed(rec, auth.AppAuthCookieName), 1)
}

// TestMiddleware_AppAuthGate_TOTPFlow exercises second-factor verification
// against the live directory through the pipeline.
func TestMiddleware_AppAuthGate_TOTPFlow(t *testing.T) {
	f := setupAppAuthFixture(t)

	totpSecret, _, err := auth.GenerateTOTPSecret(auth.TOTPIssuer, "kyra@corp.example")
	require.NoError(t, err)
	hash, err := auth.HashPassword("SuperSecret123!")
	require.NoError(t, err)
	require.NoError(t, f.store.UpsertIdentityUser(context.Background(), control.IdentityUserRecord{
		ID:           "idusr-totp",
		Username:     "kyra",
		PasswordHash: hash,
		TOTPSecret:   totpSecret,
		TOTPEnabled:  1,
		AppIDs:       `["app-1"]`,
		Enabled:      1,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}))

	submit := func(code string) *httptest.ResponseRecorder {
		form := url.Values{"username": {"kyra"}, "password": {"SuperSecret123!"}, "totp": {code}, "redirect": {"/"}}
		req := httptest.NewRequest(http.MethodPost, "http://app.example.com"+auth.AppAuthLoginPath, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		require.NoError(t, f.mw.ServeHTTP(rec, req, &mockNextHandler{}))
		return rec
	}

	// Missing second factor fails closed.
	rec := submit("")
	require.Equal(t, 467, rec.Code)
	require.Contains(t, rec.Body.String(), "Invalid verification code")

	// Valid code clears the session.
	code, genErr := totpGenerate(totpSecret)
	require.NoError(t, genErr)
	rec = submit(code)
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	require.Len(t, cookiesNamed(rec, auth.AppAuthCookieName), 1)
}

// totpGenerate mints a fresh code for the wire test.
func totpGenerate(secret string) (string, error) {
	return totp.GenerateCode(secret, time.Now())
}
