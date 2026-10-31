package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	// SessionCookieName is the fallback cookie name for local plaintext dev.
	SessionCookieName = "raiwall_session"
	// SecureSessionCookieName is used whenever the session cookie is Secure.
	SecureSessionCookieName = "__Host-raiwall_session"
	RoleAdmin               = "admin"
	RoleViewer              = "viewer"

	defaultSessionTouchInterval = 5 * time.Minute
	maxUserAgentLength          = 512
)

// dummyPasswordHash keeps unknown-user login timing close to a real check.
var dummyPasswordHash, _ = bcrypt.GenerateFromPassword([]byte("raiwall-dummy-password"), bcrypt.DefaultCost)

// AuthContext holds authenticated principal information.
type AuthContext struct {
	UserID    string `json:"user_id,omitempty"`
	Username  string `json:"username,omitempty"`
	Role      string `json:"role"`
	IsAPIKey  bool   `json:"is_api_key"`
	KeyID     string `json:"key_id,omitempty"`
	SessionID string `json:"-"`
	// Method is "cookie", "api_key", or "basic". It is not exposed to clients.
	Method string `json:"-"`
}

// SessionConfig controls opaque operator sessions and the login surface.
type SessionConfig struct {
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
	Secure          bool
	AllowBasicAuth  bool
	PublicURL       string
}

func (c SessionConfig) withDefaults() SessionConfig {
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = 8 * time.Hour
	}
	if c.AbsoluteTimeout <= 0 {
		c.AbsoluteTimeout = 24 * time.Hour
	}
	if c.IdleTimeout > c.AbsoluteTimeout {
		c.IdleTimeout = c.AbsoluteTimeout
	}
	return c
}

// AuthManager handles authentication, operator sessions, and password hashing.
type AuthManager struct {
	store      control.ControlStore
	hmacSecret []byte
	limiter    *loginLimiter
	now        func() time.Time

	mu      sync.RWMutex
	session SessionConfig
}

// NewAuthManager creates an AuthManager. The HMAC secret keys session token
// hashes, so a database leak alone cannot replay cookies.
func NewAuthManager(store control.ControlStore, secret []byte) *AuthManager {
	if len(secret) == 0 {
		secret = make([]byte, 32)
		_, _ = rand.Read(secret)
	}
	return &AuthManager{
		store:      store,
		hmacSecret: secret,
		limiter:    newLoginLimiter(),
		now:        time.Now,
		session:    SessionConfig{Secure: true}.withDefaults(),
	}
}

// SetSessionConfig applies session/cookie/login settings.
func (am *AuthManager) SetSessionConfig(cfg SessionConfig) {
	am.mu.Lock()
	am.session = cfg.withDefaults()
	am.mu.Unlock()
}

// SessionConfig returns the active settings.
func (am *AuthManager) SessionConfig() SessionConfig {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.session
}

// CookieName returns the cookie name implied by the Secure setting.
func (am *AuthManager) CookieName() string {
	if am.SessionConfig().Secure {
		return SecureSessionCookieName
	}
	return SessionCookieName
}

// HashPassword hashes a raw password using bcrypt.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// CheckPassword checks a password against a bcrypt hash.
func CheckPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// HashAPIKey computes the SHA-256 hex string of a raw API token.
func HashAPIKey(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func (am *AuthManager) hashToken(token string) string {
	mac := hmac.New(sha256.New, am.hmacSecret)
	mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil))
}

// ErrInvalidCredentials is returned for a wrong password or unknown user.
var ErrInvalidCredentials = errors.New("invalid username or password")

// LoginLockedError reports a throttled login; RetryAfter is a minimum wait.
type LoginLockedError struct {
	RetryAfter time.Duration
}

func (e *LoginLockedError) Error() string { return "too many failed login attempts" }

// CheckCredentials verifies a username/password pair, applying per-IP and
// per-username throttling. It always performs a bcrypt comparison.
func (am *AuthManager) CheckCredentials(ctx context.Context, username, password, clientIP string) (control.UserRecord, error) {
	keys := throttlingKeys(username, clientIP)
	if retry, blocked := am.limiter.check(am.now(), keys...); blocked {
		return control.UserRecord{}, &LoginLockedError{RetryAfter: retry}
	}

	user, err := am.store.GetUserByUsername(ctx, username)
	hash := string(dummyPasswordHash)
	if err == nil && user.PasswordHash != "" {
		hash = user.PasswordHash
	}
	valid := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	if err != nil || user.IsActive != 1 || !valid {
		am.limiter.failure(am.now(), keys...)
		return control.UserRecord{}, ErrInvalidCredentials
	}

	am.limiter.success(keys...)
	return user, nil
}

// CreateSessionCookie mints a session, stores only its hash, and returns the
// cookie to send to the client.
func (am *AuthManager) CreateSessionCookie(ctx context.Context, user *control.UserRecord, clientIP, userAgent string) (*http.Cookie, error) {
	if user == nil {
		return nil, errors.New("cannot create session for nil user")
	}
	cfg := am.SessionConfig()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generate session token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	now := am.now().UTC()

	session := control.AdminSession{
		ID:                uuid.NewString(),
		UserID:            user.ID,
		TokenHash:         am.hashToken(token),
		CreatedAt:         now,
		LastSeenAt:        now,
		IdleExpiresAt:     now.Add(cfg.IdleTimeout),
		AbsoluteExpiresAt: now.Add(cfg.AbsoluteTimeout),
		ClientIP:          clientIP,
		UserAgent:         truncate(userAgent, maxUserAgentLength),
	}
	if err := am.store.CreateAdminSession(ctx, session); err != nil {
		return nil, fmt.Errorf("persist session: %w", err)
	}
	return am.newCookie(token, session.AbsoluteExpiresAt), nil
}

// VerifySessionCookie resolves the session cookie, revalidates the user in the
// database, and returns the current role (not the role at login time).
func (am *AuthManager) VerifySessionCookie(r *http.Request) (*AuthContext, error) {
	cookie, err := r.Cookie(am.CookieName())
	if err != nil || cookie.Value == "" {
		return nil, errors.New("no session cookie")
	}

	session, err := am.store.GetAdminSessionByTokenHash(r.Context(), am.hashToken(cookie.Value))
	if err != nil {
		return nil, errors.New("invalid session")
	}
	now := am.now().UTC()
	if session.RevokedAt.Valid {
		return nil, errors.New("session revoked")
	}
	if !now.Before(session.IdleExpiresAt) || !now.Before(session.AbsoluteExpiresAt) {
		return nil, errors.New("session expired")
	}

	user, err := am.store.GetUserByID(r.Context(), session.UserID)
	if err != nil || user.IsActive != 1 {
		return nil, errors.New("operator account is inactive")
	}

	if now.Sub(session.LastSeenAt) >= defaultSessionTouchInterval {
		idle := now.Add(am.SessionConfig().IdleTimeout)
		if idle.After(session.AbsoluteExpiresAt) {
			idle = session.AbsoluteExpiresAt
		}
		_ = am.store.TouchAdminSession(r.Context(), session.ID, now, idle)
	}

	return &AuthContext{
		UserID:    user.ID,
		Username:  user.Username,
		Role:      user.Role,
		SessionID: session.ID,
		Method:    "cookie",
	}, nil
}

// RevokeSession ends one session immediately.
func (am *AuthManager) RevokeSession(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return nil
	}
	return am.store.RevokeAdminSession(ctx, sessionID, am.now().UTC())
}

// RevokeUserSessions ends every session for a user (role/password/state change).
func (am *AuthManager) RevokeUserSessions(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	return am.store.RevokeAdminSessionsForUser(ctx, userID, am.now().UTC())
}

// ClearSessionCookie expires the active cookie name.
func (am *AuthManager) ClearSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     am.CookieName(),
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   am.SessionConfig().Secure,
		SameSite: http.SameSiteLaxMode,
	}
}

func (am *AuthManager) newCookie(token string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     am.CookieName(),
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   am.SessionConfig().Secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// Authenticate resolves the request principal from an API key, session cookie,
// or (when enabled) HTTP Basic credentials.
func (am *AuthManager) Authenticate(r *http.Request) (*AuthContext, error) {
	if authCtx := am.authenticateAPIKey(r); authCtx != nil {
		return authCtx, nil
	}

	if authCtx, err := am.VerifySessionCookie(r); err == nil {
		return authCtx, nil
	}

	if username, _, ok := r.BasicAuth(); ok && am.SessionConfig().AllowBasicAuth {
		if authCtx, err := am.authenticateBasic(r, username, clientIPFromRequest(r)); err == nil {
			return authCtx, nil
		}
	}
	return nil, errors.New("unauthorized: valid API key or session cookie required")
}

func (am *AuthManager) authenticateAPIKey(r *http.Request) *AuthContext {
	token := r.Header.Get("X-Raiwall-Key")
	if token == "" {
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			token = strings.TrimPrefix(h, "Bearer ")
		}
	}
	if token == "" {
		return nil
	}

	keyRecord, err := am.store.GetAPIKeyByHash(r.Context(), HashAPIKey(token))
	if err != nil || keyRecord.IsActive != 1 {
		return nil
	}
	if keyRecord.ExpiresAt.Valid && !keyRecord.ExpiresAt.Time.After(time.Now().UTC()) {
		return nil
	}
	go func(kID string) {
		_ = am.store.UpdateAPIKeyLastUsed(context.Background(), kID, time.Now().UTC())
	}(keyRecord.ID)
	return &AuthContext{
		Role:     keyRecord.Role,
		IsAPIKey: true,
		KeyID:    keyRecord.ID,
		Username: keyRecord.Name,
		Method:   "api_key",
	}
}

func (am *AuthManager) authenticateBasic(r *http.Request, username, clientIP string) (*AuthContext, error) {
	_, password, ok := r.BasicAuth()
	if !ok {
		return nil, errors.New("missing basic credentials")
	}
	user, err := am.CheckCredentials(r.Context(), username, password, clientIP)
	if err != nil {
		return nil, err
	}
	return &AuthContext{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		Method:   "basic",
	}, nil
}

func throttlingKeys(username, clientIP string) []string {
	keys := make([]string, 0, 2)
	if clientIP != "" {
		keys = append(keys, "ip:"+clientIP)
	}
	if normalized := strings.ToLower(strings.TrimSpace(username)); normalized != "" {
		keys = append(keys, "user:"+normalized)
	}
	return keys
}

// OriginAllowed enforces same-origin on cookie-authenticated mutations.
// Requests with neither Origin nor Referer are non-browser clients (curl, CI)
// and are allowed; browsers send Origin on cross-site unsafe requests, which
// must match this host or the configured public URL.
func (am *AuthManager) OriginAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return false
	}
	if strings.EqualFold(parsed.Host, r.Host) {
		return true
	}
	publicURL := am.SessionConfig().PublicURL
	if publicURL == "" {
		return false
	}
	expected, err := url.Parse(publicURL)
	return err == nil && strings.EqualFold(parsed.Host, expected.Host)
}

func clientIPFromRequest(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
