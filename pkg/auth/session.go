package auth

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SessionClaims represents the claims encoded in the signed session JWT.
type SessionClaims struct {
	Subject  string   `json:"sub"`
	Email    string   `json:"email,omitempty"`
	Name     string   `json:"name,omitempty"`
	Roles    []string `json:"roles,omitempty"`
	Provider string   `json:"provider,omitempty"`
	jwt.RegisteredClaims
}

// SessionConfig configures the session manager.
type SessionConfig struct {
	Secret     []byte
	CookieName string
	TTL        time.Duration
	Secure     bool
}

// SessionOption allows configuring SessionManager.
type SessionOption func(*SessionManager)

// WithCookieName overrides the default cookie name.
func WithCookieName(name string) SessionOption {
	return func(s *SessionManager) {
		if name != "" {
			s.cookieName = name
		}
	}
}

// WithCookieTTL overrides the session expiration duration.
func WithCookieTTL(ttl time.Duration) SessionOption {
	return func(s *SessionManager) {
		s.cookieTTL = ttl
	}
}

// WithCookieDomain sets the domain for the session cookie.
func WithCookieDomain(domain string) SessionOption {
	return func(s *SessionManager) {
		s.cookieDomain = domain
	}
}

// WithCookieSecure sets the Secure attribute on the session cookie.
func WithCookieSecure(secure bool) SessionOption {
	return func(s *SessionManager) {
		s.secure = secure
	}
}

// WithCookieSameSite configures the SameSite policy for the session cookie.
func WithCookieSameSite(mode http.SameSite) SessionOption {
	return func(s *SessionManager) {
		s.sameSite = mode
	}
}

// SessionManager signs and validates stateless JWT session cookies.
type SessionManager struct {
	secret       []byte
	cookieName   string
	cookieTTL    time.Duration
	cookiePath   string
	cookieDomain string
	secure       bool
	httpOnly     bool
	sameSite     http.SameSite
}

// NewSessionManager creates a SessionManager accepting either a secret string or a SessionConfig struct.
func NewSessionManager(secretOrCfg any, opts ...SessionOption) *SessionManager {
	sm := &SessionManager{
		secret:     []byte("raiwall-default-secret-change-in-production-32b"),
		cookieName: DefaultSessionCookieName,
		cookieTTL:  DefaultSessionTTL,
		cookiePath: "/",
		secure:     true,
		httpOnly:   true,
		sameSite:   http.SameSiteLaxMode,
	}

	switch v := secretOrCfg.(type) {
	case string:
		if v != "" {
			sm.secret = []byte(v)
		}
	case []byte:
		if len(v) > 0 {
			sm.secret = v
		}
	case SessionConfig:
		if len(v.Secret) > 0 {
			sm.secret = v.Secret
		}
		if v.CookieName != "" {
			sm.cookieName = v.CookieName
		}
		if v.TTL > 0 {
			sm.cookieTTL = v.TTL
		}
		sm.secure = v.Secure
	case *SessionConfig:
		if v != nil {
			if len(v.Secret) > 0 {
				sm.secret = v.Secret
			}
			if v.CookieName != "" {
				sm.cookieName = v.CookieName
			}
			if v.TTL > 0 {
				sm.cookieTTL = v.TTL
			}
			sm.secure = v.Secure
		}
	}

	for _, opt := range opts {
		opt(sm)
	}

	return sm
}

// IssueToken is an alias for CreateSessionToken.
func (s *SessionManager) IssueToken(identity *UserIdentity) (string, error) {
	return s.CreateSessionToken(identity)
}

// ValidateToken is an alias for ValidateSessionToken.
func (s *SessionManager) ValidateToken(tokenString string) (*UserIdentity, error) {
	return s.ValidateSessionToken(tokenString)
}

// CreateSessionToken creates a signed HMAC-SHA256 JWT string for an identity.
func (s *SessionManager) CreateSessionToken(identity *UserIdentity) (string, error) {
	if identity == nil {
		return "", fmt.Errorf("identity cannot be nil")
	}

	now := time.Now()
	exp := now.Add(s.cookieTTL)
	if !identity.ExpiresAt.IsZero() && identity.ExpiresAt.Before(exp) {
		exp = identity.ExpiresAt
	}

	claims := SessionClaims{
		Subject:  identity.Subject,
		Email:    identity.Email,
		Name:     identity.Name,
		Roles:    identity.Roles,
		Provider: identity.Provider,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "raiwall",
			Subject:   identity.Subject,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.secret)
}

// CreateSessionCookie generates a signed session cookie.
func (s *SessionManager) CreateSessionCookie(identity *UserIdentity) (*http.Cookie, error) {
	tokenStr, err := s.CreateSessionToken(identity)
	if err != nil {
		return nil, err
	}

	return &http.Cookie{
		Name:     s.cookieName,
		Value:    tokenStr,
		Path:     s.cookiePath,
		Domain:   s.cookieDomain,
		Expires:  time.Now().Add(s.cookieTTL),
		MaxAge:   int(s.cookieTTL.Seconds()),
		HttpOnly: s.httpOnly,
		Secure:   s.secure,
		SameSite: s.sameSite,
	}, nil
}

// SetSessionCookie creates and sets the cookie directly on http.ResponseWriter.
func (s *SessionManager) SetSessionCookie(w http.ResponseWriter, identity *UserIdentity) error {
	cookie, err := s.CreateSessionCookie(identity)
	if err != nil {
		return err
	}
	http.SetCookie(w, cookie)
	return nil
}

// GetSessionClaims extracts and validates UserIdentity from an http.Request.
func (s *SessionManager) GetSessionClaims(r *http.Request) (*UserIdentity, error) {
	return s.ValidateSessionCookie(r)
}

// ValidateSessionToken parses and verifies an HMAC-SHA256 JWT token string.
func (s *SessionManager) ValidateSessionToken(tokenString string) (*UserIdentity, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("empty session token")
	}

	token, err := jwt.ParseWithClaims(tokenString, &SessionClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.secret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid session token: %w", err)
	}

	claims, ok := token.Claims.(*SessionClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	issuedAt := time.Now()
	if claims.IssuedAt != nil {
		issuedAt = claims.IssuedAt.Time
	}
	expiresAt := time.Now().Add(s.cookieTTL)
	if claims.ExpiresAt != nil {
		expiresAt = claims.ExpiresAt.Time
	}

	return &UserIdentity{
		Subject:   claims.Subject,
		Email:     claims.Email,
		Name:      claims.Name,
		Roles:     claims.Roles,
		Provider:  claims.Provider,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
	}, nil
}

// ValidateSessionCookie reads and verifies the session cookie or Authorization Bearer token from an http.Request.
func (s *SessionManager) ValidateSessionCookie(r *http.Request) (*UserIdentity, error) {
	if r == nil {
		return nil, fmt.Errorf("nil request")
	}

	cookie, err := r.Cookie(s.cookieName)
	if err == nil && cookie.Value != "" {
		return s.ValidateSessionToken(cookie.Value)
	}

	// Also support Authorization: Bearer <session-token>
	if authHdr := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(authHdr), "bearer ") {
		tokenStr := strings.TrimSpace(authHdr[7:])
		if tokenStr != "" {
			return s.ValidateSessionToken(tokenStr)
		}
	}

	return nil, fmt.Errorf("session cookie %q not found", s.cookieName)
}

// ClearSessionCookie produces an expired cookie to clear the client session.
// If an http.ResponseWriter is passed, it sets the cookie on it directly.
func (s *SessionManager) ClearSessionCookie(w ...http.ResponseWriter) *http.Cookie {
	cookie := &http.Cookie{
		Name:     s.cookieName,
		Value:    "",
		Path:     s.cookiePath,
		Domain:   s.cookieDomain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: s.httpOnly,
		Secure:   s.secure,
		SameSite: s.sameSite,
	}
	if len(w) > 0 && w[0] != nil {
		http.SetCookie(w[0], cookie)
	}
	return cookie
}

// CookieName returns the active session cookie name.
func (s *SessionManager) CookieName() string {
	return s.cookieName
}
