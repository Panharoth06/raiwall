package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"golang.org/x/crypto/bcrypt"
)

const (
	SessionCookieName = "raiwall_session"
	RoleAdmin         = "admin"
	RoleViewer        = "viewer"
)

// AuthContext holds authenticated principal information.
type AuthContext struct {
	UserID   string `json:"user_id,omitempty"`
	Username string `json:"username,omitempty"`
	Role     string `json:"role"`
	IsAPIKey bool   `json:"is_api_key"`
	KeyID    string `json:"key_id,omitempty"`
}

// AuthManager handles authentication, session cookies, and password hashing.
type AuthManager struct {
	store      control.ControlStore
	hmacSecret []byte
}

// NewAuthManager creates an AuthManager with a specified HMAC secret or generates one randomly.
func NewAuthManager(store control.ControlStore, secret []byte) *AuthManager {
	if len(secret) == 0 {
		secret = make([]byte, 32)
		_, _ = rand.Read(secret)
	}
	return &AuthManager{
		store:      store,
		hmacSecret: secret,
	}
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
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// HashAPIKey computes the SHA-256 hex string of a raw API token.
func HashAPIKey(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// GenerateSessionCookie creates an HMAC-signed session cookie for a user.
func (am *AuthManager) GenerateSessionCookie(user *control.UserRecord, duration time.Duration) (*http.Cookie, error) {
	if user == nil {
		return nil, errors.New("cannot create cookie for nil user")
	}
	if duration <= 0 {
		duration = 24 * time.Hour
	}
	expiresAt := time.Now().UTC().Add(duration)
	expUnix := strconv.FormatInt(expiresAt.Unix(), 10)

	payload := fmt.Sprintf("%s:%s:%s:%s", user.ID, user.Username, user.Role, expUnix)
	mac := hmac.New(sha256.New, am.hmacSecret)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	rawCookie := fmt.Sprintf("%s:%s", payload, sig)
	encoded := base64.RawURLEncoding.EncodeToString([]byte(rawCookie))

	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    encoded,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}, nil
}

// VerifySessionCookie validates an incoming cookie's signature and expiration.
func (am *AuthManager) VerifySessionCookie(cookie *http.Cookie) (*AuthContext, error) {
	if cookie == nil || strings.TrimSpace(cookie.Value) == "" {
		return nil, errors.New("empty session cookie")
	}

	decodedBytes, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, fmt.Errorf("invalid cookie encoding: %w", err)
	}

	parts := strings.Split(string(decodedBytes), ":")
	if len(parts) != 5 {
		return nil, errors.New("invalid cookie payload format")
	}

	userID := parts[0]
	username := parts[1]
	role := parts[2]
	expStr := parts[3]
	sig := parts[4]

	payload := fmt.Sprintf("%s:%s:%s:%s", userID, username, role, expStr)
	mac := hmac.New(sha256.New, am.hmacSecret)
	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return nil, errors.New("invalid session signature")
	}

	expUnix, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return nil, errors.New("invalid session expiration")
	}
	if time.Now().UTC().Unix() > expUnix {
		return nil, errors.New("session has expired")
	}

	return &AuthContext{
		UserID:   userID,
		Username: username,
		Role:     role,
		IsAPIKey: false,
	}, nil
}
