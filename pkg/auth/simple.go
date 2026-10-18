package auth

import (
	"crypto/subtle"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// SimpleAuth provides local credential-based authentication.
type SimpleAuth struct {
	mu    sync.RWMutex
	users map[string]SimpleUser
}

// NewSimpleAuth initializes a SimpleAuth credential store with optional users.
func NewSimpleAuth(users ...SimpleUser) *SimpleAuth {
	sa := &SimpleAuth{
		users: make(map[string]SimpleUser, len(users)),
	}
	for _, u := range users {
		sa.AddUser(u)
	}
	return sa
}

// HashPassword hashes a raw password using bcrypt.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(bytes), nil
}

// CheckPassword verifies a raw password against a hash or plain string.
func CheckPassword(password, hash string) bool {
	if password == "" || hash == "" {
		return false
	}
	if strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$") {
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	}
	// Fallback constant-time compare for plain test passwords
	return subtle.ConstantTimeCompare([]byte(password), []byte(hash)) == 1
}

// AddUser stores a SimpleUser in the credential map.
func (s *SimpleAuth) AddUser(user SimpleUser) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[strings.ToLower(user.Username)] = user
}

// SetUser creates or updates a user, automatically hashing the password if it is raw.
func (s *SimpleAuth) SetUser(username, password, email, name string, roles []string) error {
	var hash string
	if strings.HasPrefix(password, "$2a$") || strings.HasPrefix(password, "$2b$") || strings.HasPrefix(password, "$2y$") {
		hash = password
	} else {
		h, err := HashPassword(password)
		if err != nil {
			return err
		}
		hash = h
	}

	s.AddUser(SimpleUser{
		Username:     username,
		PasswordHash: hash,
		Email:        email,
		Name:         name,
		Roles:        roles,
	})
	return nil
}

// GetUser retrieves a user by username.
func (s *SimpleAuth) GetUser(username string) (SimpleUser, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[strings.ToLower(username)]
	return u, ok
}

// DeleteUser removes a user by username.
func (s *SimpleAuth) DeleteUser(username string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.ToLower(username)
	if _, ok := s.users[key]; ok {
		delete(s.users, key)
		return true
	}
	return false
}

// Authenticate verifies the username and password, returning a verified UserIdentity on success.
func (s *SimpleAuth) Authenticate(username, password string) (*UserIdentity, error) {
	s.mu.RLock()
	user, exists := s.users[strings.ToLower(username)]
	s.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("invalid username or password")
	}

	if !CheckPassword(password, user.PasswordHash) {
		return nil, fmt.Errorf("invalid username or password")
	}

	now := time.Now()
	email := user.Email
	if email == "" {
		email = user.Username + "@local"
	}
	name := user.Name
	if name == "" {
		name = user.Username
	}

	return &UserIdentity{
		Subject:   user.Username,
		Email:     email,
		Name:      name,
		Roles:     user.Roles,
		Provider:  "simple",
		IssuedAt:  now,
		ExpiresAt: now.Add(DefaultSessionTTL),
	}, nil
}
