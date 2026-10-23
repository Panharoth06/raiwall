package auth

import (
	"fmt"
	"strings"
)

// DirectoryLogin verifies an identity-directory account:
//  1. enabled state (disabled accounts never authenticate),
//  2. bcrypt password match,
//  3. TOTP second factor when enrolled (a wrong or missing code rejects login).
type DirectoryLogin struct {
	// PasswordHash is the stored bcrypt hash.
	PasswordHash string
	// TOTPSecret is the stored base32 second-factor secret; empty = not enrolled.
	TOTPSecret string
	// TOTPEnrolled marks the account as requiring the second factor.
	TOTPEnrolled bool
	// Enabled gates the account; disabled accounts always fail closed.
	Enabled bool
}

// Authenticate checks credentials and returns a nil error on success.
func (d DirectoryLogin) Authenticate(password, totpCode string) error {
	if !d.Enabled {
		return fmt.Errorf("account is disabled")
	}
	if !CheckPassword(password, d.PasswordHash) {
		return fmt.Errorf("invalid username or password")
	}
	if !d.TOTPEnrolled {
		return nil
	}
	if strings.TrimSpace(d.TOTPSecret) == "" {
		return fmt.Errorf("totp is enrolled but the secret is missing; reset 2FA")
	}
	ok, err := VerifyTOTPCode(d.TOTPSecret, totpCode)
	if err != nil {
		return fmt.Errorf("totp verification failed: %w", err)
	}
	if !ok {
		return fmt.Errorf("invalid totp code")
	}
	return nil
}

// IdentityUser mirrors an end-user directory account. It is defined here as a
// pure core type so login logic never depends on storage rows.
type IdentityUser struct {
	ID           string   `json:"id"`
	Username     string   `json:"username"`
	PasswordHash string   `json:"-"` // never serialized
	Email        string   `json:"email"`
	DisplayName  string   `json:"display_name"`
	TOTPSecret   string   `json:"-"` // never serialized
	TOTPEnrolled bool     `json:"totp_enrolled"`
	AppIDs       []string `json:"app_ids"`
	Enabled      bool     `json:"enabled"`
}
