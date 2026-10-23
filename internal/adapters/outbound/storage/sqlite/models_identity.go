package sqlite

import "time"

// RaiwallIdentityUser mirrors a raiwall_identity_users row in the in-memory driver.
type RaiwallIdentityUser struct {
	ID           string
	Username     string
	PasswordHash string
	Email        string
	DisplayName  string
	TOTPSecret   string
	TOTPEnabled  int64
	AppIDs       string
	Enabled      int64
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// RaiwallIdentityProvider mirrors a raiwall_identity_providers row.
type RaiwallIdentityProvider struct {
	ID        string
	Type      string
	Name      string
	Config    string
	Enabled   int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

// RaiwallIdentityAuthEvent mirrors a raiwall_identity_auth_log row.
type RaiwallIdentityAuthEvent struct {
	CreatedAt time.Time
	Username  string
	AppID     string
	Host      string
	Method    string
	Result    string
	ClientIP  string
	Country   string
	Detail    string
}
