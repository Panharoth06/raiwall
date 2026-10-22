package sqlite

import (
	"time"
)

// RaiwallIPGroup models the raiwall_ip_groups table.
type RaiwallIPGroup struct {
	ID          string
	Name        string
	Description string
	Type        string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// RaiwallIPGroupEntry models the raiwall_ip_group_entries table.
type RaiwallIPGroupEntry struct {
	ID        string
	GroupID   string
	CIDROrIP  string
	Comment   string
	CreatedAt time.Time
}

// RaiwallResponseTemplate models the raiwall_response_templates table.
type RaiwallResponseTemplate struct {
	ID          string
	StatusCode  int
	Title       string
	ContentHTML string
	CustomCSS   string
	BrandName   string
	LogoURL     string
	IsCustom    int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
