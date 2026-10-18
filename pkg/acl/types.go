package acl

import "strings"

// Location defines parameter origination locations for ACL and exception rules.
type Location string

const (
	LocationAll       Location = "*"
	LocationPath      Location = "Path"
	LocationQuery     Location = "Query"
	LocationHeader    Location = "Header"
	LocationCookie    Location = "Cookie"
	LocationBody      Location = "Body"
	LocationJSON      Location = "JSON"
	LocationMultipart Location = "Multipart"
)

// Action represents an ACL policy decision.
type Action string

const (
	ActionAllow     Action = "allow"
	ActionBlock     Action = "block"
	ActionChallenge Action = "challenge"
	ActionRedirect  Action = "redirect"
	ActionAudit     Action = "audit"
)

// GeoData contains geographical and autonomous system intelligence for an IP address.
type GeoData struct {
	Country   string `json:"country,omitempty"`   // ISO 3166-1 alpha-2 (e.g. "US", "DE")
	Continent string `json:"continent,omitempty"` // Continent code (e.g. "NA", "EU")
	ASN       uint   `json:"asn,omitempty"`       // Autonomous System Number (e.g. 15169)
	ASOrg     string `json:"as_org,omitempty"`    // Autonomous System Organization name

	// Lowercase expr aliases for expr expressions (e.g. geo.country, geo.continent, geo.asn, geo.as_org)
	Country_   string `json:"-" expr:"country"`
	Continent_ string `json:"-" expr:"continent"`
	ASN_       uint   `json:"-" expr:"asn"`
	ASOrg_     string `json:"-" expr:"as_org"`
}

// FeedMetadata records threat feed membership and metadata for an IP or CIDR block.
type FeedMetadata struct {
	Feeds       []string `json:"feeds"`
	Description string   `json:"description,omitempty"`
}

// ThreatEntry is an alias for FeedMetadata.
type ThreatEntry = FeedMetadata

// Clone returns a deep copy of FeedMetadata for bart.Table requirements.
func (e FeedMetadata) Clone() FeedMetadata {
	var f []string
	if e.Feeds != nil {
		f = make([]string, len(e.Feeds))
		copy(f, e.Feeds)
	}
	return FeedMetadata{
		Feeds:       f,
		Description: e.Description,
	}
}

// Equal checks equality of two FeedMetadatas for bart.Table requirements.
func (e FeedMetadata) Equal(other FeedMetadata) bool {
	if e.Description != other.Description || len(e.Feeds) != len(other.Feeds) {
		return false
	}
	for i := range e.Feeds {
		if e.Feeds[i] != other.Feeds[i] {
			return false
		}
	}
	return true
}

// HasFeed checks whether the entry belongs to a specific feed name (case-insensitive).
// Wildcard "*" or empty string matches any feed.
func (e FeedMetadata) HasFeed(feedName string) bool {
	if feedName == "" || feedName == "*" {
		return len(e.Feeds) > 0
	}
	for _, f := range e.Feeds {
		if strings.EqualFold(f, feedName) {
			return true
		}
	}
	return false
}

// ACLVerdict represents the outcome of evaluating ACL rules against a request.
type ACLVerdict struct {
	Matched     bool   `json:"matched"`
	RuleName    string `json:"rule_name,omitempty"`
	Action      Action `json:"action"`
	StatusCode  int    `json:"status_code,omitempty"`
	RedirectURL string `json:"redirect_url,omitempty"`
	Reason      string `json:"reason,omitempty"`
}
