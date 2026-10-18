package acl

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
}

// ThreatEntry records threat feed membership and metadata for an IP or CIDR block.
type ThreatEntry struct {
	Feeds       []string `json:"feeds"`
	Description string   `json:"description,omitempty"`
}

// Clone returns a deep copy of ThreatEntry for bart.Table requirements.
func (e ThreatEntry) Clone() ThreatEntry {
	var f []string
	if e.Feeds != nil {
		f = make([]string, len(e.Feeds))
		copy(f, e.Feeds)
	}
	return ThreatEntry{
		Feeds:       f,
		Description: e.Description,
	}
}

// Equal checks equality of two ThreatEntries for bart.Table requirements.
func (e ThreatEntry) Equal(other ThreatEntry) bool {
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
func (e ThreatEntry) HasFeed(feedName string) bool {
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
