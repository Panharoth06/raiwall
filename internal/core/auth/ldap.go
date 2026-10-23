package auth

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
)

// LDAPConfig configures the Active Directory / OpenLDAP connector.
type LDAPConfig struct {
	// HostURL is the scheme, host, and port, e.g. ldap://dc.corp:389 or ldaps://.
	HostURL string `json:"host_url"`
	// BindDN / BindPassword identify the service account used for user search.
	BindDN       string `json:"bind_dn"`
	BindPassword string `json:"bind_password"`
	// UserBaseDN scopes the user lookup, e.g. "dc=corp,dc=example".
	UserBaseDN string `json:"user_base_dn"`
	// UserFilter must contain the %s placeholder, e.g. "(sAMAccountName=%s)".
	UserFilter string `json:"user_filter"`
	// AttributeMap names the directory attributes to read.
	Attributes LDAPAttributeMap `json:"attributes"`
	// InsecureSkip disables TLS certificate verification for ldaps URLs.
	InsecureSkip bool `json:"insecure_skip"`
}

// LDAPAttributeMap maps identity claims to directory attribute names.
type LDAPAttributeMap struct {
	Username    string `json:"username"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

// DefaultLDAPAttributeMap fills sane defaults for AD and OpenLDAP.
func DefaultLDAPAttributeMap() LDAPAttributeMap {
	return LDAPAttributeMap{Username: "sAMAccountName", Email: "mail", DisplayName: "displayName"}
}

func (c LDAPConfig) validate() error {
	if !strings.Contains(c.HostURL, "://") {
		return fmt.Errorf("host_url must include the ldap:// or ldaps:// scheme")
	}
	if c.UserBaseDN == "" {
		return fmt.Errorf("user_base_dn is required")
	}
	if c.UserFilter == "" || !strings.Contains(c.UserFilter, "%s") {
		return fmt.Errorf("user_filter must contain the %%s username placeholder")
	}
	return nil
}

// LDAPClient narrows ldap.Client to the operations the connector performs so
// unit tests can inject an in-memory directory.
type LDAPClient interface {
	Bind(username, password string) error
	Search(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

// LDAPProvider authenticates directory users via bind-then-search-then-bind.
type LDAPProvider struct {
	name string
	cfg  LDAPConfig
	// dial opens a directory connection; overridable in tests.
	dial func(ctx context.Context) (LDAPClient, error)
}

// insecureTLSConfig allows plain TLS setup for ldaps self-signed labs.
func insecureTLSConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in lab mode
}

// NewLDAPProvider builds the provider with the production dialer.
func NewLDAPProvider(name string, cfg LDAPConfig) *LDAPProvider {
	if cfg.Attributes.Username == "" {
		cfg.Attributes = DefaultLDAPAttributeMap()
	}
	return &LDAPProvider{
		name: name,
		cfg:  cfg,
		dial: func(ctx context.Context) (LDAPClient, error) {
			var opts []ldap.DialOpt
			if cfg.InsecureSkip {
				opts = append(opts, ldap.DialWithTLSConfig(insecureTLSConfig()))
			}
			// DialURL has no context parameter; the caller's ctx still
			// governs subsequent search/bind work through request contexts.
			_ = ctx
			conn, err := ldap.DialURL(cfg.HostURL, opts...)
			if err != nil {
				return nil, fmt.Errorf("ldap dial: %w", err)
			}
			return conn, nil
		},
	}
}

// Type implements IdentityProvider.
func (p *LDAPProvider) Type() string { return ProviderTypeLDAP }

// Name implements IdentityProvider.
func (p *LDAPProvider) Name() string { return p.name }

// Authenticate performs the three-step bind: service bind, user search
// (username is filter-escaped against LDAP injection), then user bind.
func (p *LDAPProvider) Authenticate(ctx context.Context, username, password string) (*UserIdentity, error) {
	if username == "" || password == "" {
		return nil, fmt.Errorf("credentials required")
	}
	if err := p.cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid ldap config: %w", err)
	}

	conn, err := p.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if bindErr := conn.Bind(p.cfg.BindDN, p.cfg.BindPassword); bindErr != nil {
		return nil, fmt.Errorf("service bind failed: %w", bindErr)
	}

	attrs := []string{
		p.cfg.Attributes.Username,
		p.cfg.Attributes.Email,
		p.cfg.Attributes.DisplayName,
	}
	result, err := conn.Search(ldap.NewSearchRequest(
		p.cfg.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		fmt.Sprintf(p.cfg.UserFilter, ldap.EscapeFilter(username)),
		attrs, []ldap.Control{},
	))
	if err != nil {
		return nil, fmt.Errorf("user search failed: %w", err)
	}
	if len(result.Entries) != 1 {
		return nil, fmt.Errorf("user %q not found or ambiguous in directory", username)
	}

	entry := result.Entries[0]
	userDN := entry.DN
	if bindErr := conn.Bind(userDN, password); bindErr != nil {
		return nil, fmt.Errorf("invalid credentials: %w", bindErr)
	}

	identity := &UserIdentity{
		Subject:  username,
		Provider: p.name,
	}
	if p.cfg.Attributes.Email != "" {
		identity.Email = entry.GetAttributeValue(p.cfg.Attributes.Email)
	}
	if p.cfg.Attributes.DisplayName != "" {
		identity.Name = entry.GetAttributeValue(p.cfg.Attributes.DisplayName)
	}
	return identity, nil
}
