package auth

import (
	"context"
	"fmt"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/require"
)

// fakeDirectory is an in-memory Active Directory stand-in.
type fakeDirectory struct {
	users map[string]*fakeDirUser // by bind DN
	// serviceUID is the only DN accepted for the service bind.
	serviceUID string
	// searchBase must match the configured UserBaseDN.
	searchBase string
}

type fakeDirUser struct {
	dn       string
	username string
	email    string
	display  string
	password string
}

func (f *fakeDirectory) Bind(dn, password string) error {
	if dn == fmt.Sprintf("cn=%s,ou=service,%s", f.serviceUID, f.searchBase) {
		if password == "service-secret" {
			return nil
		}
		return fmt.Errorf("ldap: invalid service credentials")
	}
	for _, u := range f.users {
		if u.dn == dn {
			if u.password == password {
				return nil
			}
			return fmt.Errorf("ldap: invalid user credentials for %s", dn)
		}
	}
	return fmt.Errorf("ldap: unknown DN %s", dn)
}

func (f *fakeDirectory) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if req.BaseDN != f.searchBase {
		return nil, fmt.Errorf("ldap: wrong search base %s", req.BaseDN)
	}
	// Extract (sAMAccountName=<value>) from the filter.
	if !strings.Contains(req.Filter, "=") {
		return nil, fmt.Errorf("ldap: malformed filter %q", req.Filter)
	}
	value := req.Filter[strings.LastIndex(req.Filter, "=")+1 : len(req.Filter)-1]
	for _, u := range f.users {
		if u.username == value {
			return &ldap.SearchResult{
				Entries: []*ldap.Entry{{
					DN: u.dn,
					Attributes: []*ldap.EntryAttribute{
						{Name: "uid", Values: []string{u.username}},
						{Name: "mail", Values: []string{u.email}},
						{Name: "displayName", Values: []string{u.display}},
					},
				}},
			}, nil
		}
	}
	return &ldap.SearchResult{Entries: nil}, nil
}

func (f *fakeDirectory) Close() error { return nil }

func newFakeProvider(t *testing.T) (*LDAPProvider, *fakeDirectory) {
	t.Helper()
	base := "ou=people,dc=corp,dc=example"
	dir := &fakeDirectory{
		users: map[string]*fakeDirUser{
			"uid=walter,cn=ops": {dn: "uid=walter,cn=ops", username: "walter",
				email: "walter@corp.example", display: "Walter Ops", password: "Secret123!"},
		},
		serviceUID: "svc-raiwall",
		searchBase: base,
	}
	prov := NewLDAPProvider("corp-ad", LDAPConfig{
		HostURL:      "ldap://dc.corp.example:389",
		BindDN:       "cn=svc-raiwall,ou=service,ou=people,dc=corp,dc=example",
		BindPassword: "service-secret",
		UserBaseDN:   base,
		UserFilter:   "(uid=%s)",
	})
	prov.dial = func(context.Context) (LDAPClient, error) { return dir, nil }
	return prov, dir
}

func TestLDAPProvider_Authenticate(t *testing.T) {
	prov, _ := newFakeProvider(t)

	identity, err := prov.Authenticate(context.Background(), "walter", "Secret123!")
	require.NoError(t, err)
	require.NotNil(t, identity)
	require.Equal(t, "walter", identity.Subject)
	require.Equal(t, "walter@corp.example", identity.Email)
	require.Equal(t, "Walter Ops", identity.Name)
	require.Equal(t, "corp-ad", identity.Provider)
	require.Equal(t, ProviderTypeLDAP, prov.Type())
}

func TestLDAPProvider_BadPassword(t *testing.T) {
	prov, _ := newFakeProvider(t)

	identity, err := prov.Authenticate(context.Background(), "walter", "wrong")
	require.Error(t, err)
	require.Nil(t, identity)
	require.Contains(t, err.Error(), "invalid credentials")
}

func TestLDAPProvider_UserNotFound(t *testing.T) {
	prov, _ := newFakeProvider(t)

	identity, err := prov.Authenticate(context.Background(), "ghost", "whatever")
	require.Error(t, err)
	require.Nil(t, identity)
	require.Contains(t, err.Error(), "not found")
}

func TestLDAPProvider_ConfigTemplateFailsWhenDNMissing(t *testing.T) {
	prov, _ := newFakeProvider(t)
	empty := prov
	// A zero-value config can never bind; assert the failure path explicitly.
	empty.cfg = LDAPConfig{HostURL: "ldap://dc:389", UserFilter: "(uid=%s)", UserBaseDN: ""}
	_, err := empty.Authenticate(context.Background(), "walter", "Secret123!")
	require.Error(t, err)
	require.Contains(t, err.Error(), "user_base_dn")
}

func TestNewLDAPProvider_DefaultAttributes(t *testing.T) {
	prov := NewLDAPProvider("corp-ad", LDAPConfig{HostURL: "ldap://x:389", UserFilter: "(uid=%s)", UserBaseDN: "dc=x"})
	require.Equal(t, "sAMAccountName", prov.cfg.Attributes.Username)
	require.Equal(t, "mail", prov.cfg.Attributes.Email)
	require.Equal(t, "displayName", prov.cfg.Attributes.DisplayName)
}

func TestNewLDAPProvider_InjectionEscape(t *testing.T) {
	// ldap.EscapeFilter hex-escapes metacharacters so a username ending in ")"
	// cannot close the group early ("(uid=%s)" stays a balanced filter).
	require.Equal(t, `walter\2a\28`, ldap.EscapeFilter(`walter*(`))
}
