package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGitHubProvider_ExchangeCode drives the full OAuth2 dance against an
// httptest backend: code -> access token -> verified profile (+ primary email).
func TestGitHubProvider_ExchangeCode(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "application/json", r.Header.Get("Accept"))
		require.Equal(t, "test-code", r.FormValue("code"))
		require.Equal(t, "cid", r.FormValue("client_id"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"gho_test"}`))
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer gho_test", r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"login":"walter","name":"Walter Ops","id":4041,"email":""}`))
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[
			{"email":"alias@corp.example","primary":false,"verified":true},
			{"email":"walter@corp.example","primary":true,"verified":true}
		]`))
	})
	api := httptest.NewServer(mux)
	defer api.Close()

	prov := NewGitHubProvider("github-dirsso", GitHubConfig{
		ClientID:     "cid",
		ClientSecret: "csecret",
		RedirectURL:  "https://waf.corp.example/.raiwall/auth/callback",
		AuthBase:     api.URL,
		APIBase:      api.URL,
	})

	// Auth code URL carries the client identity and CSRF state.
	authURL := prov.AuthCodeURL("state-token")
	require.Contains(t, authURL, "/login/oauth/authorize?")
	require.Contains(t, authURL, "client_id=cid")
	require.Contains(t, authURL, "state=state-token")

	identity, err := prov.ExchangeCode(context.Background(), "test-code")
	require.NoError(t, err)
	require.NotNil(t, identity)
	require.Equal(t, "github:4041:walter", identity.Subject)
	require.Equal(t, "walter@corp.example", identity.Email, "private profiles resolve via the primary verified email")
	require.Equal(t, "Walter Ops", identity.Name)
	require.Equal(t, "github-dirsso", identity.Provider)
	require.Equal(t, ProviderTypeGitHub, prov.Type())
}

func TestGitHubProvider_PublicEmailSkipsEmailsLookup(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"gho_pub"}`))
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"login":"jesse","name":"Jesse","id":17,"email":"jesse@corp.example"}`))
	})
	api := httptest.NewServer(mux)
	defer api.Close()

	prov := NewGitHubProvider("gh", GitHubConfig{AuthBase: api.URL, APIBase: api.URL})
	identity, err := prov.ExchangeCode(context.Background(), "code")
	require.NoError(t, err)
	require.Equal(t, "jesse@corp.example", identity.Email)
	require.Equal(t, "Jesse", identity.Name)
}

func TestGitHubProvider_Rejects(t *testing.T) {
	// Token grant error path.
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"bad_verification_code","error_description":"expired"}`))
	})
	api := httptest.NewServer(mux)
	defer api.Close()

	prov := NewGitHubProvider("gh", GitHubConfig{AuthBase: api.URL, APIBase: api.URL})

	_, err := prov.ExchangeCode(context.Background(), "expired-code")
	require.Error(t, err)
	require.Contains(t, err.Error(), "bad_verification_code")

	// Empty code fails before any network traffic.
	_, err = prov.ExchangeCode(context.Background(), " ")
	require.Error(t, err)
	require.Contains(t, err.Error(), "required")

	// Password path is not supported for redirect flows.
	_, err = prov.Authenticate(context.Background(), "walter", "pw")
	require.Error(t, err)
	require.Contains(t, err.Error(), "authorization-code flow")
}

func TestNewIdentityProvider_Factory(t *testing.T) {
	sa := NewSimpleAuth()

	// Unknown type rejected.
	_, err := NewIdentityProvider(IdentityProviderSpec{Type: "saml", Name: "x"}, sa)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported provider type")

	// LDAP spec parses and registers the expected type.
	p1, err := NewIdentityProvider(IdentityProviderSpec{
		Type: ProviderTypeLDAP, Name: "corp-ad",
		ConfigJSON: `{"host_url":"ldap://dc:389","user_base_dn":"dc=x","user_filter":"(uid=%s)"}`,
	}, sa)
	require.NoError(t, err)
	require.Equal(t, ProviderTypeLDAP, p1.Type())

	// GitHub spec parses or errors cleanly on malformed JSON.
	_, err = NewIdentityProvider(IdentityProviderSpec{
		Type: ProviderTypeGitHub, Name: "gh", ConfigJSON: `{invalid`,
	}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "parse github config")

	// Simple requires the local adapter.
	_, err = NewIdentityProvider(IdentityProviderSpec{Type: ProviderTypeSimple, Name: "local"}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "requires the local directory")

	// Broken LDAP config surfaces validation errors at save time.
	_, err = NewIdentityProvider(IdentityProviderSpec{
		Type: ProviderTypeLDAP, Name: "corp", ConfigJSON: `{"host_url":"dc-only-no-scheme"}`,
	}, sa)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid ldap config")
}
