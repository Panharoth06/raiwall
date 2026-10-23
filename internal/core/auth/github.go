package auth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GitHubConfig configures the GitHub OAuth2 application connector.
type GitHubConfig struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURL  string `json:"redirect_url"`
	// APIBase overrides the GitHub endpoints; set for GitHub Enterprise
	// Server or unit tests against an httptest backend.
	AuthBase string `json:"auth_base,omitempty"` // default https://github.com
	APIBase  string `json:"api_base,omitempty"`  // default https://api.github.com
	// InsecureSkip disables TLS verification for self-hosted enterprise labs.
	InsecureSkip bool `json:"insecure_skip,omitempty"`
}

const (
	githubDefaultAuthBase = "https://github.com"
	githubDefaultAPIBase  = "https://api.github.com"
	githubRequestTimeout  = 10 * time.Second
)

// GitHubProvider implements the redirect-flow GitHub connector.
type GitHubProvider struct {
	name     string
	cfg      GitHubConfig
	http     *http.Client
	tokenURL string
}

// NewGitHubProvider builds the connector with sensible endpoint defaults.
func NewGitHubProvider(name string, cfg GitHubConfig) *GitHubProvider {
	if cfg.AuthBase == "" {
		cfg.AuthBase = githubDefaultAuthBase
	}
	if cfg.APIBase == "" {
		cfg.APIBase = githubDefaultAPIBase
	}
	transport := http.DefaultTransport
	if cfg.InsecureSkip {
		// Clone and relax for self-hosted enterprise servers only.
		if t, ok := http.DefaultTransport.(*http.Transport); ok {
			t = t.Clone()
			t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in lab mode
			transport = t
		}
	}
	return &GitHubProvider{
		name:     name,
		cfg:      cfg,
		http:     &http.Client{Transport: transport, Timeout: githubRequestTimeout},
		tokenURL: cfg.AuthBase + "/login/oauth/access_token",
	}
}

// Type implements IdentityProvider.
func (p *GitHubProvider) Type() string { return ProviderTypeGitHub }

// Name implements IdentityProvider.
func (p *GitHubProvider) Name() string { return p.name }

// Authenticate implements the password half of IdentityProvider; GitHub
// identities only arrive through the redirect flow.
func (p *GitHubProvider) Authenticate(context.Context, string, string) (*UserIdentity, error) {
	return nil, errCodeFlowUnsupported
}

// AuthCodeURL implements CodeIdentityProvider.
func (p *GitHubProvider) AuthCodeURL(state string) string {
	q := url.Values{}
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", p.cfg.RedirectURL)
	q.Set("state", state)
	q.Set("scope", "read:user user:email")
	return p.cfg.AuthBase + "/login/oauth/authorize?" + q.Encode()
}

// githubTokenResponse is the access-token grant.
type githubTokenResponse struct {
	AccessToken      string `json:"access_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// githubUser is the subset of /user read for identity claims.
type githubUser struct {
	Login string `json:"login"`
	Name  string `json:"name"`
	Email string `json:"email"`
	ID    int64  `json:"id"`
}

// ExchangeCode implements CodeIdentityProvider: code -> access token ->
// verified user profile (and primary verified email when email is private).
func (p *GitHubProvider) ExchangeCode(ctx context.Context, code string) (*UserIdentity, error) {
	if strings.TrimSpace(code) == "" {
		return nil, fmt.Errorf("authorization code is required")
	}

	token, err := p.exchangeToken(ctx, code)
	if err != nil {
		return nil, err
	}

	user, err := p.fetchUser(ctx, token)
	if err != nil {
		return nil, err
	}
	if user.Login == "" {
		return nil, fmt.Errorf("github returned no user login; token scope may be insufficient")
	}

	email := user.Email
	if email == "" {
		email = p.fetchPrimaryEmail(ctx, token)
	}

	return &UserIdentity{
		Subject:  fmt.Sprintf("github:%d:%s", user.ID, user.Login),
		Email:    email,
		Name:     firstNonEmpty(user.Name, user.Login),
		Provider: p.name,
	}, nil
}

func (p *GitHubProvider) exchangeToken(ctx context.Context, code string) (string, error) {
	form := url.Values{}
	form.Set("client_id", p.cfg.ClientID)
	form.Set("client_secret", p.cfg.ClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", p.cfg.RedirectURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("token exchange returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var grant githubTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&grant); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if grant.Error != "" {
		return "", fmt.Errorf("token grant rejected: %s: %s", grant.Error, grant.ErrorDescription)
	}
	if grant.AccessToken == "" {
		return "", fmt.Errorf("token grant returned no access token")
	}
	return grant.AccessToken, nil
}

func (p *GitHubProvider) fetchUser(ctx context.Context, token string) (*githubUser, error) {
	raw, status, err := p.getJSON(ctx, token, p.cfg.APIBase+"/user")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("fetch github user returned HTTP %d", status)
	}
	var user githubUser
	if err := json.Unmarshal(raw, &user); err != nil {
		return nil, fmt.Errorf("decode github user: %w", err)
	}
	return &user, nil
}

// fetchPrimaryEmail resolves the primary verified address for private profiles.
func (p *GitHubProvider) fetchPrimaryEmail(ctx context.Context, token string) string {
	type ghEmail struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	raw, status, err := p.getJSON(ctx, token, p.cfg.APIBase+"/user/emails")
	if err != nil || status != http.StatusOK {
		return ""
	}
	var emails []ghEmail
	if jsonErr := json.Unmarshal(raw, &emails); jsonErr != nil {
		return ""
	}
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email
		}
	}
	return ""
}

// getJSON issues an authenticated GET and returns the raw body.
func (p *GitHubProvider) getJSON(ctx context.Context, token, endpoint string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := p.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("github api request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if readErr != nil {
		return nil, resp.StatusCode, fmt.Errorf("read github response: %w", readErr)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, nil // caller renders the status
	}
	return raw, resp.StatusCode, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
