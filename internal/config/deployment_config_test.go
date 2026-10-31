package config

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testHMACSecret = "0123456789abcdef0123456789abcdef"
	testPoWSecret  = "fedcba9876543210fedcba9876543210"
)

func validProductionDoc() string {
	return `
version: 1
server:
  http:
    enabled: true
    listen: ":80"
  https:
    enabled: true
    listen: ":443"
  auto_https: true
  acme:
    email: ops@example.com
control:
  hmac_secret: ` + testHMACSecret + `
  public_url: https://raiwall.example.com
  session:
    idle_timeout: 8h
    absolute_timeout: 24h
    secure: true
    allow_basic_auth: false
security:
  production_mode: true
bot:
  defense: off
`
}

func TestParseSessionDefaults(t *testing.T) {
	file, _, err := Parse([]byte("version: 1\n"), "test.yaml")
	require.NoError(t, err)
	assert.Equal(t, 8*time.Hour, time.Duration(file.Control.Session.IdleTimeout))
	assert.Equal(t, 24*time.Hour, time.Duration(file.Control.Session.AbsoluteTimeout))
	require.NotNil(t, file.Control.Session.Secure)
	assert.True(t, *file.Control.Session.Secure)
	assert.False(t, file.Control.Session.AllowBasicAuth)
	assert.False(t, file.Security.ProductionMode)
}

func TestParseProductionModeAcceptsSafeDocument(t *testing.T) {
	file, _, err := Parse([]byte(validProductionDoc()), "test.yaml")
	require.NoError(t, err)
	assert.True(t, file.Security.ProductionMode)
	assert.True(t, *file.Control.Session.Secure)
}

func TestProductionModeRejectsWeakAdminPassword(t *testing.T) {
	doc := strings.Replace(validProductionDoc(), "security:", `  bootstrap_admin:
    username: admin
    password: admin
security:`, 1)
	_, _, err := Parse([]byte(doc), "test.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bootstrap_admin.password is a weak default")
}

func TestProductionModeRejectsShortSecrets(t *testing.T) {
	doc := strings.Replace(validProductionDoc(), testHMACSecret, "short", 1)
	_, _, err := Parse([]byte(doc), "test.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "control.hmac_secret must be at least 32")
}

func TestProductionModeRejectsInsecureSessionCookie(t *testing.T) {
	doc := strings.Replace(validProductionDoc(), "secure: true", "secure: false", 1)
	_, _, err := Parse([]byte(doc), "test.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "control.session.secure must be true")
}

func TestProductionModeRejectsPlainHTTPPublicURL(t *testing.T) {
	doc := strings.Replace(validProductionDoc(), "https://raiwall.example.com", "http://raiwall.example.com", 1)
	_, _, err := Parse([]byte(doc), "test.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "control.public_url must be an https")
}

func TestProductionModeRejectsHTTPSWithoutCertificateSource(t *testing.T) {
	doc := strings.Replace(validProductionDoc(), "auto_https: true", "auto_https: false", 1)
	_, _, err := Parse([]byte(doc), "test.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no certificate source")
}

func TestProductionModeRejectsAutoHTTPSWithoutACMEEmail(t *testing.T) {
	doc := strings.Replace(validProductionDoc(), "email: ops@example.com", `email: ""`, 1)
	_, _, err := Parse([]byte(doc), "test.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server.acme.email")
}

func TestSessionIdleCannotExceedAbsolute(t *testing.T) {
	doc := strings.Replace(validProductionDoc(), "absolute_timeout: 24h", "absolute_timeout: 1h", 1)
	_, _, err := Parse([]byte(doc), "test.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session.idle_timeout")
}

func TestParseRejectsInvalidAllowedNetworks(t *testing.T) {
	doc := `
version: 1
control:
  allowed_networks: ["10.0.0.0/8", "not-a-cidr"]
`
	_, _, err := Parse([]byte(doc), "test.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "allowed_networks")
}

func TestParseRejectsInvalidPublicURL(t *testing.T) {
	doc := `
version: 1
control:
  public_url: "raiwall.example.com"
`
	_, _, err := Parse([]byte(doc), "test.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "public_url")
}

func TestProductionModeRejectsShortBootstrapPassword(t *testing.T) {
	doc := strings.Replace(validProductionDoc(), "security:", `  bootstrap_admin:
    username: admin
    password: short-pass1
security:`, 1)
	_, _, err := Parse([]byte(doc), "test.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 12 characters")
}
