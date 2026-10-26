package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMinimalAppliesDefaults(t *testing.T) {
	file, warnings, err := Parse([]byte("version: 1\n"), "test.yaml")
	require.NoError(t, err)
	assert.Empty(t, warnings)

	assert.Equal(t, ":8080", file.Server.HTTP.Listen)
	assert.Equal(t, ":8443", file.Server.HTTPS.Listen)
	assert.Equal(t, "off", file.Caddy.Admin.Listen)
	assert.Equal(t, "defense", file.WAF.Mode)
	assert.Equal(t, 5_000_000, int(file.WAF.ASTTimeout))
	assert.Equal(t, 32768, file.WAF.MaxParamSize)
	assert.Equal(t, "admin", file.Control.BootstrapAdmin.Username)
	assert.Equal(t, "off", file.Declarative.Mode)
	assert.Contains(t, file.Storage.Stores, "control")
	assert.Equal(t, "control", file.Storage.Control)
}

func TestParseEnvInterpolation(t *testing.T) {
	t.Setenv("RW_TEST_DSN", "postgres://user:pass@db:5432/raiwall")
	t.Setenv("RW_TEST_SECRET", "s3cret")

	doc := `
version: 1
storage:
  database_url: ${RW_TEST_DSN}
control:
  hmac_secret: ${RW_TEST_SECRET}
`
	file, warnings, err := Parse([]byte(doc), "test.yaml")
	require.NoError(t, err)
	assert.Empty(t, warnings)
	assert.Equal(t, "postgres://user:pass@db:5432/raiwall", file.Storage.DatabaseURL)
	assert.Equal(t, "postgres", file.Storage.Stores["default"].Driver)
	assert.Equal(t, "s3cret", file.Control.HMACSecret)
}

func TestParseMissingRequiredEnv(t *testing.T) {
	doc := `
version: 1
storage:
  database_url: ${RW_ABSENT_VAR:?database DSN is required}
`
	_, _, err := Parse([]byte(doc), "test.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database DSN is required")
}

func TestParseEnvDefault(t *testing.T) {
	doc := `
version: 1
storage:
  database_url: ${RW_ABSENT_VAR:-file:/tmp/fallback.db}
`
	file, _, err := Parse([]byte(doc), "test.yaml")
	require.NoError(t, err)
	assert.Equal(t, "file:/tmp/fallback.db", file.Storage.DatabaseURL)
}

func TestParseEnvFileIndirection(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(secretPath, []byte("from-file\n"), 0o600))
	t.Setenv("RW_FILE_SECRET_FILE", secretPath)

	doc := `
version: 1
control:
  hmac_secret: ${RW_FILE_SECRET}
`
	file, _, err := Parse([]byte(doc), "test.yaml")
	require.NoError(t, err)
	assert.Equal(t, "from-file", file.Control.HMACSecret)
}

func TestParseRejectsUnknownKey(t *testing.T) {
	_, _, err := Parse([]byte("version: 1\nnot_a_real_key: true\n"), "test.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not_a_real_key")
}

func TestParseWarnsOnInlineSecrets(t *testing.T) {
	doc := `
version: 1
control:
  hmac_secret: plain-text-secret
`
	_, warnings, err := Parse([]byte(doc), "test.yaml")
	require.NoError(t, err)
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "control.hmac_secret")
}

func TestParseStrictSecretsRejectsInline(t *testing.T) {
	doc := `
version: 1
security:
  strict_secrets: true
control:
  hmac_secret: plain-text-secret
`
	_, _, err := Parse([]byte(doc), "test.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "strict_secrets")
}

func TestParseRejectsDuplicateHostnames(t *testing.T) {
	doc := `
version: 1
applications:
  - name: a
    hostnames: [example.com]
    upstreams: [{dial: "127.0.0.1:9001"}]
  - name: b
    hostnames: [example.com]
    upstreams: [{dial: "127.0.0.1:9002"}]
`
	_, _, err := Parse([]byte(doc), "test.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already declared")
}

func TestParseRejectsBadDuration(t *testing.T) {
	_, _, err := Parse([]byte("version: 1\nwaf:\n  ast_timeout: fast\n"), "test.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid duration")
}

func TestParseUnknownFieldInNestedBlock(t *testing.T) {
	_, _, err := Parse([]byte("version: 1\nwaf:\n  mode: defense\n  typo: true\n"), "test.yaml")
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "typo"))
}

func TestParseDeclarativeDefaultsToSyncWhenResourcesPresent(t *testing.T) {
	doc := `
version: 1
acls:
  - name: block_bad
    expression: "client_ip == '10.0.0.1'"
`
	file, _, err := Parse([]byte(doc), "test.yaml")
	require.NoError(t, err)
	assert.Equal(t, "sync", file.Declarative.Mode)
}

func TestEnvOverridesBeatFile(t *testing.T) {
	t.Setenv("RAIWALL_HTTP_LISTEN", ":9090")
	t.Setenv("RAIWALL_DATABASE_URL", "postgres://user:pass@db:5432/raiwall")
	t.Setenv("RAIWALL_ADMIN_PASSWORD", "from-env")
	t.Setenv("RAIWALL_HMAC_SECRET", "env-hmac-secret")

	doc := `
version: 1
server:
  http:
    listen: ":8080"
`
	file, warnings, err := Parse([]byte(doc), "test.yaml")
	require.NoError(t, err)
	assert.Empty(t, warnings)

	assert.Equal(t, ":9090", file.Server.HTTP.Listen)
	assert.Equal(t, "from-env", file.Control.BootstrapAdmin.Password)
	assert.Equal(t, "env-hmac-secret", file.Control.HMACSecret)
	store := file.Storage.Stores[file.Storage.Control]
	assert.Equal(t, "postgres", store.Driver)
	assert.Equal(t, "postgres://user:pass@db:5432/raiwall", store.DSN)
}

func TestDiscoverPathHonoursExplicit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.yaml")
	require.NoError(t, os.WriteFile(path, []byte("version: 1\n"), 0o600))

	got, err := DiscoverPath(path)
	require.NoError(t, err)
	assert.Equal(t, path, got)
}

func TestDiscoverPathFailsWhenNothing(t *testing.T) {
	t.Setenv("RAIWALL_CONFIG", "")
	cwd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(t.TempDir()))
	t.Cleanup(func() { _ = os.Chdir(cwd) })

	_, err = DiscoverPath("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no configuration file found")
}
