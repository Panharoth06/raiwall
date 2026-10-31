package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRedisClusterSettings(t *testing.T) {
	t.Setenv("RW_REDIS_PASS", "hunter2")

	doc := `
version: 1
rate_limit:
  storage: redis
  storage_addr: "127.0.0.1:6379"
  redis_username: raiwall
  redis_password: ${RW_REDIS_PASS}
  redis_tls: true
  redis_tls_server_name: redis.internal
  redis_tls_ca_file: /etc/ssl/redis-ca.pem
  cluster_channel: raiwall:test
`
	file, warnings, err := Parse([]byte(doc), "test.yaml")
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.NotNil(t, file.RateLimit)
	assert.Equal(t, "raiwall", file.RateLimit.RedisUsername)
	assert.Equal(t, "hunter2", file.RateLimit.RedisPassword)
	assert.True(t, file.RateLimit.RedisTLS)
	assert.Equal(t, "redis.internal", file.RateLimit.RedisTLSServerName)
	assert.Equal(t, "/etc/ssl/redis-ca.pem", file.RateLimit.RedisTLSCAFile)
	assert.False(t, file.RateLimit.RedisTLSInsecureSkipVerify)
	assert.Equal(t, "raiwall:test", file.RateLimit.ClusterChannel)
}

func TestValidateRedisUsernameRequiresPassword(t *testing.T) {
	doc := `
version: 1
rate_limit:
  storage: redis
  storage_addr: "127.0.0.1:6379"
  redis_username: raiwall
`
	_, _, err := Parse([]byte(doc), "test.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redis_username requires redis_password")
}

func TestValidateRedisTLSOptionsRequireTLS(t *testing.T) {
	doc := `
version: 1
rate_limit:
  storage: redis
  storage_addr: "127.0.0.1:6379"
  redis_tls_ca_file: /etc/ssl/redis-ca.pem
`
	_, _, err := Parse([]byte(doc), "test.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redis_tls must be enabled")
}
