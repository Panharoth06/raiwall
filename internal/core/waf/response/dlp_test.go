package response_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/Panharoth06/raiwall/internal/core/waf/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fullDLPConfig(mode, action string) response.Config {
	return response.Config{
		Enabled:        true,
		Mode:           mode,
		InspectHeaders: true,
		InspectBody:    true,
		BodyLimit:      1024 * 1024,
		HardCap:        8 * 1024 * 1024,
		DLP: response.DLPConfig{
			Enabled:           true,
			Action:            action,
			DetectPAN:         true,
			DetectSecrets:     true,
			DetectJWT:         true,
			DetectPrivateKeys: true,
			Redaction:         "[REDACTED]",
			MaxScanBytes:      1024 * 1024,
		},
	}
}

func TestDLP_Detectors(t *testing.T) {
	engine, err := response.New(fullDLPConfig("audit", "audit"))
	require.NoError(t, err)

	tests := []struct {
		name          string
		headers       http.Header
		body          string
		wantRuleID    string
		wantCategory  string
		wantFinding   bool
	}{
		{
			name:        "valid Visa PAN (Luhn passes)",
			body:        `{"card": "4111 1111 1111 1111"}`,
			wantRuleID:  "dlp_pan",
			wantCategory: "payment-card",
			wantFinding: true,
		},
		{
			name:        "invalid Visa PAN (Luhn fails)",
			body:        `{"card": "4111 1111 1111 1112"}`,
			wantFinding: false,
		},
		{
			name:        "valid Mastercard PAN (Luhn passes)",
			body:        `account 5425 2334 3010 9903 confirmed`,
			wantRuleID:  "dlp_pan",
			wantCategory: "payment-card",
			wantFinding: true,
		},
		{
			name:        "random numbers not a card",
			body:        `order numbers 1234 5678 9012 3456`,
			wantFinding: false,
		},
		{
			name:        "JWT token in body",
			body:        `{"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}`,
			wantRuleID:  "dlp_jwt",
			wantCategory: "jwt",
			wantFinding: true,
		},
		{
			name:        "RSA private key in body",
			body:        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y...\n-----END RSA PRIVATE KEY-----",
			wantRuleID:  "dlp_private_key",
			wantCategory: "private-key",
			wantFinding: true,
		},
		{
			name:        "Generic private key in body",
			body:        "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...\n-----END PRIVATE KEY-----",
			wantRuleID:  "dlp_private_key",
			wantCategory: "private-key",
			wantFinding: true,
		},
		{
			name:        "AWS Access Key ID (AKIA)",
			body:        `aws_access_key_id = AKIAIOSFODNN7EXAMPLE`,
			wantRuleID:  "dlp_cloud_key",
			wantCategory: "cloud-access-key",
			wantFinding: true,
		},
		{
			name:        "AWS Temporary Access Key ID (ASIA)",
			body:        `aws_access_key_id = ASIAIOSFODNN7EXAMPLE`,
			wantRuleID:  "dlp_cloud_key",
			wantCategory: "cloud-access-key",
			wantFinding: true,
		},
		{
			name:        "Generic secret pattern (api_key: secret)",
			body:        `{"api_key": "sec_live_987654321abcdef"}`,
			wantRuleID:  "dlp_secret",
			wantCategory: "secret",
			wantFinding: true,
		},
		{
			name:        "Generic secret pattern (password = value)",
			body:        `client_secret = "supersecretpassword123!"`,
			wantRuleID:  "dlp_secret",
			wantCategory: "secret",
			wantFinding: true,
		},
		{
			name:        "Authorization header with Bearer token",
			headers:     http.Header{"Authorization": {"Bearer secret-bearer-token-12345"}},
			wantRuleID:  "dlp_auth_header",
			wantCategory: "authorization-header",
			wantFinding: true,
		},
		{
			name:        "X-Api-Key header",
			headers:     http.Header{"X-Api-Key": {"Basic secretkey12345"}},
			wantRuleID:  "dlp_auth_header",
			wantCategory: "authorization-header",
			wantFinding: true,
		},
		{
			name:        "Benign clean response",
			headers:     http.Header{"Content-Type": {"application/json"}},
			body:        `{"status": "ok", "message": "all good", "count": 42}`,
			wantFinding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &waf.ResponseContext{
				StatusCode: 200,
				Headers:    tt.headers,
				Body:       []byte(tt.body),
				Duration:   time.Millisecond,
			}
			res := engine.Inspect(ctx)
			require.NotNil(t, res)
			if !tt.wantFinding {
				assert.Empty(t, res.Findings)
				assert.Equal(t, waf.ActionAllow, res.Verdict.Action)
				return
			}
			require.NotEmpty(t, res.Findings)
			assert.Equal(t, tt.wantRuleID, res.Findings[0].RuleID)
			assert.Equal(t, tt.wantCategory, res.Findings[0].Category)
			assert.Equal(t, waf.ActionAudit, res.Verdict.Action)
		})
	}
}

func TestDLP_Actions(t *testing.T) {
	jwtPayload := `{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgN_p_m1sPqVv9_naGsm_4h_m_g_l_r_o_c_k_s"}`

	t.Run("action audit produces audit verdict", func(t *testing.T) {
		eng, err := response.New(fullDLPConfig("audit", "audit"))
		require.NoError(t, err)

		ctx := &waf.ResponseContext{
			StatusCode: 200,
			Headers:    http.Header{"Content-Type": {"application/json"}},
			Body:       []byte(jwtPayload),
		}
		res := eng.Inspect(ctx)
		require.NotEmpty(t, res.Findings)
		assert.Equal(t, waf.ActionAudit, res.Verdict.Action)
		assert.False(t, res.Redacted)
		assert.Nil(t, res.Body)
	})

	t.Run("action block produces block verdict with 403", func(t *testing.T) {
		eng, err := response.New(fullDLPConfig("block", "block"))
		require.NoError(t, err)

		ctx := &waf.ResponseContext{
			StatusCode: 200,
			Headers:    http.Header{"Content-Type": {"application/json"}},
			Body:       []byte(jwtPayload),
		}
		res := eng.Inspect(ctx)
		require.NotEmpty(t, res.Findings)
		assert.Equal(t, waf.ActionBlock, res.Verdict.Action)
		assert.Equal(t, http.StatusForbidden, res.Verdict.StatusCode)
	})

	t.Run("action redact replaces detected secret", func(t *testing.T) {
		eng, err := response.New(fullDLPConfig("redact", "redact"))
		require.NoError(t, err)

		body := `user card is 4111 1111 1111 1111 and token is eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgN_p_m1sPqVv9_naGsm_4h_m_g_l_r_o_c_k_s and cloud key AKIAIOSFODNN7EXAMPLE`
		ctx := &waf.ResponseContext{
			StatusCode: 200,
			Headers:    http.Header{"Content-Type": {"text/plain"}},
			Body:       []byte(body),
		}
		res := eng.Inspect(ctx)
		require.NotEmpty(t, res.Findings)
		assert.True(t, res.Redacted)
		assert.NotNil(t, res.Body)
		redactedText := string(res.Body)
		assert.NotContains(t, redactedText, "4111 1111 1111 1111")
		assert.NotContains(t, redactedText, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
		assert.NotContains(t, redactedText, "AKIAIOSFODNN7EXAMPLE")
		assert.Contains(t, redactedText, "[REDACTED]")
	})

	t.Run("action redact redacts secret even if body exceeds scan limit", func(t *testing.T) {
		cfg := fullDLPConfig("redact", "redact")
		cfg.DLP.MaxScanBytes = 200
		eng, err := response.New(cfg)
		require.NoError(t, err)

		body := "card: 4111 1111 1111 1111 trailing data: " + strings.Repeat("X", 500)
		ctx := &waf.ResponseContext{
			StatusCode: 200,
			Headers:    http.Header{"Content-Type": {"text/plain"}},
			Body:       []byte(body),
		}
		res := eng.Inspect(ctx)
		assert.True(t, res.Truncated)
		require.NotEmpty(t, res.Findings)
		assert.True(t, res.Redacted, "should redact secrets found within scanned limit")
		redactedText := string(res.Body)
		assert.NotContains(t, redactedText, "4111 1111 1111 1111")
		assert.Contains(t, redactedText, "[REDACTED]")
		assert.Contains(t, redactedText, strings.Repeat("X", 500))
	})
}

func TestDLP_TruncationAndFingerprint(t *testing.T) {
	cfg := fullDLPConfig("audit", "audit")
	cfg.DLP.MaxScanBytes = 100 // small limit for truncation testing

	eng, err := response.New(cfg)
	require.NoError(t, err)

	largeBody := strings.Repeat("A", 200) + " AKIAIOSFODNN7EXAMPLE"
	ctx := &waf.ResponseContext{
		StatusCode: 200,
		Body:       []byte(largeBody),
	}
	res := eng.Inspect(ctx)
	assert.True(t, res.Truncated)
	// Key was beyond 100 bytes limit, so it should not be found
	assert.Empty(t, res.Findings)

	// Fingerprint test
	fp1 := cfg.Fingerprint()
	assert.NotEmpty(t, fp1)

	cfg2 := cfg
	cfg2.DLP.DetectPAN = false
	fp2 := cfg2.Fingerprint()
	assert.NotEqual(t, fp1, fp2)
}
