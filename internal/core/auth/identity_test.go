package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

func TestGenerateTOTPSecret(t *testing.T) {
	secret, uri, err := GenerateTOTPSecret(TOTPIssuer, "walter@corp.example")
	require.NoError(t, err)
	require.NotEmpty(t, secret)
	require.NotEmpty(t, uri)
	require.Contains(t, uri, "otpauth://totp")
	require.Contains(t, uri, "issuer=Raiwall")
	require.Contains(t, uri, "Raiwall:walter@corp.example")
	require.Contains(t, uri, "secret="+secret)

	// Secrets are unique per generation.
	secret2, _, err := GenerateTOTPSecret(TOTPIssuer, "walter@corp.example")
	require.NoError(t, err)
	require.NotEqual(t, secret, secret2)
}

func TestVerifyTOTPCode_Cycle(t *testing.T) {
	secret, _, err := GenerateTOTPSecret(TOTPIssuer, "ops@corp.example")
	require.NoError(t, err)

	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	ok, err := VerifyTOTPCode(secret, code)
	require.NoError(t, err)
	require.True(t, ok, "freshly generated code must validate against its secret")
}

func TestVerifyTOTPCode_Rejects(t *testing.T) {
	secret, _, err := GenerateTOTPSecret(TOTPIssuer, "ops@corp.example")
	require.NoError(t, err)

	// Wrong-length garbage must not validate.
	ok, err := VerifyTOTPCode(secret, "00000")
	require.False(t, ok, "short garbage codes must reject")
	_ = err // the library may surface a digits-format error

	// Empty inputs fail closed.
	ok, err = VerifyTOTPCode(secret, "")
	require.Error(t, err)
	require.False(t, ok)

	ok, err = VerifyTOTPCode("", "123456")
	require.Error(t, err)
	require.False(t, ok)
}

func TestVerifyTOTPCode_SkewCap(t *testing.T) {
	secret, _, err := GenerateTOTPSecret(TOTPIssuer, "ops@corp.example")
	require.NoError(t, err)

	// A code from 10 minutes ago is far outside ±1 period; must be rejected.
	staleCode, genErr := totp.GenerateCode(secret, time.Now().Add(-10*time.Minute))
	require.NoError(t, genErr)

	ok, verifyErr := VerifyTOTPCode(secret, staleCode)
	require.NoError(t, verifyErr)
	require.False(t, ok, "codes older than one period must be rejected")
}

func TestTOTPProvisionURI(t *testing.T) {
	uri := TOTPProvisionURI(TOTPIssuer, "ops@corp.example", "JBSWY3DPEHPK3PXP")
	require.True(t, strings.HasPrefix(uri, "otpauth://totp/Raiwall:ops@corp.example?"))
	require.Contains(t, uri, "secret=JBSWY3DPEHPK3PXP")
	require.Contains(t, uri, "digits=6")
	require.Contains(t, uri, "period=30")
}

func TestDirectoryLogin_Flow(t *testing.T) {
	hash, err := HashPassword("SuperSecret123!")
	require.NoError(t, err)
	secret, _, err := GenerateTOTPSecret(TOTPIssuer, "ops@corp.example")
	require.NoError(t, err)
	code, genErr := totp.GenerateCode(secret, time.Now())
	require.NoError(t, genErr)

	tests := []struct {
		name    string
		login   DirectoryLogin
		pw      string
		code    string
		wantErr string
	}{
		{
			name:  "plain account, correct password",
			login: DirectoryLogin{PasswordHash: hash, Enabled: true},
			pw:    "SuperSecret123!",
		},
		{
			name:    "plain account, wrong password",
			login:   DirectoryLogin{PasswordHash: hash, Enabled: true},
			pw:      "nope",
			wantErr: "invalid username or password",
		},
		{
			name:    "disabled account never authenticates",
			login:   DirectoryLogin{PasswordHash: hash, Enabled: false},
			pw:      "SuperSecret123!",
			wantErr: "account is disabled",
		},
		{
			name:  "enrolled account with valid totp",
			login: DirectoryLogin{PasswordHash: hash, TOTPSecret: secret, TOTPEnrolled: true, Enabled: true},
			pw:    "SuperSecret123!",
			code:  code,
		},
		{
			name:    "enrolled account missing code fails closed",
			login:   DirectoryLogin{PasswordHash: hash, TOTPSecret: secret, TOTPEnrolled: true, Enabled: true},
			pw:      "SuperSecret123!",
			code:    "",
			wantErr: "totp",
		},
		{
			name:    "enrolled account with wrong code fails closed",
			login:   DirectoryLogin{PasswordHash: hash, TOTPSecret: secret, TOTPEnrolled: true, Enabled: true},
			pw:      "SuperSecret123!",
			code:    "000000",
			wantErr: "invalid totp code",
		},
		{
			name:    "enrolled-but-secretless account fails closed",
			login:   DirectoryLogin{PasswordHash: hash, TOTPSecret: "", TOTPEnrolled: true, Enabled: true},
			pw:      "SuperSecret123!",
			code:    "123456",
			wantErr: "secret is missing",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.login.Authenticate(tc.pw, tc.code)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErr)
		})
	}
}
