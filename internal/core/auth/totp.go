package auth

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTP defaults for the identity directory 2FA factor.
const (
	TOTPIssuer        = "Raiwall"
	TOTPCodeDigits    = 6
	TOTPValidateSkew  = 1 // ±1 period of drift tolerance
	TOTPPeriodSeconds = 30
)

// GenerateTOTPSecret creates a fresh base32 TOTP secret and its provisioning
// URI for authenticator-app enrollment.
func GenerateTOTPSecret(issuer, accountName string) (secret string, provisioningURI string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		Period:      TOTPPeriodSeconds,
		Digits:      otp.Digits(TOTPCodeDigits),
	})
	if err != nil {
		return "", "", fmt.Errorf("generate totp secret: %w", err)
	}
	return key.Secret(), key.URL(), nil
}

// VerifyTOTPCode validates a 6-digit code against the stored base32 secret
// with ±1 period skew so slow hand-offs still authenticate.
func VerifyTOTPCode(secret, code string) (bool, error) {
	if strings.TrimSpace(secret) == "" {
		return false, fmt.Errorf("totp secret is empty")
	}
	if strings.TrimSpace(code) == "" {
		return false, fmt.Errorf("totp code is empty")
	}
	return totp.ValidateCustom(strings.TrimSpace(code), secret, time.Now(), totp.ValidateOpts{
		Period:    TOTPPeriodSeconds,
		Skew:      TOTPValidateSkew,
		Digits:    otp.Digits(TOTPCodeDigits),
		Algorithm: otp.AlgorithmSHA1,
	})
}

// TOTPProvisionURI rebuilds the otpauth:// provisioning URI from parts
// (used when the URI is needed after storing just the secret).
func TOTPProvisionURI(issuer, accountName, secret string) string {
	u := url.URL{}
	u.Scheme = "otpauth"
	u.Host = "totp"
	u.Path = "/" + issuer + ":" + accountName
	q := u.Query()
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", TOTPCodeDigits))
	q.Set("period", fmt.Sprintf("%d", TOTPPeriodSeconds))
	u.RawQuery = q.Encode()
	return u.String()
}
