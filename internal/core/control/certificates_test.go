package control

import (
	"strings"
	"testing"
	"time"
)

func TestGenerateSelfSignedAndCoverage(t *testing.T) {
	now := time.Now().UTC()
	certPEM, keyPEM, leaf, err := GenerateSelfSigned([]string{"app.example.com", "10.0.0.5"}, now)
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	if certPEM == "" || keyPEM == "" {
		t.Fatal("expected PEM material")
	}
	if leaf == nil || leaf.NotAfter.Before(now) {
		t.Fatalf("unexpected leaf: %+v", leaf)
	}
	if !strings.HasPrefix(certPEM, "-----BEGIN CERTIFICATE-----") {
		t.Error("certificate is not PEM encoded")
	}
	if !strings.HasPrefix(keyPEM, "-----BEGIN EC PRIVATE KEY-----") {
		t.Error("key is not an EC private key")
	}

	if _, err := ValidateCertificateKeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("generated pair does not validate: %v", err)
	}

	if !CertificateCoversDomain(leaf, "app.example.com") {
		t.Error("expected exact hostname to be covered")
	}
	if !CertificateCoversDomain(leaf, "APP.EXAMPLE.COM:443") {
		t.Error("expected case-insensitive host:port coverage")
	}
	if !CertificateCoversDomain(leaf, "10.0.0.5") {
		t.Error("expected IP SAN coverage")
	}
	if CertificateCoversDomain(leaf, "other.example.com") {
		t.Error("unexpected coverage for a different hostname")
	}
	if CertificateCoversDomain(nil, "app.example.com") {
		t.Error("nil certificate must not report coverage")
	}
}

func TestCertificateCoversWildcard(t *testing.T) {
	leaf, err := ParseLeafCertificate(mustSelfSigned(t, []string{"*.example.com"}))
	if err != nil {
		t.Fatalf("ParseLeafCertificate: %v", err)
	}
	if !CertificateCoversDomain(leaf, "api.example.com") {
		t.Error("wildcard should cover one label")
	}
	if CertificateCoversDomain(leaf, "a.b.example.com") {
		t.Error("wildcard must not cover multiple labels")
	}
	if CertificateCoversDomain(leaf, "example.com") {
		t.Error("wildcard must not cover the apex domain")
	}
}

func TestValidateCertificateKeyPairMismatch(t *testing.T) {
	certA, _, _, err := GenerateSelfSigned([]string{"a.example.com"}, time.Now())
	if err != nil {
		t.Fatalf("generate first pair: %v", err)
	}
	_, keyB, _, err := GenerateSelfSigned([]string{"b.example.com"}, time.Now())
	if err != nil {
		t.Fatalf("generate second pair: %v", err)
	}
	if _, err := ValidateCertificateKeyPair(certA, keyB); err == nil {
		t.Fatal("expected mismatched key pair to fail validation")
	}
	if _, err := ValidateCertificateKeyPair("not a pem", keyB); err == nil {
		t.Fatal("expected invalid PEM to fail validation")
	}
}

func TestCertificateFingerprint(t *testing.T) {
	certPEM := mustSelfSigned(t, []string{"fp.example.com"})
	fp := CertificateFingerprint(certPEM)
	if len(fp) != 64 {
		t.Fatalf("expected 64 hex characters, got %d (%q)", len(fp), fp)
	}
	if strings.ToLower(fp) != fp {
		t.Error("fingerprint must be lowercase")
	}
	if CertificateFingerprint("garbage") != "" {
		t.Error("invalid PEM must produce an empty fingerprint")
	}
}

func TestPrivateKeyEncryptionRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	plaintext := "-----BEGIN EC PRIVATE KEY-----\nsecret\n-----END EC PRIVATE KEY-----\n"

	sealed, err := EncryptPrivateKey(key, plaintext)
	if err != nil {
		t.Fatalf("EncryptPrivateKey: %v", err)
	}
	if strings.Contains(sealed, "secret") {
		t.Fatal("sealed key leaks plaintext")
	}

	got, err := DecryptPrivateKey(key, sealed)
	if err != nil {
		t.Fatalf("DecryptPrivateKey: %v", err)
	}
	if got != plaintext {
		t.Errorf("round trip mismatch: %q", got)
	}

	if _, err := DecryptPrivateKey([]byte("ffffffffffffffffffffffffffffffff"), sealed); err == nil {
		t.Error("expected decryption with a different key to fail")
	}
	if _, err := DecryptPrivateKey(key, "not-base64!"); err == nil {
		t.Error("expected invalid base64 to fail")
	}
}

func mustSelfSigned(t *testing.T, domains []string) string {
	t.Helper()
	certPEM, _, _, err := GenerateSelfSigned(domains, time.Now().UTC())
	if err != nil {
		t.Fatalf("GenerateSelfSigned(%v): %v", domains, err)
	}
	return certPEM
}
