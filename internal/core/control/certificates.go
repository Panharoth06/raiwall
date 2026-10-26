package control

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// SelfSignedValidity is the lifetime of generated self-signed certificates.
const SelfSignedValidity = 90 * 24 * time.Hour

// ParseLeafCertificate decodes the first PEM certificate block.
func ParseLeafCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no PEM certificate block found")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return leaf, nil
}

// ValidateCertificateKeyPair ensures the certificate and private key form a
// valid pair and returns the parsed leaf certificate.
func ValidateCertificateKeyPair(certPEM, keyPEM string) (*x509.Certificate, error) {
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("certificate and private key do not match: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate: %w", err)
	}
	return leaf, nil
}

// GenerateSelfSigned creates a self-signed ECDSA certificate for the domains.
func GenerateSelfSigned(domains []string, now time.Time) (certPEM, keyPEM string, leaf *x509.Certificate, err error) {
	if len(domains) == 0 {
		return "", "", nil, fmt.Errorf("at least one domain is required")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", nil, fmt.Errorf("generate private key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", "", nil, fmt.Errorf("generate serial number: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: domains[0], Organization: []string{"Raiwall Self-Signed"}},
		NotBefore:             now.Add(-5 * time.Minute).UTC(),
		NotAfter:              now.Add(SelfSignedValidity).UTC(),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              make([]string, 0, len(domains)),
	}
	for _, domain := range domains {
		clean := strings.TrimSpace(domain)
		if clean == "" {
			continue
		}
		if ip := net.ParseIP(clean); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			continue
		}
		tmpl.DNSNames = append(tmpl.DNSNames, clean)
	}
	if len(tmpl.DNSNames) == 0 && len(tmpl.IPAddresses) == 0 {
		return "", "", nil, fmt.Errorf("no usable domains provided")
	}
	if len(tmpl.DNSNames) > 0 {
		tmpl.Subject.CommonName = tmpl.DNSNames[0]
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", nil, fmt.Errorf("create certificate: %w", err)
	}
	leaf, err = x509.ParseCertificate(der)
	if err != nil {
		return "", "", nil, fmt.Errorf("parse generated certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", nil, fmt.Errorf("marshal private key: %w", err)
	}

	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM, leaf, nil
}

// CertificateCoversDomain reports whether the leaf is valid for the hostname,
// honoring wildcard SANs and IP SANs.
func CertificateCoversDomain(leaf *x509.Certificate, domain string) bool {
	if leaf == nil {
		return false
	}
	host := strings.ToLower(strings.TrimSpace(domain))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, candidate := range leaf.IPAddresses {
			if ip.Equal(candidate) {
				return true
			}
		}
		return false
	}
	for _, name := range leaf.DNSNames {
		candidate := strings.ToLower(strings.TrimSpace(name))
		if candidate == host {
			return true
		}
		if strings.HasPrefix(candidate, "*.") {
			suffix := candidate[1:] // ".example.com"
			if strings.HasSuffix(host, suffix) {
				prefix := strings.TrimSuffix(host, suffix)
				if prefix != "" && !strings.Contains(prefix, ".") {
					return true
				}
			}
		}
	}
	return false
}

// FingerprintSHA256 returns the lowercase hex SHA-256 fingerprint of a DER certificate.
func FingerprintSHA256(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// CertificateFingerprint returns the SHA-256 fingerprint of a PEM certificate.
func CertificateFingerprint(certPEM string) string {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return ""
	}
	return FingerprintSHA256(block.Bytes)
}
