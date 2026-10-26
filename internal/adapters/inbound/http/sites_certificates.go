package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/google/uuid"
)

// ensureAutoCertificate provisions a certificate record for ssl_mode "auto".
// Public DNS names are issued through ACME; local or internal hostnames get a
// managed self-signed certificate so HTTPS works without public DNS.
func (s *Server) ensureAutoCertificate(ctx context.Context, hostnames []string) error {
	existing, err := s.store.ListCertificates(ctx)
	if err != nil {
		return fmt.Errorf("list certificates: %w", err)
	}
	for _, host := range hostnames {
		clean := strings.ToLower(strings.TrimSpace(host))
		if clean == "" || clean == "*" || strings.HasPrefix(clean, "*.") {
			continue
		}
		if coveredByExisting(existing, clean) {
			continue
		}
		record, buildErr := s.autoCertificateRecord(ctx, clean, time.Now().UTC())
		if buildErr != nil {
			return buildErr
		}
		if createErr := s.store.CreateCertificate(ctx, record); createErr != nil {
			return fmt.Errorf("create auto certificate: %w", createErr)
		}
		existing = append(existing, record)
	}
	s.reloadCertificates(ctx)
	return nil
}

func coveredByExisting(records []control.CertificateRecord, host string) bool {
	for _, rec := range records {
		var domains []string
		_ = json.Unmarshal([]byte(rec.Domains), &domains)
		for _, domain := range domains {
			if strings.EqualFold(domain, host) {
				return true
			}
		}
		if rec.CertPEM != "" {
			if leaf, err := control.ParseLeafCertificate(rec.CertPEM); err == nil && control.CertificateCoversDomain(leaf, host) {
				return true
			}
		}
	}
	return false
}

func (s *Server) autoCertificateRecord(ctx context.Context, host string, now time.Time) (control.CertificateRecord, error) {
	domainsJSON, _ := json.Marshal([]string{host})
	record := control.CertificateRecord{
		ID:        "cert-" + uuid.New().String()[:8],
		Name:      host,
		Domains:   string(domainsJSON),
		AutoRenew: 1,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if !qualifiesForACMECertificate(host) {
		certPEM, keyPEM, leaf, err := control.GenerateSelfSigned([]string{host}, now)
		if err != nil {
			return control.CertificateRecord{}, err
		}
		secret, err := control.EnsureCertificateSecret(ctx, s.store)
		if err != nil {
			return control.CertificateRecord{}, err
		}
		encrypted, err := control.EncryptPrivateKey(secret, keyPEM)
		if err != nil {
			return control.CertificateRecord{}, err
		}
		record.Source = control.CertSourceSelfSigned
		record.CertPEM = certPEM
		record.EncryptedKeyPEM = encrypted
		record.FingerprintSHA256 = control.FingerprintSHA256(leaf.Raw)
		record.Issuer = leaf.Issuer.CommonName
		record.NotBefore = leaf.NotBefore
		record.NotAfter = leaf.NotAfter
		return record, nil
	}

	record.Source = control.CertSourceACME
	return record, nil
}

// qualifiesForACMECertificate filters out hostnames that public CAs cannot issue for.
func qualifiesForACMECertificate(host string) bool {
	if net.ParseIP(host) != nil {
		return false
	}
	if !strings.Contains(host, ".") {
		return false
	}
	for _, suffix := range []string{".local", ".localhost", ".internal", ".invalid", ".test", ".example", ".lan", ".home"} {
		if strings.HasSuffix(host, suffix) {
			return false
		}
	}
	return !strings.EqualFold(host, "localhost")
}
