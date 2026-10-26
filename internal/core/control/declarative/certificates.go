package declarative

import (
	"crypto/x509"
	"encoding/json"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/config"
	"github.com/Panharoth06/raiwall/internal/core/control"
)

// syncCertificates materializes declared TLS certificates. Private keys are
// encrypted with the store-wide certificate secret before persistence.
func (s *syncer) syncCertificates(certs []config.Certificate) error {
	existing, err := s.store.ListCertificates(s.ctx)
	if err != nil {
		return err
	}
	byID := make(map[string]control.CertificateRecord, len(existing))
	byName := make(map[string]control.CertificateRecord, len(existing))
	ids := make([]string, 0, len(existing))
	for _, rec := range existing {
		byID[rec.ID] = rec
		byName[rec.Name] = rec
		ids = append(ids, rec.ID)
	}

	declared := make(map[string]struct{}, len(certs))
	var secret []byte
	for _, cert := range certs {
		id := namedID(KindCertificate, cert.Name)
		declared[id] = struct{}{}

		prev, exists := byID[id]
		if !exists {
			if other, taken := byName[cert.Name]; taken && !IsManaged(other.ID) {
				if err := s.conflict("certificate", cert.Name); err != nil {
					return err
				}
				continue
			}
		}
		if exists && !s.canWrite(true) {
			continue
		}

		if secret == nil && needsKeyMaterial(cert) {
			secret, err = control.EnsureCertificateSecret(s.ctx, s.store)
			if err != nil {
				if ferr := s.handle("certificate", cert.Name, err); ferr != nil {
					return ferr
				}
				continue
			}
		}

		rec, change, err := buildCertificate(cert, id, prev, secret, time.Now().UTC())
		if err != nil {
			if ferr := s.handle("certificate", cert.Name, err); ferr != nil {
				return ferr
			}
			continue
		}
		if exists {
			if change {
				if err := s.store.UpdateCertificate(s.ctx, rec); err != nil {
					if ferr := s.handle("certificate", cert.Name, err); ferr != nil {
						return ferr
					}
					continue
				}
				s.result.Updated++
			}
			continue
		}
		if err := s.store.CreateCertificate(s.ctx, rec); err != nil {
			if ferr := s.handle("certificate", cert.Name, err); ferr != nil {
				return ferr
			}
			continue
		}
		s.result.Created++
	}

	return s.pruneIDs(KindCertificate, declared, ids, func(id string) error {
		return s.store.DeleteCertificate(s.ctx, id)
	})
}

func needsKeyMaterial(cert config.Certificate) bool {
	return strings.EqualFold(cert.Source, "upload") || strings.EqualFold(cert.Source, "self-signed")
}

func buildCertificate(cert config.Certificate, id string, prev control.CertificateRecord, secret []byte, now time.Time) (control.CertificateRecord, bool, error) {
	domains := normalizeStrings(cert.Domains)
	domainsJSON, _ := json.Marshal(domains)

	source := normalizeCertSource(cert.Source)
	rec := control.CertificateRecord{
		ID:          id,
		Name:        cert.Name,
		Domains:     string(domainsJSON),
		Source:      source,
		AutoRenew:   boolToInt(cert.AutoRenew || source == control.CertSourceACME),
		ACMEStaging: boolToInt(cert.ACMEStaging),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if !prev.CreatedAt.IsZero() {
		rec.CreatedAt = prev.CreatedAt
	}

	switch source {
	case control.CertSourceACME:
		// CertMagic renews through the managed provider; keep any material.
		rec.CertPEM = prev.CertPEM
		rec.EncryptedKeyPEM = prev.EncryptedKeyPEM
		rec.FingerprintSHA256 = prev.FingerprintSHA256
		rec.Issuer = prev.Issuer
		rec.NotBefore = prev.NotBefore
		rec.NotAfter = prev.NotAfter
	case control.CertSourceUpload:
		leaf, err := control.ValidateCertificateKeyPair(cert.CertPEM, cert.KeyPEM)
		if err != nil {
			return rec, false, err
		}
		applyLeaf(&rec, cert.CertPEM, leaf)
		if prev.CertPEM == cert.CertPEM && prev.Source == source && prev.EncryptedKeyPEM != "" {
			rec.EncryptedKeyPEM = prev.EncryptedKeyPEM
			break
		}
		sealed, err := control.EncryptPrivateKey(secret, cert.KeyPEM)
		if err != nil {
			return rec, false, err
		}
		rec.EncryptedKeyPEM = sealed
	case control.CertSourceSelfSigned:
		if reusableCert(prev, domains) {
			rec.CertPEM = prev.CertPEM
			rec.EncryptedKeyPEM = prev.EncryptedKeyPEM
			rec.FingerprintSHA256 = prev.FingerprintSHA256
			rec.Issuer = prev.Issuer
			rec.NotBefore = prev.NotBefore
			rec.NotAfter = prev.NotAfter
			break
		}
		certPEM, keyPEM, leaf, err := control.GenerateSelfSigned(domains, now)
		if err != nil {
			return rec, false, err
		}
		applyLeaf(&rec, certPEM, leaf)
		sealed, err := control.EncryptPrivateKey(secret, keyPEM)
		if err != nil {
			return rec, false, err
		}
		rec.EncryptedKeyPEM = sealed
	}

	rec.LastError = ""
	change := prev.ID == "" || prev.Name != rec.Name || prev.Domains != rec.Domains ||
		prev.Source != rec.Source || prev.CertPEM != rec.CertPEM ||
		prev.EncryptedKeyPEM != rec.EncryptedKeyPEM || prev.FingerprintSHA256 != rec.FingerprintSHA256 ||
		prev.AutoRenew != rec.AutoRenew || prev.ACMEStaging != rec.ACMEStaging
	return rec, change, nil
}

func applyLeaf(rec *control.CertificateRecord, certPEM string, leaf *x509.Certificate) {
	rec.CertPEM = certPEM
	rec.FingerprintSHA256 = control.FingerprintSHA256(leaf.Raw)
	rec.Issuer = leaf.Issuer.String()
	rec.NotBefore = leaf.NotBefore.UTC()
	rec.NotAfter = leaf.NotAfter.UTC()
}

func reusableCert(prev control.CertificateRecord, domains []string) bool {
	if prev.CertPEM == "" || prev.EncryptedKeyPEM == "" {
		return false
	}
	leaf, err := control.ParseLeafCertificate(prev.CertPEM)
	if err != nil || time.Now().After(leaf.NotAfter.Add(-7*24*time.Hour)) {
		return false
	}
	for _, domain := range domains {
		if !control.CertificateCoversDomain(leaf, domain) {
			return false
		}
	}
	return true
}

func normalizeCertSource(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "upload":
		return control.CertSourceUpload
	case "acme":
		return control.CertSourceACME
	default:
		return control.CertSourceSelfSigned
	}
}

func normalizeStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		clean := strings.ToLower(strings.TrimSpace(value))
		if clean != "" {
			out = append(out, clean)
		}
	}
	return out
}

func boolToInt(v bool) int64 {
	if v {
		return 1
	}
	return 0
}
