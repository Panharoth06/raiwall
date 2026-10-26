package sqlite

import (
	"context"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// Managed TLS certificates.

func (s *Store) ListCertificates(ctx context.Context) ([]control.CertificateRecord, error) {
	rows, err := s.Queries.FetchCertificates(ctx)
	if err != nil {
		return nil, err
	}
	res := make([]control.CertificateRecord, len(rows))
	for i, r := range rows {
		res[i] = toControlCertificate(r)
	}
	return res, nil
}

func (s *Store) GetCertificate(ctx context.Context, id string) (control.CertificateRecord, error) {
	r, err := s.Queries.FetchCertificate(ctx, id)
	if err != nil {
		return control.CertificateRecord{}, err
	}
	return toControlCertificate(r), nil
}

func (s *Store) CreateCertificate(ctx context.Context, cert control.CertificateRecord) error {
	return s.Queries.InsertCertificate(ctx, InsertCertificateParams{
		ID:                cert.ID,
		Name:              cert.Name,
		Domains:           cert.Domains,
		Source:            cert.Source,
		CertPem:           cert.CertPEM,
		EncryptedKeyPem:   cert.EncryptedKeyPEM,
		FingerprintSha256: cert.FingerprintSHA256,
		Issuer:            cert.Issuer,
		NotBefore:         cert.NotBefore,
		NotAfter:          cert.NotAfter,
		AutoRenew:         cert.AutoRenew,
		AcmeStaging:       cert.ACMEStaging,
		LastError:         cert.LastError,
		CreatedAt:         cert.CreatedAt,
		UpdatedAt:         cert.UpdatedAt,
	})
}

func (s *Store) UpdateCertificate(ctx context.Context, cert control.CertificateRecord) error {
	return s.Queries.ModifyCertificate(ctx, ModifyCertificateParams{
		Name:              cert.Name,
		Domains:           cert.Domains,
		Source:            cert.Source,
		CertPem:           cert.CertPEM,
		EncryptedKeyPem:   cert.EncryptedKeyPEM,
		FingerprintSha256: cert.FingerprintSHA256,
		Issuer:            cert.Issuer,
		NotBefore:         cert.NotBefore,
		NotAfter:          cert.NotAfter,
		AutoRenew:         cert.AutoRenew,
		AcmeStaging:       cert.ACMEStaging,
		LastError:         cert.LastError,
		UpdatedAt:         cert.UpdatedAt,
		ID:                cert.ID,
	})
}

func (s *Store) DeleteCertificate(ctx context.Context, id string) error {
	return s.Queries.RemoveCertificate(ctx, id)
}

func toControlCertificate(r RaiwallCertificate) control.CertificateRecord {
	return control.CertificateRecord{
		ID:                r.ID,
		Name:              r.Name,
		Domains:           r.Domains,
		Source:            r.Source,
		CertPEM:           r.CertPem,
		EncryptedKeyPEM:   r.EncryptedKeyPem,
		FingerprintSHA256: r.FingerprintSha256,
		Issuer:            r.Issuer,
		NotBefore:         r.NotBefore,
		NotAfter:          r.NotAfter,
		AutoRenew:         r.AutoRenew,
		ACMEStaging:       r.AcmeStaging,
		LastError:         r.LastError,
		CreatedAt:         r.CreatedAt,
		UpdatedAt:         r.UpdatedAt,
	}
}
