package postgres

import (
	"context"
	"fmt"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// Managed TLS certificates.

const certificateColumns = `id, name, domains, source, cert_pem, encrypted_key_pem, fingerprint_sha256,
	issuer, not_before, not_after, auto_renew, acme_staging, last_error, created_at, updated_at`

func (s *ControlStore) ListCertificates(ctx context.Context) ([]control.CertificateRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+certificateColumns+` FROM raiwall_certificates ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}
	defer rows.Close()

	var out []control.CertificateRecord
	for rows.Next() {
		var c control.CertificateRecord
		if err := rows.Scan(
			&c.ID, &c.Name, &c.Domains, &c.Source, &c.CertPEM, &c.EncryptedKeyPEM,
			&c.FingerprintSHA256, &c.Issuer, &c.NotBefore, &c.NotAfter, &c.AutoRenew,
			&c.ACMEStaging, &c.LastError, &c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan certificate: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *ControlStore) GetCertificate(ctx context.Context, id string) (control.CertificateRecord, error) {
	var c control.CertificateRecord
	err := s.db.QueryRowContext(ctx,
		`SELECT `+certificateColumns+` FROM raiwall_certificates WHERE id = $1 LIMIT 1`, id,
	).Scan(
		&c.ID, &c.Name, &c.Domains, &c.Source, &c.CertPEM, &c.EncryptedKeyPEM,
		&c.FingerprintSHA256, &c.Issuer, &c.NotBefore, &c.NotAfter, &c.AutoRenew,
		&c.ACMEStaging, &c.LastError, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return control.CertificateRecord{}, fmt.Errorf("get certificate %s: %w", id, err)
	}
	return c, nil
}

func (s *ControlStore) CreateCertificate(ctx context.Context, c control.CertificateRecord) error {
	query := `INSERT INTO raiwall_certificates (` + certificateColumns + `)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`
	_, err := s.db.ExecContext(ctx, query,
		c.ID, c.Name, c.Domains, c.Source, c.CertPEM, c.EncryptedKeyPEM,
		c.FingerprintSHA256, c.Issuer, c.NotBefore, c.NotAfter, c.AutoRenew,
		c.ACMEStaging, c.LastError, c.CreatedAt, c.UpdatedAt,
	)
	return err
}

func (s *ControlStore) UpdateCertificate(ctx context.Context, c control.CertificateRecord) error {
	query := `UPDATE raiwall_certificates SET
		name = $1, domains = $2, source = $3, cert_pem = $4, encrypted_key_pem = $5,
		fingerprint_sha256 = $6, issuer = $7, not_before = $8, not_after = $9,
		auto_renew = $10, acme_staging = $11, last_error = $12, updated_at = $13
	WHERE id = $14`
	_, err := s.db.ExecContext(ctx, query,
		c.Name, c.Domains, c.Source, c.CertPEM, c.EncryptedKeyPEM,
		c.FingerprintSHA256, c.Issuer, c.NotBefore, c.NotAfter, c.AutoRenew,
		c.ACMEStaging, c.LastError, c.UpdatedAt, c.ID,
	)
	return err
}

func (s *ControlStore) DeleteCertificate(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM raiwall_certificates WHERE id = $1`, id)
	return err
}
