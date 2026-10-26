package sqlite

import (
	"database/sql/driver"
	"sort"
	"strings"
)

var certificateColumns = []string{
	"id", "name", "domains", "source", "cert_pem", "encrypted_key_pem",
	"fingerprint_sha256", "issuer", "not_before", "not_after", "auto_renew",
	"acme_staging", "last_error", "created_at", "updated_at",
}

func certificateRow(c *RaiwallCertificate) []driver.Value {
	return []driver.Value{
		c.ID, c.Name, c.Domains, c.Source, c.CertPem, c.EncryptedKeyPem,
		c.FingerprintSha256, c.Issuer, c.NotBefore, c.NotAfter, c.AutoRenew,
		c.AcmeStaging, c.LastError, c.CreatedAt, c.UpdatedAt,
	}
}

func (s *controlStmt) queryCertificates(st *databaseState, q string, args []driver.Value) (driver.Rows, bool) {
	if strings.Contains(q, "FROM raiwall_certificates WHERE id = ?") {
		id := toStringVal(args[0])
		if cert, ok := st.certificates[id]; ok {
			return &driverMemoryRows{
				columns: certificateColumns,
				data:    [][]driver.Value{certificateRow(cert)},
			}, true
		}
		return &driverMemoryRows{}, true
	}
	if strings.Contains(q, "FROM raiwall_certificates") {
		list := make([]*RaiwallCertificate, 0, len(st.certificates))
		for _, c := range st.certificates {
			list = append(list, c)
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
		rows := make([][]driver.Value, len(list))
		for i, c := range list {
			rows[i] = certificateRow(c)
		}
		return &driverMemoryRows{columns: certificateColumns, data: rows}, true
	}
	return nil, false
}
