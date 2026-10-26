package sqlite

import (
	"database/sql/driver"
	"strings"
)

func (s *controlStmt) execCertificates(st *databaseState, q string, args []driver.Value) (driver.Result, bool) {
	if strings.Contains(q, "INSERT INTO raiwall_certificates") {
		cert := &RaiwallCertificate{
			ID:                toStringVal(args[0]),
			Name:              toStringVal(args[1]),
			Domains:           toStringVal(args[2]),
			Source:            toStringVal(args[3]),
			CertPem:           toStringVal(args[4]),
			EncryptedKeyPem:   toStringVal(args[5]),
			FingerprintSha256: toStringVal(args[6]),
			Issuer:            toStringVal(args[7]),
			NotBefore:         toTime(args[8]),
			NotAfter:          toTime(args[9]),
			AutoRenew:         toInt64Val(args[10]),
			AcmeStaging:       toInt64Val(args[11]),
			LastError:         toStringVal(args[12]),
			CreatedAt:         toTime(args[13]),
			UpdatedAt:         toTime(args[14]),
		}
		st.certificates[cert.ID] = cert
		return driver.RowsAffected(1), true
	}
	if strings.Contains(q, "UPDATE raiwall_certificates SET") {
		id := toStringVal(args[13])
		if cert, ok := st.certificates[id]; ok {
			cert.Name = toStringVal(args[0])
			cert.Domains = toStringVal(args[1])
			cert.Source = toStringVal(args[2])
			cert.CertPem = toStringVal(args[3])
			cert.EncryptedKeyPem = toStringVal(args[4])
			cert.FingerprintSha256 = toStringVal(args[5])
			cert.Issuer = toStringVal(args[6])
			cert.NotBefore = toTime(args[7])
			cert.NotAfter = toTime(args[8])
			cert.AutoRenew = toInt64Val(args[9])
			cert.AcmeStaging = toInt64Val(args[10])
			cert.LastError = toStringVal(args[11])
			cert.UpdatedAt = toTime(args[12])
			return driver.RowsAffected(1), true
		}
		return driver.RowsAffected(0), true
	}
	if strings.Contains(q, "DELETE FROM raiwall_certificates") {
		id := toStringVal(args[0])
		if _, ok := st.certificates[id]; ok {
			delete(st.certificates, id)
			return driver.RowsAffected(1), true
		}
		return driver.RowsAffected(0), true
	}
	return nil, false
}
