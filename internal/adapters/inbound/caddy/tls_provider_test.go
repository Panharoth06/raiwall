package caddy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/sqlite"
	"github.com/Panharoth06/raiwall/internal/core/control"
)

func newCertTestProvider(t *testing.T) (*CertificateProvider, control.ControlStore) {
	t.Helper()
	store, err := sqlite.InitDB(fmt.Sprintf("file:test_tls_provider_%d.db", time.Now().UnixNano()))
	if err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	provider, err := NewCertificateProvider(store, nil, nil)
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	return provider, store
}

func storeSelfSignedCert(t *testing.T, provider *CertificateProvider, store control.ControlStore, id string, domains []string) {
	t.Helper()
	now := time.Now().UTC()
	certPEM, keyPEM, leaf, err := control.GenerateSelfSigned(domains, now)
	if err != nil {
		t.Fatalf("generate self-signed: %v", err)
	}
	encrypted, err := control.EncryptPrivateKey(provider.secret, keyPEM)
	if err != nil {
		t.Fatalf("encrypt key: %v", err)
	}
	domainsJSON, _ := json.Marshal(domains)
	record := control.CertificateRecord{
		ID:                id,
		Name:              domains[0],
		Domains:           string(domainsJSON),
		Source:            control.CertSourceSelfSigned,
		CertPEM:           certPEM,
		EncryptedKeyPEM:   encrypted,
		FingerprintSHA256: control.FingerprintSHA256(leaf.Raw),
		Issuer:            leaf.Issuer.CommonName,
		NotBefore:         leaf.NotBefore,
		NotAfter:          leaf.NotAfter,
		AutoRenew:         1,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := store.CreateCertificate(context.Background(), record); err != nil {
		t.Fatalf("create certificate: %v", err)
	}
}

func TestCertificateProviderResolvesSNI(t *testing.T) {
	provider, store := newCertTestProvider(t)
	storeSelfSignedCert(t, provider, store, "cert-exact", []string{"app.example.com"})
	storeSelfSignedCert(t, provider, store, "cert-wild", []string{"*.wild.example.com"})

	if err := provider.Reload(context.Background()); err != nil {
		t.Fatalf("reload: %v", err)
	}

	cases := []struct {
		sni  string
		want bool
	}{
		{"app.example.com", true},
		{"APP.EXAMPLE.COM.", true},
		{"api.wild.example.com", true},
		{"deep.api.wild.example.com", false},
		{"unknown.example.com", false},
		{"", false},
	}
	for _, tc := range cases {
		got, err := provider.GetCertificate(context.Background(), &tls.ClientHelloInfo{ServerName: tc.sni})
		if err != nil {
			t.Fatalf("GetCertificate(%q): %v", tc.sni, err)
		}
		if tc.want && got == nil {
			t.Errorf("expected certificate for %q", tc.sni)
		}
		if !tc.want && got != nil {
			t.Errorf("unexpected certificate for %q", tc.sni)
		}
	}
}

func TestCertificateProviderSkipsACMEAndBrokenRecords(t *testing.T) {
	provider, store := newCertTestProvider(t)
	now := time.Now().UTC()
	acme := control.CertificateRecord{
		ID:        "cert-acme",
		Name:      "acme",
		Domains:   `["acme.example.com"]`,
		Source:    control.CertSourceACME,
		AutoRenew: 1,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := store.CreateCertificate(context.Background(), acme); err != nil {
		t.Fatalf("create acme record: %v", err)
	}
	broken := control.CertificateRecord{
		ID:              "cert-broken",
		Name:            "broken",
		Domains:         `["broken.example.com"]`,
		Source:          control.CertSourceSelfSigned,
		CertPEM:         "not pem",
		EncryptedKeyPEM: "not base64!",
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := store.CreateCertificate(context.Background(), broken); err != nil {
		t.Fatalf("create broken record: %v", err)
	}

	if err := provider.Reload(context.Background()); err != nil {
		t.Fatalf("reload must tolerate broken records: %v", err)
	}
	for _, sni := range []string{"acme.example.com", "broken.example.com"} {
		if cert, _ := provider.GetCertificate(context.Background(), &tls.ClientHelloInfo{ServerName: sni}); cert != nil {
			t.Errorf("expected no cert for %q", sni)
		}
	}
}

func TestCertificateProviderRenewsExpiringSelfSigned(t *testing.T) {
	provider, store := newCertTestProvider(t)
	now := time.Now().UTC()
	certPEM, keyPEM, leaf, err := control.GenerateSelfSigned([]string{"expiring.example.com"}, now)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	encrypted, err := control.EncryptPrivateKey(provider.secret, keyPEM)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	record := control.CertificateRecord{
		ID:              "cert-expiring",
		Name:            "expiring",
		Domains:         `["expiring.example.com"]`,
		Source:          control.CertSourceSelfSigned,
		CertPEM:         certPEM,
		EncryptedKeyPEM: encrypted,
		NotBefore:       now.Add(-80 * 24 * time.Hour),
		NotAfter:        now.Add(5 * 24 * time.Hour),
		AutoRenew:       1,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := store.CreateCertificate(context.Background(), record); err != nil {
		t.Fatalf("create: %v", err)
	}

	provider.Reconcile(context.Background())

	updated, err := store.GetCertificate(context.Background(), "cert-expiring")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if updated.FingerprintSHA256 == control.FingerprintSHA256(leaf.Raw) {
		t.Fatal("certificate was not re-issued")
	}
	if !updated.NotAfter.After(now.Add(60 * 24 * time.Hour)) {
		t.Fatalf("renewed certificate expires too soon: %s", updated.NotAfter)
	}
	if updated.LastError != "" {
		t.Errorf("unexpected last_error: %s", updated.LastError)
	}
	if cert, _ := provider.GetCertificate(context.Background(), &tls.ClientHelloInfo{ServerName: "expiring.example.com"}); cert == nil {
		t.Error("renewed certificate is not served")
	}
}
