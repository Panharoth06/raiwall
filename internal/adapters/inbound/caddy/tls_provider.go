package caddy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"go.uber.org/zap"
)

// CertificateProvider resolves SNI handshakes against managed certificate
// records. Uploaded and self-signed certificates are served directly from
// memory; ACME certificates are issued and renewed through Caddy's TLS app and
// served from Caddy's own cache.
type CertificateProvider struct {
	mu      sync.RWMutex
	store   control.ControlStore
	secret  []byte
	certs   map[string]*tls.Certificate
	records map[string]control.CertificateRecord
	tlsApp  *caddytls.TLS
	logger  *zap.Logger
	now     func() time.Time
}

var currentCertProvider atomic.Pointer[CertificateProvider]

// CurrentCertificateProvider returns the provider installed by the raiwall module.
func CurrentCertificateProvider() *CertificateProvider {
	return currentCertProvider.Load()
}

// NewCertificateProvider builds a provider backed by the control store.
func NewCertificateProvider(store control.ControlStore, tlsApp *caddytls.TLS, logger *zap.Logger) (*CertificateProvider, error) {
	secret, err := control.EnsureCertificateSecret(context.Background(), store)
	if err != nil {
		return nil, err
	}
	return &CertificateProvider{
		store:   store,
		secret:  secret,
		certs:   make(map[string]*tls.Certificate),
		records: make(map[string]control.CertificateRecord),
		tlsApp:  tlsApp,
		logger:  logger,
		now:     func() time.Time { return time.Now().UTC() },
	}, nil
}

// Reload rebuilds the in-memory SNI index from the certificate store.
func (p *CertificateProvider) Reload(ctx context.Context) error {
	records, err := p.store.ListCertificates(ctx)
	if err != nil {
		return fmt.Errorf("list certificates: %w", err)
	}

	nextCerts := make(map[string]*tls.Certificate, len(records))
	nextRecords := make(map[string]control.CertificateRecord, len(records))
	for _, rec := range records {
		nextRecords[rec.ID] = rec
		if rec.Source == control.CertSourceACME || rec.CertPEM == "" || rec.EncryptedKeyPEM == "" {
			continue
		}
		pair, pairErr := p.pairFor(rec)
		if pairErr != nil {
			if p.logger != nil {
				p.logger.Warn("failed to load managed certificate",
					zap.String("certificate_id", rec.ID), zap.Error(pairErr))
			}
			continue
		}
		registerCertificateNames(nextCerts, rec, pair)
	}

	p.mu.Lock()
	p.certs = nextCerts
	p.records = nextRecords
	p.mu.Unlock()
	return nil
}

func (p *CertificateProvider) pairFor(rec control.CertificateRecord) (*tls.Certificate, error) {
	keyPEM, err := control.DecryptPrivateKey(p.secret, rec.EncryptedKeyPEM)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair([]byte(rec.CertPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("parse key pair: %w", err)
	}
	return &pair, nil
}

func registerCertificateNames(index map[string]*tls.Certificate, rec control.CertificateRecord, pair *tls.Certificate) {
	var domains []string
	if rec.Domains != "" {
		_ = json.Unmarshal([]byte(rec.Domains), &domains)
	}
	if len(domains) == 0 && len(pair.Certificate) > 0 {
		if leaf, err := control.ParseLeafCertificate(rec.CertPEM); err == nil {
			domains = append(domains, leaf.DNSNames...)
			for _, ip := range leaf.IPAddresses {
				domains = append(domains, ip.String())
			}
		}
	}
	for _, domain := range domains {
		clean := normalizeSNI(domain)
		if clean != "" {
			index[clean] = pair
		}
	}
}

// GetCertificate implements certmagic.Manager.
func (p *CertificateProvider) GetCertificate(_ context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if p == nil || hello == nil {
		return nil, nil
	}
	sni := normalizeSNI(hello.ServerName)
	if sni == "" {
		return nil, nil
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	if pair, ok := p.certs[sni]; ok {
		return pair, nil
	}
	if idx := strings.Index(sni, "."); idx >= 0 {
		if pair, ok := p.certs["*"+sni[idx:]]; ok {
			return pair, nil
		}
	}
	// ACME-managed names are served by Caddy's certificate cache.
	return nil, nil
}

// Reconcile renews self-signed certificates and ensures ACME certificates are
// managed. It is safe to run after every deploy.
func (p *CertificateProvider) Reconcile(ctx context.Context) {
	records, err := p.store.ListCertificates(ctx)
	if err != nil {
		if p.logger != nil {
			p.logger.Warn("certificate reconcile: list failed", zap.Error(err))
		}
		return
	}

	renewBefore := p.now().Add(30 * 24 * time.Hour)
	for _, rec := range records {
		switch rec.Source {
		case control.CertSourceSelfSigned:
			if rec.AutoRenew != 1 || rec.NotAfter.After(renewBefore) {
				continue
			}
			if err := p.renewSelfSigned(ctx, rec); err != nil && p.logger != nil {
				p.logger.Warn("self-signed certificate renewal failed",
					zap.String("certificate_id", rec.ID), zap.Error(err))
			}
		case control.CertSourceACME:
			if rec.AutoRenew != 1 {
				continue
			}
			p.manageACME(ctx, rec)
		}
	}

	if err := p.Reload(ctx); err != nil && p.logger != nil {
		p.logger.Warn("certificate reload failed", zap.Error(err))
	}
}

func (p *CertificateProvider) manageACME(ctx context.Context, rec control.CertificateRecord) {
	if p.tlsApp == nil {
		return
	}
	var domains []string
	if rec.Domains != "" {
		_ = json.Unmarshal([]byte(rec.Domains), &domains)
	}
	if len(domains) == 0 {
		return
	}
	if err := p.tlsApp.Manage(domains); err != nil {
		if p.logger != nil {
			p.logger.Warn("ACME issuance failed", zap.String("certificate_id", rec.ID), zap.Error(err))
		}
		rec.LastError = err.Error()
		rec.UpdatedAt = p.now()
		_ = p.store.UpdateCertificate(ctx, rec)
		return
	}
	if rec.LastError != "" {
		rec.LastError = ""
		rec.UpdatedAt = p.now()
		_ = p.store.UpdateCertificate(ctx, rec)
	}
}

func (p *CertificateProvider) renewSelfSigned(ctx context.Context, rec control.CertificateRecord) error {
	var domains []string
	if rec.Domains != "" {
		_ = json.Unmarshal([]byte(rec.Domains), &domains)
	}
	if len(domains) == 0 {
		return fmt.Errorf("certificate has no domains")
	}
	certPEM, keyPEM, leaf, err := control.GenerateSelfSigned(domains, p.now())
	if err != nil {
		return err
	}
	encrypted, err := control.EncryptPrivateKey(p.secret, keyPEM)
	if err != nil {
		return err
	}
	rec.CertPEM = certPEM
	rec.EncryptedKeyPEM = encrypted
	rec.FingerprintSHA256 = control.FingerprintSHA256(leaf.Raw)
	rec.Issuer = leaf.Issuer.CommonName
	rec.NotBefore = leaf.NotBefore
	rec.NotAfter = leaf.NotAfter
	rec.LastError = ""
	rec.UpdatedAt = p.now()
	return p.store.UpdateCertificate(ctx, rec)
}

func normalizeSNI(host string) string {
	clean := strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(clean); err == nil {
		clean = h
	}
	return strings.TrimSuffix(strings.Trim(clean, "[]"), ".")
}
