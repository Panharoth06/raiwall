package caddy

import (
	"context"
	"crypto/tls"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
)

func init() {
	caddy.RegisterModule(CertificateGetter{})
}

// CertificateGetter is the `tls.get_certificate.raiwall` module. It resolves
// handshakes against certificates managed in the Raiwall control plane and
// returns (nil, nil) when a name is not managed here, letting Caddy fall back to
// its own cache or issuers.
type CertificateGetter struct{}

// CaddyModule returns the Caddy module information.
func (CertificateGetter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.get_certificate.raiwall",
		New: func() caddy.Module { return new(CertificateGetter) },
	}
}

// GetCertificate implements certmagic.Manager.
func (g *CertificateGetter) GetCertificate(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	provider := CurrentCertificateProvider()
	if provider == nil {
		return nil, nil
	}
	return provider.GetCertificate(ctx, hello)
}

var _ certmagic.Manager = (*CertificateGetter)(nil)
