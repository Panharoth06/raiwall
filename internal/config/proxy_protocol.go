package config

import (
	"net/netip"
	"strings"
)

// ProxyProtocol configures PROXY protocol v1/v2 on the public listeners.
// Only peers inside Allow may supply a PROXY header; a header from any other
// peer is rejected so it can never rewrite the client address.
type ProxyProtocol struct {
	Enabled *bool    `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Allow   []string `yaml:"allow" json:"allow"`
	// Timeout bounds how long a trusted peer may take to send the header.
	Timeout Duration `yaml:"timeout" json:"timeout"`
}

// Active reports whether PROXY protocol handling is configured and enabled.
func (p *ProxyProtocol) Active() bool {
	return p != nil && enabled(p.Enabled)
}

func (f *File) validateProxyProtocol(v *validator) {
	pp := f.Server.ProxyProtocol
	if !pp.Active() {
		return
	}
	if len(pp.Allow) == 0 {
		v.add("server.proxy_protocol.allow must list the trusted load balancer CIDRs")
	}
	for i, cidr := range pp.Allow {
		if _, err := netip.ParsePrefix(strings.TrimSpace(cidr)); err != nil {
			v.add("server.proxy_protocol.allow[%d] %q is not a valid CIDR", i, cidr)
		}
	}
	if pp.Timeout < 0 {
		v.add("server.proxy_protocol.timeout must be non-negative")
	}
}
