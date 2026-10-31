package redis

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

const (
	defaultRESPTimeout  = 2 * time.Second
	defaultKeepAlive    = 30 * time.Second
	defaultReconnectMin = 100 * time.Millisecond
	defaultReconnectMax = 5 * time.Second
	// subscribeBuffer lets a briefly slow consumer fall behind without stalling the socket.
	subscribeBuffer = 256
	// keepAliveMisses is how many keep-alive intervals may pass without any
	// traffic before a subscription connection is treated as dead.
	keepAliveMisses = 2
)

// Options configures a SimpleRESPClient built with NewRESPClient.
type Options struct {
	// Addr is the host:port of the Redis server.
	Addr string
	// Timeout bounds dial, TLS handshake, AUTH and each command round trip.
	Timeout time.Duration

	// Username is the optional ACL user. It requires Password.
	Username string
	// Password is sent with AUTH on every (re)connect, for command and subscribe connections.
	Password string

	// TLS enables TLS for every connection. The fields below are ignored when false.
	TLS bool
	// TLSServerName overrides the name used to verify the server certificate.
	// It defaults to the host part of Addr.
	TLSServerName string
	// TLSCAFile is a PEM bundle of trusted roots. The system roots are used when empty.
	TLSCAFile string
	// TLSInsecureSkipVerify disables certificate verification. Off by default and
	// only appropriate for local testing, since it permits man-in-the-middle attacks.
	TLSInsecureSkipVerify bool
	// TLSConfig is an optional base configuration. It is cloned, and the fields above
	// are applied on top of it.
	TLSConfig *tls.Config

	// KeepAlive is the PING interval on subscribe connections, which detects half-open sockets.
	KeepAlive time.Duration
	// OnReconnect runs after every successful subscribe handshake, including
	// the first. Subscribers use it to reconcile events missed while the
	// connection was down, since pub/sub does not replay messages.
	OnReconnect func()
	// ReconnectMin and ReconnectMax bound the exponential backoff between subscribe reconnects.
	ReconnectMin time.Duration
	ReconnectMax time.Duration
}

func (o Options) withDefaults() Options {
	if o.Timeout <= 0 {
		o.Timeout = defaultRESPTimeout
	}
	if o.KeepAlive <= 0 {
		o.KeepAlive = defaultKeepAlive
	}
	if o.ReconnectMin <= 0 {
		o.ReconnectMin = defaultReconnectMin
	}
	if o.ReconnectMax < o.ReconnectMin {
		o.ReconnectMax = max(defaultReconnectMax, o.ReconnectMin)
	}
	return o
}

func (o Options) validate() error {
	if o.Addr == "" {
		return errors.New("redis: address is required")
	}
	if o.Username != "" && o.Password == "" {
		return errors.New("redis: username requires a password")
	}
	return nil
}

// tlsConfig returns nil when TLS is disabled.
func (o Options) tlsConfig() (*tls.Config, error) {
	if !o.TLS {
		return nil, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if o.TLSConfig != nil {
		cfg = o.TLSConfig.Clone()
	}
	switch {
	case o.TLSServerName != "":
		cfg.ServerName = o.TLSServerName
	case cfg.ServerName == "":
		host, _, err := net.SplitHostPort(o.Addr)
		if err != nil {
			host = o.Addr
		}
		cfg.ServerName = host
	}
	if o.TLSCAFile != "" {
		pem, err := os.ReadFile(o.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("redis: read tls ca file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("redis: no certificates found in %s", o.TLSCAFile)
		}
		cfg.RootCAs = pool
	}
	if o.TLSInsecureSkipVerify {
		cfg.InsecureSkipVerify = true // #nosec G402 -- explicit opt-in, defaults to off
	}
	return cfg, nil
}
