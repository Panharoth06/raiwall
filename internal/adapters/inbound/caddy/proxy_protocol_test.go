package caddy

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/proxyprotocol"
	"github.com/stretchr/testify/require"

	"github.com/Panharoth06/raiwall/internal/config"
)

// wrapperFor builds Caddy's real PROXY protocol wrapper from the exact JSON the
// adapter emits, so the test covers the generated settings and not a copy.
func wrapperFor(t *testing.T, allow []string) *proxyprotocol.ListenerWrapper {
	t.Helper()
	file := &config.File{}
	file.Server.ProxyProtocol = &config.ProxyProtocol{Allow: allow, Timeout: config.Duration(2 * time.Second)}
	raw, err := json.Marshal(proxyProtocolWrapper(file))
	require.NoError(t, err)

	var w proxyprotocol.ListenerWrapper
	require.NoError(t, json.Unmarshal(raw, &w))
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	t.Cleanup(cancel)
	require.NoError(t, w.Provision(ctx))
	return &w
}

// remoteAddrSeenByServer sends a PROXY v1 header claiming 203.0.113.9 over a
// real loopback connection and returns what the server-side conn reports.
func remoteAddrSeenByServer(t *testing.T, w *proxyprotocol.ListenerWrapper) (string, error) {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ln := w.WrapListener(inner)
	t.Cleanup(func() { _ = ln.Close() })

	type result struct {
		addr string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- result{err: err}
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = c.Read(buf) // the header is parsed on first read
		done <- result{addr: c.RemoteAddr().String(), err: err}
	}()

	c, err := net.Dial("tcp", inner.Addr().String())
	require.NoError(t, err)
	defer c.Close()
	_, err = c.Write([]byte("PROXY TCP4 203.0.113.9 10.0.0.1 54321 443\r\nping"))
	require.NoError(t, err)

	select {
	case r := <-done:
		return r.addr, r.err
	case <-time.After(3 * time.Second):
		t.Fatal("server did not finish")
		return "", nil
	}
}

func TestProxyProtocolTrustedPeerRewritesRemoteAddr(t *testing.T) {
	w := wrapperFor(t, []string{"127.0.0.0/8"})
	addr, err := remoteAddrSeenByServer(t, w)
	require.NoError(t, err)
	require.Equal(t, "203.0.113.9:54321", addr)
}

func TestProxyProtocolUntrustedPeerCannotSpoof(t *testing.T) {
	// The loopback test client is outside the allow list.
	w := wrapperFor(t, []string{"192.0.2.0/24"})
	addr, err := remoteAddrSeenByServer(t, w)
	require.Error(t, err, "an untrusted peer sending a PROXY header must be refused")
	require.NotContains(t, addr, "203.0.113.9")
}
