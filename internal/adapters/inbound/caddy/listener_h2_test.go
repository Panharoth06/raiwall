package caddy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/require"
)

// TestH2ListenerCapturesRealClient serves HTTP/2 through a listener chain
// shaped like Caddy's (TLS first, fingerprint wrapper after) and checks that a
// real client's SETTINGS and pseudo-header order are captured while HTTP/2
// still negotiates.
func TestH2ListenerCapturesRealClient(t *testing.T) {
	// Borrow httptest's self-signed certificate.
	certSrv := httptest.NewUnstartedServer(http.NotFoundHandler())
	certSrv.StartTLS()
	certs := certSrv.TLS.Certificates
	certSrv.Close()

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tlsLn := tls.NewListener(raw, &tls.Config{Certificates: certs, NextProtos: []string{"h2", "http/1.1"}})
	ln := (H2ListenerWrapper{}).WrapListener(tlsLn)

	type result struct {
		hash  string
		order []string
		sets  int
	}
	got := make(chan result, 1)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, h2 := connectionFingerprints(r)
			if h2 != nil {
				select {
				case got <- result{h2.Hash, h2.PseudoHeaderOrder, len(h2.Settings)}:
				default:
				}
			}
			_, _ = io.WriteString(w, r.Proto)
		}),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, caddyhttp.ConnCtxKey, c)
		},
	}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	client := &http.Client{Transport: &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
	}}
	resp, err := client.Get("https://" + raw.Addr().String() + "/")
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, "HTTP/2.0", string(body), "wrapper must not break HTTP/2")

	select {
	case r := <-got:
		require.NotEmpty(t, r.hash)
		require.NotZero(t, r.sets)
		require.ElementsMatch(t, []string{"m", "a", "s", "p"}, r.order)
	default:
		t.Fatal("no HTTP/2 fingerprint captured for the connection")
	}
}
