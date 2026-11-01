package caddy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/require"
)

// TestJA4ListenerCapturesRealHandshake runs a real TLS/HTTP2 client against a
// server whose raw listener is wrapped by the JA4 wrapper, and checks that the
// request can find the fingerprint through the connection in its context.
func TestJA4ListenerCapturesRealHandshake(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ja4, _ := connectionFingerprints(r)
		_, _ = io.WriteString(w, ja4)
	}))
	srv.Listener = (JA4ListenerWrapper{}).WrapListener(srv.Listener)
	srv.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, caddyhttp.ConnCtxKey, c)
	}
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	require.Equal(t, 2, resp.ProtoMajor, "wrapped listener must not break HTTP/2")
	require.Regexp(t, regexp.MustCompile(`^t13[di]\d{4}h2_[0-9a-f]{12}_[0-9a-f]{12}$`), string(body))

	// A second connection from the same client config yields the same JA4.
	srv.Client().CloseIdleConnections()
	resp2, err := srv.Client().Get(srv.URL)
	require.NoError(t, err)
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)
	require.Equal(t, string(body), string(body2))
}
