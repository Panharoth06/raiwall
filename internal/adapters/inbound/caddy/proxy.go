package caddy

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// maxReplayableBodyBytes bounds how much request body is buffered to enable a
// retry on another backend. Larger bodies get a single attempt.
const maxReplayableBodyBytes = 1 << 20

// defaultProxyAttempts is how many distinct backends a request may try before
// the client receives a 502.
const defaultProxyAttempts = 2

// splitDialTarget separates an optional scheme from an upstream dial address.
func splitDialTarget(dial string) (scheme, host string) {
	scheme, host = "http", dial
	if strings.HasPrefix(host, "https://") {
		return "https", strings.TrimPrefix(host, "https://")
	}
	if strings.HasPrefix(host, "http://") {
		return "http", strings.TrimPrefix(host, "http://")
	}
	return scheme, host
}

// IsWebSocketUpgrade reports whether the request asks to switch protocols.
func IsWebSocketUpgrade(r *http.Request) bool {
	if r == nil {
		return false
	}
	for _, token := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
			return strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket")
		}
	}
	return false
}

// buildUpstreamRequest clones the inbound request onto an upstream target.
func buildUpstreamRequest(r *http.Request, dial string, body io.Reader) (*http.Request, error) {
	scheme, host := splitDialTarget(dial)
	outURL := *r.URL
	outURL.Scheme = scheme
	outURL.Host = host

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), body)
	if err != nil {
		return nil, err
	}
	outReq.Header = r.Header.Clone()
	if r.Host != "" {
		outReq.Host = r.Host
	}
	return outReq, nil
}

// copyResponseHeaders mirrors upstream headers onto the client response.
func copyResponseHeaders(dst http.ResponseWriter, src *http.Response) {
	for k, vv := range src.Header {
		for _, v := range vv {
			dst.Header().Add(k, v)
		}
	}
}

// ProxyToBackend forwards an HTTP request to an upstream dial address using the given transport.
func ProxyToBackend(w http.ResponseWriter, r *http.Request, dial string, transport http.RoundTripper) error {
	outReq, err := buildUpstreamRequest(r, dial, r.Body)
	if err != nil {
		http.Error(w, "Failed to create upstream request: "+err.Error(), http.StatusBadGateway)
		return err
	}

	if transport == nil {
		transport = http.DefaultTransport
	}

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, "Upstream connection failed: "+err.Error(), http.StatusBadGateway)
		return err
	}
	defer resp.Body.Close()

	copyResponseHeaders(w, resp)
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	return err
}

// ProxyWebSocket hijacks the client connection and splices it to the upstream so
// 101 Switching Protocols upgrades (WebSocket, and h2c-over-upgrade) work
// instead of hanging on a buffered response (TASKS.md 0.8).
func ProxyWebSocket(w http.ResponseWriter, r *http.Request, dial string, dialTimeout time.Duration) error {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Upstream upgrade unsupported by this listener", http.StatusBadGateway)
		return errors.New("response writer does not support hijacking")
	}

	scheme, host := splitDialTarget(dial)
	if dialTimeout <= 0 {
		dialTimeout = upstreamDialTimeout
	}

	var upstream net.Conn
	var err error
	dialer := &net.Dialer{Timeout: dialTimeout}
	if scheme == "https" {
		upstream, err = tls.DialWithDialer(dialer, "tcp", host, nil)
	} else {
		upstream, err = dialer.DialContext(r.Context(), "tcp", host)
	}
	if err != nil {
		http.Error(w, "Upstream connection failed: "+err.Error(), http.StatusBadGateway)
		return err
	}
	defer upstream.Close()

	// Forward the original upgrade request verbatim; Write preserves the
	// Connection/Upgrade headers that a RoundTrip would strip.
	outReq := r.Clone(r.Context())
	outReq.URL.Scheme = scheme
	outReq.URL.Host = host
	if err := outReq.Write(upstream); err != nil {
		http.Error(w, "Upstream upgrade failed: "+err.Error(), http.StatusBadGateway)
		return err
	}

	client, buf, err := hijacker.Hijack()
	if err != nil {
		return err
	}
	defer client.Close()

	errCh := make(chan error, 2)
	go func() {
		_, copyErr := io.Copy(upstream, buf)
		errCh <- copyErr
	}()
	go func() {
		_, copyErr := io.Copy(client, upstream)
		errCh <- copyErr
	}()

	// Returning after the first side closes tears down both halves via defer.
	return <-errCh
}

// ProxyWithFailover forwards the request and retries another backend when a
// backend fails to produce a response. Failures are marked passively so an
// unhealthy backend drops out of rotation before its probe notices
// (TASKS.md 0.8). Requests with an unrepeatable body are attempted once.
func ProxyWithFailover(
	w http.ResponseWriter,
	r *http.Request,
	pool *UpstreamPool,
	policy, clientIP string,
	transport http.RoundTripper,
	maxAttempts int,
) error {
	if pool == nil {
		http.Error(w, "Bad Gateway: no upstream pool", http.StatusBadGateway)
		return errors.New("no upstream pool")
	}
	if transport == nil {
		transport = http.DefaultTransport
	}
	if maxAttempts <= 0 {
		maxAttempts = 2
	}

	// Only a replayable body can be retried. GET/HEAD and empty bodies qualify;
	// anything else gets a single attempt so we never send a half-read body.
	var body []byte
	replayable := r.Body == nil || r.Body == http.NoBody
	if !replayable {
		if r.ContentLength >= 0 && r.ContentLength <= maxReplayableBodyBytes {
			var readErr error
			body, readErr = io.ReadAll(io.LimitReader(r.Body, maxReplayableBodyBytes))
			_ = r.Body.Close()
			if readErr != nil {
				http.Error(w, "Failed to buffer request body: "+readErr.Error(), http.StatusBadGateway)
				return readErr
			}
			replayable = true
		} else {
			maxAttempts = 1
		}
	}

	tried := make(map[string]bool, maxAttempts)
	var lastErr error

	for attempt := 0; attempt < maxAttempts; attempt++ {
		backend, release, err := pool.SelectBackend(policy, clientIP)
		if err != nil {
			lastErr = err
			break
		}
		if tried[backend.Dial] && attempt > 0 {
			release()
			break
		}
		tried[backend.Dial] = true

		var reqBody io.Reader
		if replayable && len(body) > 0 {
			reqBody = bytes.NewReader(body)
		} else if !replayable {
			reqBody = r.Body
		}

		outReq, buildErr := buildUpstreamRequest(r, backend.Dial, reqBody)
		if buildErr != nil {
			release()
			lastErr = buildErr
			break
		}

		resp, rtErr := transport.RoundTrip(outReq)
		if rtErr != nil {
			backend.MarkFailure()
			release()
			lastErr = rtErr
			continue
		}

		backend.MarkSuccess()
		copyResponseHeaders(w, resp)
		w.WriteHeader(resp.StatusCode)
		_, copyErr := io.Copy(w, resp.Body)
		_ = resp.Body.Close()
		release()
		return copyErr
	}

	msg := "Upstream connection failed"
	if lastErr != nil {
		msg += ": " + lastErr.Error()
	}
	http.Error(w, msg, http.StatusBadGateway)
	return lastErr
}
