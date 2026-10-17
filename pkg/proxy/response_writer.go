package proxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// ResponseInterceptor wraps an http.ResponseWriter to capture the status code,
// count bytes written, and strip sensitive upstream headers before sending.
type ResponseInterceptor struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
	wroteHeader  bool
	stripHeaders []string
}

// NewResponseInterceptor creates a ResponseInterceptor wrapping w.
func NewResponseInterceptor(w http.ResponseWriter, stripHeaders []string) *ResponseInterceptor {
	return &ResponseInterceptor{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
		stripHeaders:   stripHeaders,
	}
}

// StatusCode returns the recorded HTTP status code.
func (ri *ResponseInterceptor) StatusCode() int {
	return ri.statusCode
}

// BytesWritten returns the total bytes written to the response body.
func (ri *ResponseInterceptor) BytesWritten() int64 {
	return ri.bytesWritten
}

// Header returns the header map from the underlying ResponseWriter.
func (ri *ResponseInterceptor) Header() http.Header {
	return ri.ResponseWriter.Header()
}

// WriteHeader strips sensitive headers and records the status code before delegating.
func (ri *ResponseInterceptor) WriteHeader(statusCode int) {
	if ri.wroteHeader {
		return
	}
	ri.statusCode = statusCode
	ri.wroteHeader = true

	// Sanitize/strip sensitive headers
	header := ri.ResponseWriter.Header()
	for _, h := range ri.stripHeaders {
		header.Del(h)
	}

	ri.ResponseWriter.WriteHeader(statusCode)
}

// Write writes data to the connection, ensuring WriteHeader is called first.
func (ri *ResponseInterceptor) Write(b []byte) (int, error) {
	if !ri.wroteHeader {
		ri.WriteHeader(http.StatusOK)
	}
	n, err := ri.ResponseWriter.Write(b)
	ri.bytesWritten += int64(n)
	return n, err
}

// Flush implements http.Flusher to support streaming, SSE, and chunked transfer.
func (ri *ResponseInterceptor) Flush() {
	if f, ok := ri.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker to support WebSockets.
func (ri *ResponseInterceptor) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := ri.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter (%T) does not implement http.Hijacker", ri.ResponseWriter)
}

// Unwrap returns the underlying ResponseWriter.
func (ri *ResponseInterceptor) Unwrap() http.ResponseWriter {
	return ri.ResponseWriter
}

// DefaultSensitiveHeaders are headers commonly stripped to prevent backend reconnaissance.
var DefaultSensitiveHeaders = []string{
	"Server",
	"X-Powered-By",
	"X-AspNet-Version",
	"X-AspNetMvc-Version",
}

// CanonicalizeHeaderList normalizes header names for stripping.
func CanonicalizeHeaderList(headers []string) []string {
	if len(headers) == 0 {
		return DefaultSensitiveHeaders
	}
	res := make([]string, 0, len(headers))
	for _, h := range headers {
		trimmed := strings.TrimSpace(h)
		if trimmed != "" {
			res = append(res, http.CanonicalHeaderKey(trimmed))
		}
	}
	return res
}
