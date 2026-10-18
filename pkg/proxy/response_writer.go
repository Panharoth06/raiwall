package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/Panharoth06/raiwall/pkg/bot"
)

// ResponseInterceptor wraps an http.ResponseWriter to capture the status code,
// count bytes written, strip sensitive upstream headers, and optionally inject honeypot traps.
type ResponseInterceptor struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
	wroteHeader  bool
	stripHeaders []string

	honeypotInjector *bot.HoneypotInjector
	bufferedBody     *bytes.Buffer
	isHTML           bool
	headerCommitted  bool
}

// NewResponseInterceptor creates a ResponseInterceptor wrapping w.
func NewResponseInterceptor(w http.ResponseWriter, stripHeaders []string) *ResponseInterceptor {
	if len(stripHeaders) == 0 {
		stripHeaders = DefaultSensitiveHeaders
	}
	return &ResponseInterceptor{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
		stripHeaders:   stripHeaders,
	}
}

// SetHoneypotInjector enables dynamic honeypot injection on HTML responses.
func (ri *ResponseInterceptor) SetHoneypotInjector(inj *bot.HoneypotInjector) {
	ri.honeypotInjector = inj
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

func (ri *ResponseInterceptor) commitHeaders(statusCode int) {
	if ri.headerCommitted {
		return
	}
	ri.headerCommitted = true

	// Sanitize/strip sensitive headers
	header := ri.ResponseWriter.Header()
	for _, h := range ri.stripHeaders {
		header.Del(h)
	}

	ri.ResponseWriter.WriteHeader(statusCode)
}

// WriteHeader strips sensitive headers and records the status code before delegating.
// Informational 1xx responses (except 101 Switching Protocols) do not seal the headers.
func (ri *ResponseInterceptor) WriteHeader(statusCode int) {
	if ri.wroteHeader {
		return
	}

	// 1xx Informational responses (e.g. 103 Early Hints, 100 Continue) do not seal the response
	if statusCode >= 100 && statusCode <= 199 && statusCode != http.StatusSwitchingProtocols {
		ri.statusCode = statusCode
		ri.ResponseWriter.WriteHeader(statusCode)
		return
	}

	ri.statusCode = statusCode
	ri.wroteHeader = true

	// If honeypot injection is active and response is uncompressed HTML, buffer the body before writing headers
	if ri.honeypotInjector != nil {
		if statusCode != http.StatusNoContent && statusCode != http.StatusNotModified && !(statusCode >= 100 && statusCode < 200) {
			ce := strings.ToLower(ri.Header().Get("Content-Encoding"))
			isCompressed := ce != "" && ce != "identity"
			cd := strings.ToLower(ri.Header().Get("Content-Disposition"))
			isAttachment := strings.Contains(cd, "attachment")

			if !isCompressed && !isAttachment {
				ct := strings.ToLower(ri.Header().Get("Content-Type"))
				if strings.Contains(ct, "text/html") {
					ri.isHTML = true
					ri.bufferedBody = new(bytes.Buffer)
					return
				}
			}
		}
	}

	ri.commitHeaders(statusCode)
}

// Write writes data to the connection, ensuring WriteHeader is called first.
func (ri *ResponseInterceptor) Write(b []byte) (int, error) {
	if !ri.wroteHeader {
		ri.WriteHeader(http.StatusOK)
	}

	if ri.isHTML && ri.bufferedBody != nil {
		if ri.bufferedBody.Len()+len(b) <= 2*1024*1024 {
			return ri.bufferedBody.Write(b)
		}
		// Over 2MB limit: flush buffer directly without honeypot mutation
		ri.flushBufferedHTMLDirect()
	}

	n, err := ri.ResponseWriter.Write(b)
	ri.bytesWritten += int64(n)
	return n, err
}

func (ri *ResponseInterceptor) flushBufferedHTMLDirect() {
	if !ri.isHTML || ri.bufferedBody == nil {
		return
	}
	ri.isHTML = false
	buf := ri.bufferedBody.Bytes()
	ri.bufferedBody = nil
	ri.commitHeaders(ri.statusCode)
	if len(buf) > 0 {
		n, _ := ri.ResponseWriter.Write(buf)
		ri.bytesWritten += int64(n)
	}
}

// Finish flushes any buffered HTML response with honeypot injection applied.
func (ri *ResponseInterceptor) Finish() {
	if !ri.isHTML || ri.bufferedBody == nil {
		return
	}

	body := ri.bufferedBody.Bytes()
	ri.bufferedBody = nil
	ri.isHTML = false

	if ri.honeypotInjector != nil {
		injectedBody, ok := ri.honeypotInjector.Inject(body)
		if ok {
			body = injectedBody
		}
	}

	if ri.Header().Get("Content-Length") != "" {
		ri.Header().Set("Content-Length", strconv.Itoa(len(body)))
	}

	ri.commitHeaders(ri.statusCode)
	if len(body) > 0 {
		n, _ := ri.ResponseWriter.Write(body)
		ri.bytesWritten += int64(n)
	}
}

// Flush implements http.Flusher to support streaming, SSE, and chunked transfer.
func (ri *ResponseInterceptor) Flush() {
	if ri.isHTML && ri.bufferedBody != nil {
		ri.flushBufferedHTMLDirect()
	}
	if f, ok := ri.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker to support WebSockets.
func (ri *ResponseInterceptor) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if ri.isHTML && ri.bufferedBody != nil {
		ri.flushBufferedHTMLDirect()
	}
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
