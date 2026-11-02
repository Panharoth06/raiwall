package caddy

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/Panharoth06/raiwall/internal/core/bot"
)

// ResponseInspectionConfig controls outbound body buffering and gating in the interceptor.
type ResponseInspectionConfig struct {
	Enabled        bool
	InspectHeaders bool
	InspectBody    bool
	BodyLimit      int
	HardCap        int
	Decompress     bool
	ContentTypes   []string
	Budget         *InflightBudget
}

// ResponseInterceptor wraps an http.ResponseWriter to capture the status code,
// count bytes written, strip sensitive upstream headers, optionally inject honeypot traps,
// and buffer eligible responses for WAF and DLP outbound inspection.
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

	inspectionCfg  ResponseInspectionConfig
	inspecting     bool
	streamed       bool
	overflowed     bool
	reservedBudget int64
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

// SetInspectionConfig enables response body buffering for outbound WAF/DLP inspection.
func (ri *ResponseInterceptor) SetInspectionConfig(cfg ResponseInspectionConfig) {
	ri.inspectionCfg = cfg
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

// BufferedBody returns a slice of buffered body bytes if available.
func (ri *ResponseInterceptor) BufferedBody() []byte {
	if ri.bufferedBody == nil {
		return nil
	}
	return ri.bufferedBody.Bytes()
}

// IsStreamed reports whether the response was flushed or hijacked directly.
func (ri *ResponseInterceptor) IsStreamed() bool {
	return ri.streamed
}

// IsOverflowed reports whether the response exceeded the hard cap or budget.
func (ri *ResponseInterceptor) IsOverflowed() bool {
	return ri.overflowed
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

	// Check if body buffering is eligible
	if statusCode != http.StatusNoContent && statusCode != http.StatusNotModified && !(statusCode >= 100 && statusCode < 200) {
		ce := strings.ToLower(ri.Header().Get("Content-Encoding"))
		isCompressed := ce != "" && ce != "identity"
		cd := strings.ToLower(ri.Header().Get("Content-Disposition"))
		isAttachment := strings.Contains(cd, "attachment")

		if !isAttachment {
			ct := ri.Header().Get("Content-Type")
			isHTML := strings.Contains(strings.ToLower(ct), "text/html")
			isInspectable := ri.inspectionCfg.Enabled && ri.inspectionCfg.InspectBody && isInspectableContentType(ct, ri.inspectionCfg.ContentTypes)
			if isCompressed && !ri.inspectionCfg.Decompress {
				isInspectable = false
			}

			shouldBufferHoneypot := ri.honeypotInjector != nil && isHTML && !isCompressed
			shouldBufferInspect := isInspectable

			if shouldBufferHoneypot || shouldBufferInspect {
				ri.isHTML = isHTML && shouldBufferHoneypot
				ri.inspecting = shouldBufferInspect
				ri.bufferedBody = new(bytes.Buffer)
				return
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

	if ri.bufferedBody != nil && !ri.streamed && !ri.overflowed {
		hardCap := ri.inspectionCfg.HardCap
		if hardCap <= 0 {
			hardCap = 8 * 1024 * 1024
		}
		if ri.isHTML && !ri.inspecting && hardCap > 2*1024*1024 {
			hardCap = 2 * 1024 * 1024
		}

		if ri.bufferedBody.Len()+len(b) <= hardCap {
			if ri.inspectionCfg.Budget == nil || ri.inspectionCfg.Budget.Reserve(int64(len(b))) {
				ri.reservedBudget += int64(len(b))
				return ri.bufferedBody.Write(b)
			}
		}

		// Over limit or budget exhausted: overflow and stream directly
		ri.overflowed = true
		ri.flushBufferedDirect()
	}

	n, err := ri.ResponseWriter.Write(b)
	ri.bytesWritten += int64(n)
	return n, err
}

func (ri *ResponseInterceptor) releaseBudget() {
	if ri.reservedBudget > 0 {
		if ri.inspectionCfg.Budget != nil {
			ri.inspectionCfg.Budget.Release(ri.reservedBudget)
		}
		ri.reservedBudget = 0
	}
}

func (ri *ResponseInterceptor) flushBufferedDirect() {
	if ri.bufferedBody == nil {
		return
	}
	buf := ri.bufferedBody.Bytes()
	ri.bufferedBody = nil
	ri.isHTML = false
	ri.inspecting = false
	ri.releaseBudget()
	ri.commitHeaders(ri.statusCode)
	if len(buf) > 0 {
		n, _ := ri.ResponseWriter.Write(buf)
		ri.bytesWritten += int64(n)
	}
}

// Finish flushes any buffered response with honeypot injection applied if HTML.
func (ri *ResponseInterceptor) Finish() {
	if ri.bufferedBody == nil {
		return
	}

	body := ri.bufferedBody.Bytes()
	ri.bufferedBody = nil
	ri.inspecting = false
	ri.releaseBudget()

	if ri.isHTML && ri.honeypotInjector != nil {
		injectedBody, ok := ri.honeypotInjector.Inject(body)
		if ok {
			body = injectedBody
		}
	}
	ri.isHTML = false

	if ri.Header().Get("Content-Length") != "" {
		ri.Header().Set("Content-Length", strconv.Itoa(len(body)))
	}

	ri.commitHeaders(ri.statusCode)
	if len(body) > 0 {
		n, _ := ri.ResponseWriter.Write(body)
		ri.bytesWritten += int64(n)
	}
}

// WriteBlockResponse writes a WAF/DLP block page instead of the buffered upstream response.
func (ri *ResponseInterceptor) WriteBlockResponse(statusCode int, body string, eventID string) {
	ri.bufferedBody = nil
	ri.isHTML = false
	ri.inspecting = false
	ri.releaseBudget()

	ri.statusCode = statusCode
	header := ri.ResponseWriter.Header()
	for _, h := range ri.stripHeaders {
		header.Del(h)
	}
	header.Set("Content-Type", "text/html; charset=utf-8")
	header.Set("Content-Length", strconv.Itoa(len(body)))
	if eventID != "" {
		header.Set("X-Raiwall-Event-ID", eventID)
	}
	ri.headerCommitted = true
	ri.ResponseWriter.WriteHeader(statusCode)
	n, _ := ri.ResponseWriter.Write([]byte(body))
	ri.bytesWritten += int64(n)
}

// ReplaceBody replaces the buffered response body with modified content (e.g. DLP redaction).
func (ri *ResponseInterceptor) ReplaceBody(newBody []byte) {
	if ri.bufferedBody == nil {
		return
	}
	diff := int64(len(newBody)) - int64(ri.bufferedBody.Len())
	if diff > 0 && ri.inspectionCfg.Budget != nil {
		if ri.inspectionCfg.Budget.Reserve(diff) {
			ri.reservedBudget += diff
		}
	} else if diff < 0 && ri.inspectionCfg.Budget != nil {
		ri.inspectionCfg.Budget.Release(-diff)
		ri.reservedBudget += diff
	}
	ri.bufferedBody.Reset()
	ri.bufferedBody.Write(newBody)
}

// Flush implements http.Flusher to support streaming, SSE, and chunked transfer.
func (ri *ResponseInterceptor) Flush() {
	if ri.bufferedBody != nil {
		ri.streamed = true
		ri.flushBufferedDirect()
	}
	if f, ok := ri.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker to support WebSockets.
func (ri *ResponseInterceptor) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if ri.bufferedBody != nil {
		ri.streamed = true
		ri.flushBufferedDirect()
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
