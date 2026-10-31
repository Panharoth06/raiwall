package waf

import (
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Straight-match SSRF external-fetch targets (cloud instance metadata endpoints).
var ssrfStrongMarkers = [...]string{
	"169.254.169.254",          // AWS EC2 / Azure instance metadata
	"metadata.google.internal", // GCP metadata
	"metadata.azure.internal",  // Azure alternate endpoints
	"100.100.100.200",          // Alibaba Cloud metadata
	"fd00:ec2::254",            // IPv6 EC2 metadata
}

// scanSSRF detects attempts to coerce the application into fetching internal or
// cloud-metadata resources through URL-shaped parameter values.
func scanSSRF(v string) (Detection, bool) {
	if !strings.ContainsAny(v, ".:@") && !strings.Contains(v, "//") {
		return Detection{}, false
	}

	lower := strings.ToLower(v)

	for _, marker := range ssrfStrongMarkers {
		if idx := strings.Index(lower, marker); idx != -1 {
			return Detection{
				Module:  ModuleSSRF,
				Level:   LevelStrong,
				Reason:  "Cloud metadata endpoint fetch attempt",
				Matched: snippet(v, idx, len(marker)),
			}, true
		}
	}

	authority := ssrfAuthority(lower)
	if authority == "" {
		return Detection{}, false
	}

	strong, weak := classifySSRFHost(authority)
	switch {
	case strong:
		return Detection{
			Module:  ModuleSSRF,
			Level:   LevelStrong,
			Reason:  "Loopback, unspecified or link-local endpoint fetch attempt",
			Matched: authority,
		}, true
	case weak:
		return Detection{
			Module:  ModuleSSRF,
			Level:   LevelWeak,
			Reason:  "Internal network endpoint fetch attempt",
			Matched: authority,
		}, true
	}

	return Detection{}, false
}

// ssrfAuthority extracts the authority component of a URL embedded in a
// parameter value. It accepts absolute (scheme://) and scheme-relative (//)
// forms and strips userinfo, path, query and fragment.
func ssrfAuthority(v string) string {
	var rest string
	if idx := strings.Index(v, "://"); idx > 0 {
		rest = v[idx+3:]
	} else if idx := strings.Index(v, "//"); idx >= 0 && (idx == 0 || isAuthorityBoundary(v[idx-1])) {
		rest = v[idx+2:]
	} else {
		return ""
	}
	if end := strings.IndexAny(rest, "/?#"); end != -1 {
		rest = rest[:end]
	}
	if at := strings.LastIndexByte(rest, '@'); at != -1 {
		rest = rest[at+1:]
	}
	return rest
}

// isAuthorityBoundary reports whether a byte may precede an embedded
// scheme-relative URL (u=//host, redirect: //host).
func isAuthorityBoundary(b byte) bool {
	switch b {
	case '=', ':', ',', '(', ' ', '\t', '\'', '"':
		return true
	default:
		return false
	}
}

// classifySSRFHost classifies a URL authority by its target address.
//
// Loopback, unspecified and link-local targets are strong signals: fetching
// them is never legitimate from an application. RFC1918/ULA ranges and the
// localhost hostname stay weak because development OAuth callbacks and
// staging integrations legitimately point there; operators can raise the SSRF
// module to strict or add a parameter exception when needed.
func classifySSRFHost(authority string) (strong, weak bool) {
	host := authority
	if strings.HasPrefix(host, "[") {
		if end := strings.IndexByte(host, ']'); end != -1 {
			host = host[1:end]
		}
	} else if colon := strings.LastIndexByte(host, ':'); colon != -1 {
		host = host[:colon]
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return false, false
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return false, true
	}
	if zone := strings.IndexByte(host, '%'); zone != -1 {
		host = host[:zone]
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		// Legacy inet_aton forms: 2130706433, 0x7f000001, 0177.0.0.1.
		var ok bool
		addr, ok = parseObfuscatedIPv4(host)
		if !ok {
			return false, false
		}
	}

	addr = addr.Unmap()
	switch {
	case addr.IsLoopback(), addr.IsUnspecified(), addr.IsLinkLocalUnicast():
		return true, false
	case addr.IsPrivate():
		return false, true
	}
	return false, false
}

// parseObfuscatedIPv4 decodes the address forms accepted by inet_aton and
// browsers: single 32-bit integers, hex/octal parts, and 2-4 component
// addresses. Attackers use these to bypass string-prefix SSRF filters.
func parseObfuscatedIPv4(host string) (netip.Addr, bool) {
	parts := strings.Split(host, ".")
	if len(parts) > 4 {
		return netip.Addr{}, false
	}

	vals := make([]uint64, len(parts))
	for i, part := range parts {
		if part == "" {
			return netip.Addr{}, false
		}
		base := 10
		switch {
		case strings.HasPrefix(part, "0x") || strings.HasPrefix(part, "0X"):
			base = 16
			part = part[2:]
			if part == "" {
				return netip.Addr{}, false
			}
		case len(part) > 1 && part[0] == '0':
			base = 8
			part = part[1:]
		}
		val, err := strconv.ParseUint(part, base, 32)
		if err != nil {
			return netip.Addr{}, false
		}
		vals[i] = val
	}

	var addr uint64
	switch len(vals) {
	case 1:
		if vals[0] > 0xFFFFFFFF {
			return netip.Addr{}, false
		}
		addr = vals[0]
	case 2:
		if vals[0] > 0xFF || vals[1] > 0xFFFFFF {
			return netip.Addr{}, false
		}
		addr = vals[0]<<24 | vals[1]
	case 3:
		if vals[0] > 0xFF || vals[1] > 0xFF || vals[2] > 0xFFFF {
			return netip.Addr{}, false
		}
		addr = vals[0]<<24 | vals[1]<<16 | vals[2]
	case 4:
		for _, val := range vals {
			if val > 0xFF {
				return netip.Addr{}, false
			}
		}
		addr = vals[0]<<24 | vals[1]<<16 | vals[2]<<8 | vals[3]
	default:
		return netip.Addr{}, false
	}

	var b [4]byte
	b[0] = byte(addr >> 24)
	b[1] = byte(addr >> 16)
	b[2] = byte(addr >> 8)
	b[3] = byte(addr)
	return netip.AddrFrom4(b), true
}

// Dangerous upload extensions blocked confidently in Balance mode.
var uploadStrongExt = [...]string{
	".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml", ".pht",
	".jsp", ".jspx", ".jspa", ".asp", ".aspx", ".asax", ".ashx", ".asmx", ".cer",
	".exe", ".dll", ".so", ".sh", ".bash", ".cgi",
}

// Script extensions tolerated in Balance mode (legit tooling uploads).
var uploadWeakExt = [...]string{
	".py", ".rb", ".pl", ".lua", ".ps1", ".bat", ".cmd",
}

// scanFileUpload inspects multipart file-part values for executable or
// polyglot upload attempts. It is context-gated on the extractor's
// `<field>.filename` naming convention, so ordinary form fields never trip it.
func scanFileUpload(paramName, v string) (Detection, bool) {
	if !strings.HasSuffix(paramName, ".filename") || v == "" {
		return Detection{}, false
	}

	basename := v
	if idx := strings.LastIndexAny(basename, "/\\"); idx != -1 {
		basename = basename[idx+1:]
	}

	lower := strings.ToLower(basename)

	// Double-extension bypass (shell.php.jpg): dangerous extension not at tail.
	// Requiring the trailing dot prevents substring false positives (e.g. ".source").
	for _, ext := range uploadStrongExt {
		if strings.Contains(lower, ext+".") {
			return Detection{
				Module:  ModuleFileUpload,
				Level:   LevelStrong,
				Reason:  fmt.Sprintf("Double-extension upload bypass (%s…)", ext),
				Matched: basename,
			}, true
		}
	}

	// Plain dangerous tail extension
	for _, ext := range uploadStrongExt {
		if strings.HasSuffix(lower, ext) {
			return Detection{
				Module:  ModuleFileUpload,
				Level:   LevelStrong,
				Reason:  fmt.Sprintf("Executable file upload (%s)", ext),
				Matched: basename,
			}, true
		}
	}

	// Weak: tooling extensions that frequently have legitimate uses.
	for _, ext := range uploadWeakExt {
		if strings.HasSuffix(lower, ext) {
			return Detection{
				Module:  ModuleFileUpload,
				Level:   LevelWeak,
				Reason:  fmt.Sprintf("Script file upload (%s)", ext),
				Matched: basename,
			}, true
		}
	}

	return Detection{}, false
}

// scanMalHTTP detects HTTP request-smuggling structural anomalies:
// duplicate Content-Length headers, Content-Length + Transfer-Encoding pairs,
// and duplicated or obfuscated Transfer-Encoding values. Values count on the
// canonical http.Header map: Go's textproto parser folds duplicate header lines
// into a single multi-element entry.
func scanMalHTTP(headers http.Header) (Detection, bool) {
	if headers == nil {
		return Detection{}, false
	}

	contentLengths := headers.Values("Content-Length")
	transferEncodings := headers.Values("Transfer-Encoding")

	if len(contentLengths) > 1 {
		return Detection{
			Module:  ModuleMalHTTP,
			Level:   LevelStrong,
			Reason:  "Duplicate Content-Length headers (request smuggling)",
			Matched: "content-length x" + fmt.Sprint(len(contentLengths)),
		}, true
	}

	if len(transferEncodings) > 1 {
		// Normalize values for comparison: TE is case-insensitive.
		normalized := make([]string, 0, len(transferEncodings))
		seenDistinct := false
		for i, te := range transferEncodings {
			t := strings.ToLower(strings.TrimSpace(te))
			normalized = append(normalized, t)
			if i > 0 && t != normalized[0] {
				seenDistinct = true
			}
		}
		if seenDistinct {
			return Detection{
				Module:  ModuleMalHTTP,
				Level:   LevelStrong,
				Reason:  "Conflicting Transfer-Encoding headers (request smuggling)",
				Matched: "transfer-encoding x" + fmt.Sprint(len(transferEncodings)),
			}, true
		}
		return Detection{
			Module:  ModuleMalHTTP,
			Level:   LevelWeak,
			Reason:  "Duplicate Transfer-Encoding headers",
			Matched: "transfer-encoding x" + fmt.Sprint(len(transferEncodings)),
		}, true
	}

	if len(contentLengths) == 1 && len(transferEncodings) == 1 {
		return Detection{
			Module:  ModuleMalHTTP,
			Level:   LevelStrong,
			Reason:  "Content-Length present together with Transfer-Encoding (CL.TE smuggling)",
			Matched: "content-length+transfer-encoding",
		}, true
	}

	// Obfuscated Transfer-Encoding values (bf. "chunked" vs "chunkus") — hop-by-hop
	// confusion is a classic smuggling pre-stage.
	if len(transferEncodings) == 1 {
		te := strings.ToLower(strings.TrimSpace(transferEncodings[0]))
		if te != "" && te != "chunked" && te != "identity" {
			return Detection{
				Module:  ModuleMalHTTP,
				Level:   LevelWeak,
				Reason:  "Unrecognized Transfer-Encoding value",
				Matched: te,
			}, true
		}
	}

	return Detection{}, false
}

// detectCSRF validates Origin/Referer co-location with the target host on
// state-changing methods. Cross-origin misses are strong signals; malformed or
// "null" origins and Referer-only mismatches are weak signals.
func detectCSRF(method string, headers http.Header, host string) (Detection, bool) {
	if headers == nil || host == "" {
		return Detection{}, false
	}
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
	default:
		return Detection{}, false
	}

	if origin := headers.Get("Origin"); origin != "" {
		if origin == "null" {
			return Detection{
				Module:  ModuleCSRF,
				Level:   LevelWeak,
				Reason:  "Origin null on state-changing request",
				Matched: "null origin",
			}, true
		}
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" {
			return Detection{
				Module:  ModuleCSRF,
				Level:   LevelWeak,
				Reason:  "Malformed Origin header",
				Matched: origin,
			}, true
		}
		if normalizeCSRFHost(u.Host) != normalizeCSRFHost(host) {
			return Detection{
				Module:  ModuleCSRF,
				Level:   LevelStrong,
				Reason:  fmt.Sprintf("Cross-origin request: origin %q does not match host %q", u.Host, host),
				Matched: origin,
			}, true
		}
		// Same-origin request: no CSRF detection.
		return Detection{}, false
	}

	// Referer fallback when Origin is absent (HTML form posts from legacy pages).
	if referer := headers.Get("Referer"); referer != "" {
		u, err := url.Parse(referer)
		if err == nil && u.Host != "" && normalizeCSRFHost(u.Host) != normalizeCSRFHost(host) {
			return Detection{
				Module:  ModuleCSRF,
				Level:   LevelWeak,
				Reason:  fmt.Sprintf("Referer %q does not match host %q", u.Host, host),
				Matched: referer,
			}, true
		}
	}

	return Detection{}, false
}

// normalizeCSRFHost lowercases and strips default ports so that
// "example.com:443" and "example.com" compare equal.
func normalizeCSRFHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	for _, suffix := range []string{":443", ":80"} {
		if strings.HasSuffix(h, suffix) {
			return strings.TrimSuffix(h, suffix)
		}
	}
	return h
}

// requestLevelDetection pairs a request-level detection with a stable
// pseudo-parameter name used in verdict reasons and exception matching.
type requestLevelDetection struct {
	detection Detection
	paramName string
}

// requestLevelDetections evaluates the protocol/context scanners that operate
// on the whole request rather than on individual parameters.
func requestLevelDetections(ctx *RequestContext) []requestLevelDetection {
	var out []requestLevelDetection

	if d, ok := scanMalHTTP(ctx.Headers); ok {
		out = append(out, requestLevelDetection{detection: d, paramName: "*"})
	}
	if d, ok := detectCSRF(ctx.Method, ctx.Headers, ctx.Host); ok {
		out = append(out, requestLevelDetection{detection: d, paramName: "*"})
	}

	return out
}
