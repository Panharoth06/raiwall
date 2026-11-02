package caddy

import (
	"net/http"
	"strings"
)

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

func isInspectableContentType(ct string, allowed []string) bool {
	ct = strings.TrimSpace(ct)
	if ct == "" {
		return false
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(ct, ";")[0]))
	if mediaType == "text/event-stream" {
		return false
	}
	if strings.HasPrefix(mediaType, "text/") {
		return true
	}
	if mediaType == "application/json" || strings.HasSuffix(mediaType, "+json") {
		return true
	}
	if mediaType == "application/xml" || strings.HasSuffix(mediaType, "+xml") {
		return true
	}
	if mediaType == "application/javascript" || mediaType == "text/javascript" || mediaType == "application/x-javascript" {
		return true
	}
	for _, a := range allowed {
		if strings.EqualFold(mediaType, strings.TrimSpace(a)) {
			return true
		}
	}
	return false
}
