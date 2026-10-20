package bot

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Header constants for HTTP/2 fingerprint ingestion from edge proxies/CDNs.
const (
	HeaderXHTTP2Fingerprint = "X-HTTP2-Fingerprint"
	HeaderXH2Fingerprint    = "X-H2-Fingerprint"
)

type h2ContextKey string

const http2ContextKey h2ContextKey = "raiwall.bot.h2"

// HTTP2Setting represents a single SETTINGS frame parameter ID and value.
type HTTP2Setting struct {
	ID    uint16 `json:"id"`
	Value uint32 `json:"value"`
}

// HTTP2Fingerprint contains the captured HTTP/2 connection parameters.
type HTTP2Fingerprint struct {
	Settings          []HTTP2Setting `json:"settings,omitempty"`
	WindowUpdate      uint32         `json:"window_update,omitempty"`
	PseudoHeaderOrder []string       `json:"pseudo_header_order,omitempty"`
	RawString         string         `json:"raw_string,omitempty"`
	Hash              string         `json:"hash,omitempty"`
}

// WithHTTP2Fingerprint stores an HTTP2Fingerprint in the request context.
func WithHTTP2Fingerprint(ctx context.Context, fp *HTTP2Fingerprint) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, http2ContextKey, fp)
}

// GetHTTP2Fingerprint retrieves an HTTP2Fingerprint from the request context.
func GetHTTP2Fingerprint(ctx context.Context) *HTTP2Fingerprint {
	if ctx == nil {
		return nil
	}
	if fp, ok := ctx.Value(http2ContextKey).(*HTTP2Fingerprint); ok {
		return fp
	}
	return nil
}

// ComputeH2Fingerprint generates the canonical Akamai-style HTTP/2 fingerprint string:
// <settings>|<window_update>|<priority>|<pseudo_headers>
func ComputeH2Fingerprint(fp *HTTP2Fingerprint) string {
	if fp == nil {
		return ""
	}

	// 1. Settings string: e.g. 1:65536,2:0,4:6291456,6:262144
	var settingsParts []string
	for _, s := range fp.Settings {
		settingsParts = append(settingsParts, fmt.Sprintf("%d:%d", s.ID, s.Value))
	}
	settingsStr := strings.Join(settingsParts, ",")

	// 2. Window update increment
	windowUpdateStr := strconv.FormatUint(uint64(fp.WindowUpdate), 10)

	// 3. Priority (default 0)
	priorityStr := "0"

	// 4. Pseudo-header order: e.g. m,a,s,p
	pseudoStr := strings.Join(fp.PseudoHeaderOrder, ",")

	return fmt.Sprintf("%s|%s|%s|%s", settingsStr, windowUpdateStr, priorityStr, pseudoStr)
}

// ComputeH2Hash returns the MD5 hex digest of the canonical HTTP/2 fingerprint string.
func ComputeH2Hash(fp *HTTP2Fingerprint) string {
	canonical := ComputeH2Fingerprint(fp)
	if canonical == "" {
		return ""
	}
	h := md5.Sum([]byte(canonical))
	return hex.EncodeToString(h[:])
}

// ParseH2Fingerprint parses a canonical HTTP/2 fingerprint string into an HTTP2Fingerprint.
func ParseH2Fingerprint(raw string) (*HTTP2Fingerprint, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty fingerprint string")
	}

	parts := strings.Split(raw, "|")
	if len(parts) < 4 {
		return nil, fmt.Errorf("invalid http/2 fingerprint format: expected at least 4 pipe-delimited fields")
	}

	fp := &HTTP2Fingerprint{
		RawString: raw,
	}

	// Parse settings
	if parts[0] != "" {
		settingTokens := strings.Split(parts[0], ",")
		for _, token := range settingTokens {
			kv := strings.Split(token, ":")
			if len(kv) == 2 {
				id, err1 := strconv.ParseUint(kv[0], 10, 16)
				val, err2 := strconv.ParseUint(kv[1], 10, 32)
				if err1 == nil && err2 == nil {
					fp.Settings = append(fp.Settings, HTTP2Setting{
						ID:    uint16(id),
						Value: uint32(val),
					})
				}
			}
		}
	}

	// Parse window update
	if parts[1] != "" {
		if wu, err := strconv.ParseUint(parts[1], 10, 32); err == nil {
			fp.WindowUpdate = uint32(wu)
		}
	}

	// Parse pseudo-headers
	if parts[3] != "" {
		pseudoTokens := strings.Split(parts[3], ",")
		for _, token := range pseudoTokens {
			trimmed := strings.TrimSpace(token)
			if trimmed != "" {
				fp.PseudoHeaderOrder = append(fp.PseudoHeaderOrder, trimmed)
			}
		}
	}

	fp.Hash = ComputeH2Hash(fp)
	return fp, nil
}

// ExtractHTTP2Fingerprint extracts HTTP/2 connection parameters from context or headers.
func ExtractHTTP2Fingerprint(r *http.Request) *HTTP2Fingerprint {
	if r == nil {
		return nil
	}

	// 1. Check request context
	if fp := GetHTTP2Fingerprint(r.Context()); fp != nil {
		return fp
	}

	// 2. Check header fallbacks
	headerVal := r.Header.Get(HeaderXHTTP2Fingerprint)
	if headerVal == "" {
		headerVal = r.Header.Get(HeaderXH2Fingerprint)
	}

	if headerVal != "" {
		if fp, err := ParseH2Fingerprint(headerVal); err == nil {
			return fp
		}
	}

	return nil
}

// CorrelateH2WithUA checks for inconsistencies between the HTTP/2 fingerprint and User-Agent.
func CorrelateH2WithUA(fp *HTTP2Fingerprint, ua string) (isSpoofed bool, reason string) {
	if fp == nil || ua == "" {
		return false, ""
	}

	pseudoStr := strings.Join(fp.PseudoHeaderOrder, ",")
	uaLower := strings.ToLower(ua)

	// Chrome: m,a,s,p
	// Firefox: m,p,a,s
	// Safari: m,s,p,a
	if strings.Contains(uaLower, "chrome") && !strings.Contains(uaLower, "edg") && !strings.Contains(uaLower, "opr") {
		// If UA is Chrome, but pseudo-headers are clearly Firefox (m,p,a,s)
		if pseudoStr == "m,p,a,s" {
			return true, "HTTP2_SPOOFING: Chrome User-Agent exhibiting Firefox pseudo-header order (m,p,a,s)"
		}
		// If UA is Chrome, but pseudo-headers are clearly Safari (m,s,p,a)
		if pseudoStr == "m,s,p,a" {
			return true, "HTTP2_SPOOFING: Chrome User-Agent exhibiting Safari pseudo-header order (m,s,p,a)"
		}
	}

	if strings.Contains(uaLower, "firefox") {
		// If UA is Firefox, but pseudo-headers are clearly Chrome (m,a,s,p)
		if pseudoStr == "m,a,s,p" {
			return true, "HTTP2_SPOOFING: Firefox User-Agent exhibiting Chrome pseudo-header order (m,a,s,p)"
		}
	}

	if strings.Contains(uaLower, "safari") && !strings.Contains(uaLower, "chrome") && !strings.Contains(uaLower, "android") {
		// If UA is Safari, but pseudo-headers are clearly Chrome (m,a,s,p)
		if pseudoStr == "m,a,s,p" {
			return true, "HTTP2_SPOOFING: Safari User-Agent exhibiting Chrome pseudo-header order (m,a,s,p)"
		}
		// If UA is Safari, but pseudo-headers are clearly Firefox (m,p,a,s)
		if pseudoStr == "m,p,a,s" {
			return true, "HTTP2_SPOOFING: Safari User-Agent exhibiting Firefox pseudo-header order (m,p,a,s)"
		}
	}

	// Check for headless / Go / CLI settings claiming to be full desktop browser
	if isBrowserUserAgent(ua) && len(fp.Settings) > 0 {
		// Go client sends only 1 setting: 2:0
		if len(fp.Settings) == 1 && fp.Settings[0].ID == 2 && fp.Settings[0].Value == 0 {
			return true, "HTTP2_SPOOFING: Browser User-Agent with Go http2 SETTINGS frame (2:0)"
		}
	}

	return false, ""
}
