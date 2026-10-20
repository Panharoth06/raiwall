package bot

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/Panharoth06/raiwall/internal/core/waf"
)

// BotVerdict contains classification results for a client connection.
type BotVerdict struct {
	IsBot       bool           `json:"is_bot"`
	IsSpoofed   bool           `json:"is_spoofed"`
	BotCategory BotCategory    `json:"bot_category"`
	Confidence  float64        `json:"confidence"`
	Action      waf.Action  `json:"action"`
	StatusCode  int            `json:"status_code,omitempty"`
	Reason      string         `json:"reason,omitempty"`
	ToolName    string         `json:"tool_name,omitempty"`
}

// BotClassifier inspects incoming client requests and JA4 fingerprints
// to detect automated tools, scanners, and User-Agent spoofing.
type BotClassifier struct {
	knownSignatures map[string]KnownSignature
}

// ClassifierOption configures a BotClassifier instance.
type ClassifierOption func(*BotClassifier)

// WithSignatures replaces or seeds the known signature catalog.
func WithSignatures(sigs map[string]KnownSignature) ClassifierOption {
	return func(c *BotClassifier) {
		for k, v := range sigs {
			c.knownSignatures[k] = v
		}
	}
}

// WithCustomSignature adds an individual known JA4 signature.
func WithCustomSignature(ja4 string, sig KnownSignature) ClassifierOption {
	return func(c *BotClassifier) {
		c.knownSignatures[ja4] = sig
	}
}

// NewBotClassifier creates an initialized BotClassifier.
func NewBotClassifier(opts ...ClassifierOption) *BotClassifier {
	c := &BotClassifier{
		knownSignatures: make(map[string]KnownSignature, len(DefaultKnownSignatures)),
	}
	for k, v := range DefaultKnownSignatures {
		c.knownSignatures[k] = v
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Classify evaluates the request and JA4 fingerprint to produce a BotVerdict.
func (c *BotClassifier) Classify(r *http.Request, ja4 string) *BotVerdict {
	if r == nil {
		return &BotVerdict{
			IsBot:      false,
			Action:     waf.ActionAllow,
			Confidence: 0.0,
		}
	}

	if ja4 == "" {
		ja4 = ExtractJA4(r)
	}

	ua := r.UserAgent()
	uaLower := strings.ToLower(ua)
	claimsBrowser := isBrowserUserAgent(ua)

	// 1. Correlate JA4 against known tool / library / scanner signatures
	if ja4 != "" {
		if sig, found := c.knownSignatures[ja4]; found {
			// If JA4 indicates CLI/library/scanner, but User-Agent claims to be a browser -> SPOOFING!
			if claimsBrowser {
				return &BotVerdict{
					IsBot:       true,
					IsSpoofed:   true,
					BotCategory: sig.BotCategory,
					ToolName:    sig.ToolName,
					Confidence:  0.99,
					Action:      waf.ActionBlock,
					StatusCode:  http.StatusForbidden,
					Reason:      fmt.Sprintf("USER_AGENT_SPOOFING: %s TLS fingerprint masquerading as browser", sig.ToolName),
				}
			}

			// JA4 matches known tool and UA is not claiming to be a browser
			action := waf.ActionAllow
			statusCode := 0
			if sig.BotCategory == BotCategoryScanner {
				action = waf.ActionBlock
				statusCode = http.StatusForbidden
			}
			return &BotVerdict{
				IsBot:       true,
				IsSpoofed:   false,
				BotCategory: sig.BotCategory,
				ToolName:    sig.ToolName,
				Confidence:  0.95,
				Action:      action,
				StatusCode:  statusCode,
				Reason:      fmt.Sprintf("KNOWN_TOOL_JA4: %s", sig.ToolName),
			}
		}

		// 2. JA4 Protocol / ALPN Anomaly Checks for clients claiming to be modern browsers
		// JA4 format: (t|q)(12|13|00)(d|i)(cipher count)(ext count)(h2|h1|00)
		if claimsBrowser && len(ja4) >= 10 {
			// Section a is the first 10 characters: e.g. "t13d1516h2"
			alpnPart := ja4[8:10]
			sniPart := ja4[3]

			// Modern desktop/mobile browsers always negotiate ALPN (h2 or h1), never 00.
			if alpnPart == "00" {
				return &BotVerdict{
					IsBot:       true,
					IsSpoofed:   true,
					BotCategory: BotCategoryLibrary,
					Confidence:  0.92,
					Action:      waf.ActionBlock,
					StatusCode:  http.StatusForbidden,
					Reason:      "USER_AGENT_SPOOFING: browser User-Agent without ALPN negotiation",
				}
			}

			// Modern browsers accessing a domain name always supply SNI (part 'd').
			// If 'i', the client provided no SNI or connected directly to an IP without SNI.
			hostName := r.Host
			if h, _, err := net.SplitHostPort(r.Host); err == nil {
				hostName = h
			}
			cleanHost := strings.Trim(hostName, "[]")
			if sniPart == 'i' && net.ParseIP(cleanHost) == nil && hostName != "localhost" && hostName != "" {
				return &BotVerdict{
					IsBot:       true,
					IsSpoofed:   true,
					BotCategory: BotCategoryLibrary,
					Confidence:  0.88,
					Action:      waf.ActionBlock,
					StatusCode:  http.StatusForbidden,
					Reason:      "USER_AGENT_SPOOFING: browser User-Agent without SNI in TLS handshake",
				}
			}
		}
	}

	// 3. HTTP/2 Frame Fingerprint Correlation
	h2 := ExtractHTTP2Fingerprint(r)
	if h2 != nil {
		if isSpoofed, reason := CorrelateH2WithUA(h2, ua); isSpoofed {
			return &BotVerdict{
				IsBot:       true,
				IsSpoofed:   true,
				BotCategory: BotCategoryLibrary,
				Confidence:  0.95,
				Action:      waf.ActionBlock,
				StatusCode:  http.StatusForbidden,
				Reason:      reason,
			}
		}
	}

	// 4. User-Agent Pattern Inspection
	for _, pattern := range KnownToolUAPatterns {
		if strings.Contains(uaLower, strings.ToLower(pattern.Substr)) {
			action := waf.ActionAllow
			statusCode := 0
			if pattern.Category == BotCategoryScanner {
				action = waf.ActionBlock
				statusCode = http.StatusForbidden
			}
			return &BotVerdict{
				IsBot:       true,
				IsSpoofed:   false,
				BotCategory: pattern.Category,
				ToolName:    pattern.ToolName,
				Confidence:  1.0,
				Action:      action,
				StatusCode:  statusCode,
				Reason:      fmt.Sprintf("KNOWN_TOOL_UA: %s", pattern.ToolName),
			}
		}
	}

	// 4. Empty User-Agent
	if strings.TrimSpace(ua) == "" {
		return &BotVerdict{
			IsBot:       true,
			IsSpoofed:   false,
			BotCategory: BotCategoryUnknown,
			Confidence:  0.80,
			Action:      waf.ActionAllow,
			Reason:      "EMPTY_USER_AGENT",
		}
	}

	// 5. Legitimate Browser User-Agent
	if claimsBrowser {
		return &BotVerdict{
			IsBot:       false,
			IsSpoofed:   false,
			BotCategory: BotCategoryBrowser,
			Confidence:  0.90,
			Action:      waf.ActionAllow,
		}
	}

	// 6. Generic unclassified client
	return &BotVerdict{
		IsBot:       false,
		IsSpoofed:   false,
		BotCategory: BotCategoryUnknown,
		Confidence:  0.50,
		Action:      waf.ActionAllow,
	}
}

// isBrowserUserAgent checks if the User-Agent claims to be a modern web browser.
func isBrowserUserAgent(ua string) bool {
	if !strings.Contains(ua, "Mozilla/5.0") {
		return false
	}
	uaLower := strings.ToLower(ua)
	// Check for automated drivers claiming Mozilla
	if strings.Contains(uaLower, "headlesschrome") ||
		strings.Contains(uaLower, "phantomjs") ||
		strings.Contains(uaLower, "selenium") ||
		strings.Contains(uaLower, "puppeteer") ||
		strings.Contains(uaLower, "playwright") {
		return false
	}

	return strings.Contains(uaLower, "chrome") ||
		strings.Contains(uaLower, "safari") ||
		strings.Contains(uaLower, "firefox") ||
		strings.Contains(uaLower, "edg") ||
		strings.Contains(uaLower, "opr")
}
