package bot

import (
	"net/http"
	"path"
	"strings"
)

// RouteType represents the categorized type of incoming HTTP request.
type RouteType string

const (
	// RouteAPI represents machine-to-machine, webhook, or JSON API traffic (bypasses interactive challenges).
	RouteAPI RouteType = "api"
	// RouteBrowser represents human-driven interactive browser navigation (target for PoW/CAPTCHA).
	RouteBrowser RouteType = "browser"
	// RouteStatic represents static assets (images, stylesheets, fonts, scripts).
	RouteStatic RouteType = "static"
)

// RouteClassifierConfig configures path prefixes, bypass headers, and static extensions.
type RouteClassifierConfig struct {
	APIPrefixes   []string `json:"api_prefixes,omitempty"`
	BypassHeaders []string `json:"bypass_headers,omitempty"`
	StaticExts    []string `json:"static_exts,omitempty"`
}

// DefaultRouteClassifierConfig provides battle-tested production defaults.
var DefaultRouteClassifierConfig = RouteClassifierConfig{
	APIPrefixes: []string{
		"/api/",
		"/api",
		"/v1/",
		"/v2/",
		"/v3/",
		"/graphql",
		"/webhook",
		"/webhooks",
		"/.well-known/",
		"/healthz",
		"/metrics",
	},
	BypassHeaders: []string{
		"Authorization",
		"X-API-Key",
		"X-Api-Key",
		"X-Webhook-Token",
		"X-Webhook-Secret",
	},
	StaticExts: []string{
		".css", ".js", ".mjs", ".map",
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif", ".bmp", ".tiff",
		".woff", ".woff2", ".ttf", ".otf", ".eot",
		".mp4", ".webm", ".ogg", ".mp3", ".wav", ".flac", ".aac",
		".wasm",
	},
}

// RouteClassifier categorizes HTTP requests into RouteAPI, RouteBrowser, or RouteStatic.
type RouteClassifier struct {
	cfg RouteClassifierConfig
}

// NewRouteClassifier constructs a RouteClassifier with the provided configuration.
func NewRouteClassifier(cfg *RouteClassifierConfig) *RouteClassifier {
	c := &RouteClassifier{}
	if cfg == nil {
		c.cfg = DefaultRouteClassifierConfig
		return c
	}

	c.cfg = *cfg
	if len(c.cfg.APIPrefixes) == 0 {
		c.cfg.APIPrefixes = DefaultRouteClassifierConfig.APIPrefixes
	}
	if len(c.cfg.BypassHeaders) == 0 {
		c.cfg.BypassHeaders = DefaultRouteClassifierConfig.BypassHeaders
	}
	if len(c.cfg.StaticExts) == 0 {
		c.cfg.StaticExts = DefaultRouteClassifierConfig.StaticExts
	}
	return c
}

// Classify classifies the request route into RouteAPI, RouteBrowser, or RouteStatic.
func (c *RouteClassifier) Classify(r *http.Request) RouteType {
	if r == nil {
		return RouteAPI
	}

	urlPath := r.URL.Path
	pathLower := strings.ToLower(urlPath)

	// 1. Static asset check (file extension)
	ext := strings.ToLower(path.Ext(pathLower))
	if ext != "" {
		for _, staticExt := range c.cfg.StaticExts {
			if ext == staticExt {
				return RouteStatic
			}
		}
	}

	// 2. API path prefix check
	for _, prefix := range c.cfg.APIPrefixes {
		if strings.HasPrefix(pathLower, prefix) || pathLower == strings.TrimSuffix(prefix, "/") {
			return RouteAPI
		}
	}

	// 3. Authorization & Machine header checks
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") ||
		strings.HasPrefix(authHeader, "Basic ") ||
		strings.HasPrefix(authHeader, "Token ") ||
		strings.HasPrefix(authHeader, "ApiKey ") {
		return RouteAPI
	}

	for _, header := range c.cfg.BypassHeaders {
		if header == "Authorization" {
			continue
		}
		if val := strings.TrimSpace(r.Header.Get(header)); val != "" {
			return RouteAPI
		}
	}

	// 4. Content negotiation & Accept header checks
	accept := strings.ToLower(r.Header.Get("Accept"))
	contentType := strings.ToLower(r.Header.Get("Content-Type"))

	// Explicit JSON / gRPC / Protobuf / octet-stream without HTML
	if !strings.Contains(accept, "text/html") {
		if strings.Contains(accept, "application/json") ||
			strings.Contains(accept, "application/problem+json") ||
			strings.Contains(accept, "application/grpc") ||
			strings.Contains(accept, "application/octet-stream") ||
			strings.Contains(contentType, "application/json") ||
			strings.Contains(contentType, "application/grpc") {
			return RouteAPI
		}

		// XHR or Fetch without text/html
		if r.Header.Get("X-Requested-With") == "XMLHttpRequest" ||
			r.Header.Get("Sec-Fetch-Dest") == "empty" {
			return RouteAPI
		}
	}

	// 5. Browser route
	return RouteBrowser
}

// ShouldBypass returns true if the route type is exempt from interactive bot challenges.
func (c *RouteClassifier) ShouldBypass(r *http.Request) bool {
	route := c.Classify(r)
	return route == RouteAPI || route == RouteStatic
}

// ShouldBypassChallenge returns true if RouteAPI or RouteStatic.
func ShouldBypassChallenge(route RouteType) bool {
	return route == RouteAPI || route == RouteStatic
}
