package templates

import (
	"net/http"
)

// DefaultTemplateDef holds definition for a built-in deterministic response template.
type DefaultTemplateDef struct {
	StatusCode int
	Title      string
	HTML       string
	CSS        string
	BrandName  string
}

// BuiltinTemplates returns the complete map of default response templates.
func BuiltinTemplates() map[int]DefaultTemplateDef {
	return map[int]DefaultTemplateDef{
		http.StatusForbidden: {
			StatusCode: 403,
			Title:      "Security Violation - Request Blocked",
			BrandName:  "Raiwall",
			CSS:        baseTemplateCSS,
			HTML:       template403HTML,
		},
		http.StatusNotFound: {
			StatusCode: 404,
			Title:      "Resource Not Found",
			BrandName:  "Raiwall",
			CSS:        baseTemplateCSS,
			HTML:       template404HTML,
		},
		http.StatusTooManyRequests: {
			StatusCode: 429,
			Title:      "Too Many Requests - Rate Limited",
			BrandName:  "Raiwall",
			CSS:        baseTemplateCSS,
			HTML:       template429HTML,
		},
		465: {
			StatusCode: 465,
			Title:      "Virtual Waiting Room - Queue Buffer",
			BrandName:  "Raiwall",
			CSS:        baseTemplateCSS,
			HTML:       template465HTML,
		},
		466: {
			StatusCode: 466,
			Title:      "Application Offline - Maintenance Mode",
			BrandName:  "Raiwall",
			CSS:        baseTemplateCSS,
			HTML:       template466HTML,
		},
		467: {
			StatusCode: 467,
			Title:      "Pre-Application Identity Gateway",
			BrandName:  "Raiwall",
			CSS:        baseTemplateCSS,
			HTML:       template467HTML,
		},
		468: {
			StatusCode: 468,
			Title:      "Automated Traffic Verification - PoW Challenge",
			BrandName:  "Raiwall",
			CSS:        baseTemplateCSS,
			HTML:       template468HTML,
		},
		http.StatusBadGateway: {
			StatusCode: 502,
			Title:      "Bad Gateway - Upstream Unreachable",
			BrandName:  "Raiwall",
			CSS:        baseTemplateCSS,
			HTML:       template502HTML,
		},
		http.StatusServiceUnavailable: {
			StatusCode: 503,
			Title:      "Service Unavailable - Maintenance Mode",
			BrandName:  "Raiwall",
			CSS:        baseTemplateCSS,
			HTML:       template466HTML,
		},
		http.StatusGatewayTimeout: {
			StatusCode: 504,
			Title:      "Gateway Timeout - Upstream Response Exceeded",
			BrandName:  "Raiwall",
			CSS:        baseTemplateCSS,
			HTML:       template504HTML,
		},
	}
}

const baseTemplateCSS = `
:root {
  --bg: #121212;
  --card: #1a1a1a;
  --border: #2e2e2e;
  --text: #f5f5f5;
  --muted: #a8a8a8;
  --threat: #ef4444;
  --accent: #22d3ee;
  --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background-color: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 1.5rem;
}
.container {
  max-width: 640px;
  width: 100%;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 2.5rem;
}
.header {
  display: flex;
  align-items: center;
  gap: 1rem;
  margin-bottom: 1.5rem;
  border-bottom: 1px solid var(--border);
  padding-bottom: 1.25rem;
}
.brand {
  font-size: 1.125rem;
  font-weight: 700;
  letter-spacing: -0.025em;
  color: var(--text);
}
.status-badge {
  font-family: var(--font-mono);
  font-size: 0.875rem;
  font-weight: 600;
  padding: 0.25rem 0.625rem;
  border-radius: 4px;
  background: rgba(239, 68, 68, 0.15);
  color: var(--threat);
  border: 1px solid rgba(239, 68, 68, 0.3);
}
.title {
  font-size: 1.5rem;
  font-weight: 600;
  margin-bottom: 0.75rem;
  line-height: 1.3;
}
.description {
  color: var(--muted);
  font-size: 0.95rem;
  line-height: 1.6;
  margin-bottom: 1.75rem;
}
.meta-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.75rem;
  background: rgba(0, 0, 0, 0.28);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 1rem;
  font-family: var(--font-mono);
  font-size: 0.8125rem;
  margin-bottom: 1.5rem;
}
.meta-item { display: flex; flex-direction: column; gap: 0.25rem; }
.meta-label { color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
.meta-val { color: var(--text); word-break: break-all; }
.footer {
  font-size: 0.8125rem;
  color: var(--muted);
  text-align: center;
}
@media (max-width: 560px) {
  .container { padding: 1.75rem; }
  .header { flex-wrap: wrap; }
  .meta-grid { grid-template-columns: 1fr; }
  .title { font-size: 1.25rem; }
}
`
