package api

import (
	"encoding/json"
	"net/http"
)

// OpenAPISpec returns the complete OpenAPI 3.1 JSON document for Raiwall Control Plane.
func OpenAPISpec() map[string]any {
	return map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":       "Raiwall Control Plane API",
			"version":     "1.0.0",
			"description": "Enterprise-grade WAF & Gateway Control Plane REST API with 2-tier RBAC, staged deployments, and 1-click rollback.",
		},
		"servers": []map[string]any{
			{"url": "/api/v1", "description": "Raiwall API v1 Gateway"},
		},
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"BearerAuth": map[string]any{
					"type":        "http",
					"scheme":      "bearer",
					"description": "Raiwall API Key token",
				},
				"ApiKeyAuth": map[string]any{
					"type": "apiKey",
					"in":   "header",
					"name": "X-Raiwall-Key",
				},
				"CookieAuth": map[string]any{
					"type": "apiKey",
					"in":   "cookie",
					"name": SessionCookieName,
				},
			},
		},
		"security": []map[string]any{
			{"BearerAuth": []any{}},
			{"ApiKeyAuth": []any{}},
			{"CookieAuth": []any{}},
		},
		"paths": map[string]any{
			"/auth/login": map[string]any{
				"post": map[string]any{
					"summary":     "Authenticate administrator or viewer",
					"description": "Authenticates credentials and establishes session cookie",
					"security":    []any{},
					"responses": map[string]any{
						"200": map[string]any{"description": "Authentication successful"},
						"401": map[string]any{"description": "Invalid username or password"},
					},
				},
			},
			"/auth/logout": map[string]any{
				"post": map[string]any{
					"summary": "Invalidate session cookie",
					"responses": map[string]any{
						"200": map[string]any{"description": "Logged out successfully"},
					},
				},
			},
			"/auth/me": map[string]any{
				"get": map[string]any{
					"summary": "Get authenticated user profile and role",
					"responses": map[string]any{
						"200": map[string]any{"description": "Current user context"},
					},
				},
			},
			"/sites": map[string]any{
				"get": map[string]any{
					"summary": "List all configured sites and upstreams",
					"responses": map[string]any{
						"200": map[string]any{"description": "List of site configurations"},
					},
				},
				"post": map[string]any{
					"summary": "Create a new protected site configuration (admin only)",
					"responses": map[string]any{
						"201": map[string]any{"description": "Site created in draft"},
						"403": map[string]any{"description": "Forbidden for viewer role"},
					},
				},
			},
			"/sites/{id}": map[string]any{
				"get":    map[string]any{"summary": "Get site details by ID"},
				"put":    map[string]any{"summary": "Update site configuration (admin only)"},
				"delete": map[string]any{"summary": "Delete site configuration (admin only)"},
			},
			"/exceptions": map[string]any{
				"get":  map[string]any{"summary": "List false-positive exception rules"},
				"post": map[string]any{"summary": "Create an exception rule (admin only)"},
			},
			"/exceptions/{id}": map[string]any{
				"get":    map[string]any{"summary": "Get exception rule by ID"},
				"put":    map[string]any{"summary": "Update exception rule (admin only)"},
				"delete": map[string]any{"summary": "Delete exception rule (admin only)"},
			},
			"/exceptions/test": map[string]any{
				"post": map[string]any{
					"summary": "Dry-run test an exception rule against synthetic HTTP parameters",
				},
			},
			"/acls": map[string]any{
				"get":  map[string]any{"summary": "List compiled ACL rules"},
				"post": map[string]any{"summary": "Create an ACL rule (admin only)"},
			},
			"/acls/{id}": map[string]any{
				"get":    map[string]any{"summary": "Get ACL rule by ID"},
				"put":    map[string]any{"summary": "Update ACL rule (admin only)"},
				"delete": map[string]any{"summary": "Delete ACL rule (admin only)"},
			},
			"/acls/test": map[string]any{
				"post": map[string]any{
					"summary": "Dry-run syntax validation and test evaluation of an expr ACL rule",
				},
			},
			"/policies/rate": map[string]any{
				"get":  map[string]any{"summary": "List rate limiting policies"},
				"post": map[string]any{"summary": "Create rate limiting policy (admin only)"},
			},
			"/policies/rate/{id}": map[string]any{
				"get":    map[string]any{"summary": "Get rate policy by ID"},
				"put":    map[string]any{"summary": "Update rate policy (admin only)"},
				"delete": map[string]any{"summary": "Delete rate policy (admin only)"},
			},
			"/policies/bot": map[string]any{
				"get":  map[string]any{"summary": "List bot defense configurations"},
				"post": map[string]any{"summary": "Create bot defense configuration (admin only)"},
			},
			"/policies/bot/{id}": map[string]any{
				"get":    map[string]any{"summary": "Get bot config by ID"},
				"put":    map[string]any{"summary": "Update bot config (admin only)"},
				"delete": map[string]any{"summary": "Delete bot config (admin only)"},
			},
			"/config/draft/diff": map[string]any{
				"get": map[string]any{
					"summary": "Get visual diff of staged database changes vs active live snapshot",
				},
			},
			"/config/apply": map[string]any{
				"post": map[string]any{
					"summary": "Pre-flight validate, commit snapshot revision, and execute atomic data plane swap",
				},
			},
			"/config/rollback/{version}": map[string]any{
				"post": map[string]any{
					"summary": "Instantly revert active data plane to historical snapshot version",
				},
			},
			"/config/snapshots": map[string]any{
				"get": map[string]any{
					"summary": "List all historical configuration snapshot revisions",
				},
			},
			"/apikeys": map[string]any{
				"get":  map[string]any{"summary": "List all API keys (admin only)"},
				"post": map[string]any{"summary": "Generate a new API key with role (admin only)"},
			},
			"/apikeys/{id}": map[string]any{
				"delete": map[string]any{"summary": "Revoke API key (admin only)"},
			},
		},
	}
}

// ServeOpenAPISpec writes the OpenAPI 3.1 JSON specification to the response.
func ServeOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(OpenAPISpec())
}

// ServeScalarDocs serves the interactive Scalar API documentation UI.
func ServeScalarDocs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	const scalarHTML = `<!doctype html>
<html>
  <head>
    <title>Raiwall Control Plane API Documentation</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style>
      body { margin: 0; background-color: #0b0f19; color: #fff; font-family: sans-serif; }
    </style>
  </head>
  <body>
    <script
      id="api-reference"
      data-url="/.raiwall/api/openapi.json"
      data-configuration='{"theme":"purple","layout":"modern"}'></script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
  </body>
</html>`
	_, _ = w.Write([]byte(scalarHTML))
}

// ServeSwaggerDocs serves the interactive Swagger UI.
func ServeSwaggerDocs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	const swaggerHTML = `<!doctype html>
<html>
  <head>
    <title>Raiwall Swagger UI</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui.css" />
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-bundle.js"></script>
    <script>
      window.onload = () => {
        window.ui = SwaggerUIBundle({
          url: '/.raiwall/api/openapi.json',
          dom_id: '#swagger-ui',
        });
      };
    </script>
  </body>
</html>`
	_, _ = w.Write([]byte(swaggerHTML))
}
