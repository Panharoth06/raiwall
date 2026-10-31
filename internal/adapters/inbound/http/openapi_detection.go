package api

// mergeDetectionOpenAPI adds the detection workspace paths to the static
// OpenAPI document. Keeping this in a separate file avoids growing openapi.go
// past the project's file-size ceiling.
func mergeDetectionOpenAPI(spec map[string]any) map[string]any {
	paths, ok := spec["paths"].(map[string]any)
	if !ok {
		paths = make(map[string]any)
		spec["paths"] = paths
	}
	for path, item := range detectionOpenAPIPaths() {
		paths[path] = item
	}
	return spec
}

func detectionOpenAPIPaths() map[string]any {
	okResponse := map[string]any{"description": "Success"}
	badRequest := map[string]any{"description": "Invalid detection configuration"}
	unauthorized := map[string]any{"description": "Missing or invalid credentials"}
	forbidden := map[string]any{"description": "Admin role required"}
	return map[string]any{
		"/detection/status": map[string]any{
			"get": map[string]any{
				"summary":     "Get the active detection posture and rule counts",
				"description": "Reports the active snapshot version, detection mode, sensitivity, CRS state, and catalog counts.",
				"responses":   map[string]any{"200": okResponse, "401": unauthorized},
			},
		},
		"/detection/presets": map[string]any{
			"get": map[string]any{
				"summary":     "List sensitivity preset expansions",
				"description": "Returns the module matrix expansion for low, medium, and high sensitivity.",
				"responses":   map[string]any{"200": okResponse, "401": unauthorized},
			},
		},
		"/detection/policy": map[string]any{
			"get": map[string]any{
				"summary":   "Get the global detection policy",
				"responses": map[string]any{"200": okResponse, "401": unauthorized},
			},
			"put": map[string]any{
				"summary":     "Update the global detection policy",
				"description": "Validates mode, sensitivity, module overrides, CRS tuning, and disabled packs. Applies atomically when auto-apply is enabled.",
				"responses": map[string]any{
					"200": okResponse, "400": badRequest, "401": unauthorized, "403": forbidden,
				},
			},
		},
		"/detection/policies/apps": map[string]any{
			"get": map[string]any{
				"summary":   "List effective per-site detection policies",
				"responses": map[string]any{"200": okResponse, "401": unauthorized},
			},
		},
		"/detection/rules": map[string]any{
			"get": map[string]any{
				"summary":     "List the unified detection rule catalog",
				"description": "Merges semantic modules, bundled CVE virtual patches, embedded CRS rules, and imported packs. Supports q, source, pack, category, severity, enabled, offset, and limit.",
				"responses":   map[string]any{"200": okResponse, "401": unauthorized},
			},
		},
		"/detection/rules/{id}": map[string]any{
			"get": map[string]any{
				"summary":   "Get one catalog rule by canonical ID (source:id)",
				"responses": map[string]any{"200": okResponse, "401": unauthorized, "404": map[string]any{"description": "Unknown rule"}},
			},
			"patch": map[string]any{
				"summary":     "Override a rule's enabled state, action, or severity",
				"description": "Semantic modules map action changes onto the detector matrix; native, CVE, CRS, and ModSecurity rules persist a catalog override.",
				"responses": map[string]any{
					"200": okResponse, "400": badRequest, "401": unauthorized, "403": forbidden,
					"404": map[string]any{"description": "Unknown rule"},
				},
			},
		},
		"/detection/rules/{id}/override": map[string]any{
			"delete": map[string]any{
				"summary":   "Reset a rule to its source default",
				"responses": map[string]any{"200": okResponse, "401": unauthorized, "403": forbidden},
			},
		},
		"/detection/rules/bulk": map[string]any{
			"post": map[string]any{
				"summary":   "Apply an override to multiple rules",
				"responses": map[string]any{"200": okResponse, "400": badRequest, "401": unauthorized, "403": forbidden},
			},
		},
		"/detection/packs": map[string]any{
			"get": map[string]any{
				"summary":   "List installed rule packs",
				"responses": map[string]any{"200": okResponse, "401": unauthorized},
			},
			"post": map[string]any{
				"summary":     "Install and compile a rule pack",
				"description": "Accepts native JSON signatures, ModSecurity directive text, and multi-file CRS bundles. Returns 422 when compilation fails.",
				"responses": map[string]any{
					"201": okResponse, "400": badRequest, "401": unauthorized, "403": forbidden,
					"409": map[string]any{"description": "Pack name/version already exists"},
					"422": map[string]any{"description": "Pack failed validation"},
				},
			},
		},
		"/detection/packs/validate": map[string]any{
			"post": map[string]any{
				"summary":     "Validate and compile a rule pack without installing it",
				"description": "Returns 200 with valid=false and per-directive diagnostics when the pack cannot compile.",
				"responses":   map[string]any{"200": okResponse, "400": badRequest, "401": unauthorized},
			},
		},
		"/detection/packs/{id}": map[string]any{
			"put": map[string]any{
				"summary":   "Enable, disable, or reprioritize a rule pack",
				"responses": map[string]any{"200": okResponse, "400": badRequest, "401": unauthorized, "403": forbidden, "404": map[string]any{"description": "Unknown pack"}},
			},
			"delete": map[string]any{
				"summary":   "Remove a rule pack and its overrides",
				"responses": map[string]any{"200": okResponse, "401": unauthorized, "403": forbidden, "404": map[string]any{"description": "Unknown pack"}},
			},
		},
		"/detection/policies/apps/{id}": map[string]any{
			"get": map[string]any{
				"summary":   "Get the effective detection policy for a site",
				"responses": map[string]any{"200": okResponse, "401": unauthorized, "404": map[string]any{"description": "Unknown application"}},
			},
			"put": map[string]any{
				"summary":   "Update the detection policy for a site",
				"responses": map[string]any{"200": okResponse, "400": badRequest, "401": unauthorized, "403": forbidden, "404": map[string]any{"description": "Unknown application"}},
			},
			"delete": map[string]any{
				"summary":   "Reset a site's detection policy to inherit the global policy",
				"responses": map[string]any{"200": okResponse, "401": unauthorized, "403": forbidden},
			},
		},
	}
}
