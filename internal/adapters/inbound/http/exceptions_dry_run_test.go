package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func postExceptionDryRun(t *testing.T, server *Server, cookie *http.Cookie, payload map[string]any) ExceptionTestResponse {
	t.Helper()
	body, err := json.Marshal(payload)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/exceptions/dry-run", bytes.NewReader(body))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp ExceptionTestResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp
}

func TestExceptionDryRunReportsCRSTargetEffect(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()
	cookie := loginTestAdmin(t, server, store)

	resp := postExceptionDryRun(t, server, cookie, map[string]any{
		"rule": map[string]any{
			"host":        "example.com",
			"path_prefix": "/search",
			"location":    "query",
			"param_name":  "q",
			"rule_id":     "942100",
		},
		"sample_request": map[string]any{
			"host":       "example.com",
			"path":       "/search/results",
			"method":     "GET",
			"location":   "query",
			"param_name": "q",
			"rule_id":    "942100",
		},
	})

	require.True(t, resp.Matched)
	require.Len(t, resp.Effects, 2)
	require.Equal(t, "semantic", resp.Effects[0].Engine)
	require.Equal(t, "crs", resp.Effects[1].Engine)
	require.Equal(t, "ctl:ruleRemoveTargetById=942100;ARGS:q", resp.Effects[1].Directive)
}

func TestExceptionDryRunReportsWholeRuleCRSEffect(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()
	cookie := loginTestAdmin(t, server, store)

	resp := postExceptionDryRun(t, server, cookie, map[string]any{
		"rule": map[string]any{
			"host":    "example.com",
			"rule_id": "949110",
		},
		"sample_request": map[string]any{
			"host":    "example.com",
			"path":    "/anything",
			"method":  "GET",
			"rule_id": "949110",
		},
	})

	require.True(t, resp.Matched)
	require.Len(t, resp.Effects, 2)
	require.Equal(t, "ctl:ruleRemoveById=949110", resp.Effects[1].Directive)
}

func TestExceptionDryRunExplainsSemanticOnlyRules(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()
	cookie := loginTestAdmin(t, server, store)

	resp := postExceptionDryRun(t, server, cookie, map[string]any{
		"rule": map[string]any{
			"host":       "example.com",
			"location":   "query",
			"param_name": "q",
			"rule_id":    "SEMANTIC_SQLI",
		},
		"sample_request": map[string]any{
			"host":       "example.com",
			"path":       "/search",
			"method":     "GET",
			"location":   "query",
			"param_name": "q",
			"rule_id":    "SEMANTIC_SQLI",
		},
	})

	require.True(t, resp.Matched)
	require.Len(t, resp.Effects, 2)
	require.Equal(t, "crs", resp.Effects[1].Engine)
	require.Empty(t, resp.Effects[1].Directive)
	require.Contains(t, resp.Effects[1].Detail, "semantic-only")
}

func TestExceptionDryRunReportsNoEffectsWhenUnmatched(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()
	cookie := loginTestAdmin(t, server, store)

	resp := postExceptionDryRun(t, server, cookie, map[string]any{
		"rule": map[string]any{
			"host":    "example.com",
			"rule_id": "942100",
		},
		"sample_request": map[string]any{
			"host":    "other.example.com",
			"path":    "/search",
			"method":  "GET",
			"rule_id": "942100",
		},
	})

	require.False(t, resp.Matched)
	require.Empty(t, resp.Effects)
}
