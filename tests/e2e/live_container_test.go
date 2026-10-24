//go:build integration

package e2e

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLiveContainer_EndToEndVerification(t *testing.T) {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	baseURL := "http://127.0.0.1:8080"

	// 1. Check container readiness
	resp, err := client.Get(baseURL + "/.raiwall/api/openapi.json")
	if err != nil {
		t.Skipf("Docker container is not reachable on %s: %v (skipping live container test)", baseURL, err)
		return
	}
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "OpenAPI spec should be reachable")
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "openapi", "Should return valid OpenAPI JSON")

	// 2. Embedded Vue 3 SPA Admin UI
	uiResp, err := client.Get(baseURL + "/.raiwall/")
	require.NoError(t, err)
	defer uiResp.Body.Close()
	assert.Equal(t, http.StatusOK, uiResp.StatusCode, "Embedded UI should load with 200")
	uiBody, _ := io.ReadAll(uiResp.Body)
	assert.Contains(t, strings.ToLower(string(uiBody)), "<!doctype html>", "Should serve HTML document")

	// 3. Basic Auth verification on Control Plane API
	basicAuthHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:admin"))

	// 3a. Unauthorized without credentials
	unauthReq, _ := http.NewRequest(http.MethodGet, baseURL+"/.raiwall/api/v1/sites", nil)
	unauthResp, err := client.Do(unauthReq)
	require.NoError(t, err)
	defer unauthResp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, unauthResp.StatusCode, "Unauthenticated request should return 401")

	// 3b. Unauthorized with bad credentials
	badAuthReq, _ := http.NewRequest(http.MethodGet, baseURL+"/.raiwall/api/v1/sites", nil)
	badAuthReq.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:wrongpass")))
	badAuthResp, err := client.Do(badAuthReq)
	require.NoError(t, err)
	defer badAuthResp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, badAuthResp.StatusCode, "Bad credentials should return 401")

	// 3c. Authorized with admin:admin
	authReq, _ := http.NewRequest(http.MethodGet, baseURL+"/.raiwall/api/v1/sites", nil)
	authReq.Header.Set("Authorization", basicAuthHeader)
	authResp, err := client.Do(authReq)
	require.NoError(t, err)
	defer authResp.Body.Close()
	assert.Equal(t, http.StatusOK, authResp.StatusCode, "Basic auth admin:admin should return 200")

	// 4. IP Groups API Endpoint (Task 94)
	ipgReq, _ := http.NewRequest(http.MethodGet, baseURL+"/.raiwall/api/v1/ip-groups", nil)
	ipgReq.Header.Set("Authorization", basicAuthHeader)
	ipgResp, err := client.Do(ipgReq)
	require.NoError(t, err)
	defer ipgResp.Body.Close()
	assert.Equal(t, http.StatusOK, ipgResp.StatusCode, "IP groups endpoint should return 200")

	// 5. Response Templates API Endpoint (Task 95)
	tmplReq, _ := http.NewRequest(http.MethodGet, baseURL+"/.raiwall/api/v1/templates", nil)
	tmplReq.Header.Set("Authorization", basicAuthHeader)
	tmplResp, err := client.Do(tmplReq)
	require.NoError(t, err)
	defer tmplResp.Body.Close()
	assert.Equal(t, http.StatusOK, tmplResp.StatusCode, "Templates endpoint should return 200")

	// 6. Live WAF Threat Detection (SQLi -> 403 Forbidden)
	sqliReq, _ := http.NewRequest(http.MethodGet, baseURL+"/public/items?id=1%27%20OR%201=1--", nil)
	sqliReq.Header.Set("Accept", "application/json")
	sqliResp, err := client.Do(sqliReq)
	require.NoError(t, err)
	defer sqliResp.Body.Close()
	assert.Equal(t, http.StatusForbidden, sqliResp.StatusCode, "SQL injection must return 403 Forbidden")
	sqliBody, _ := io.ReadAll(sqliResp.Body)
	assert.NotEmpty(t, sqliBody, "Response should contain block template")

	// 7. Live WAF Threat Detection (XSS -> 403 Forbidden)
	xssReq, _ := http.NewRequest(http.MethodGet, baseURL+"/public/search?q=%3Cscript%3Ealert(1)%3C/script%3E", nil)
	xssReq.Header.Set("Accept", "application/json")
	xssResp, err := client.Do(xssReq)
	require.NoError(t, err)
	defer xssResp.Body.Close()
	assert.Equal(t, http.StatusForbidden, xssResp.StatusCode, "XSS injection must return 403 Forbidden")

	// 8. Live WAF Threat Detection (CmdI -> 403 Forbidden)
	cmdiReq, _ := http.NewRequest(http.MethodGet, baseURL+"/public/ping?host=127.0.0.1;cat%20/etc/passwd", nil)
	cmdiReq.Header.Set("Accept", "application/json")
	cmdiResp, err := client.Do(cmdiReq)
	require.NoError(t, err)
	defer cmdiResp.Body.Close()
	assert.Equal(t, http.StatusForbidden, cmdiResp.StatusCode, "Command injection must return 403 Forbidden")

	// 9. Benign traffic passes through
	benignReq, _ := http.NewRequest(http.MethodGet, baseURL+"/healthz", nil)
	benignResp, err := client.Do(benignReq)
	require.NoError(t, err)
	defer benignResp.Body.Close()
	assert.True(t, benignResp.StatusCode != http.StatusForbidden, "Benign request should not be blocked")

	// 10. Query Telemetry Events
	time.Sleep(600 * time.Millisecond) // Wait for buffer flush
	telemReq, _ := http.NewRequest(http.MethodGet, baseURL+"/.raiwall/api/v1/telemetry/events?limit=5", nil)
	telemReq.Header.Set("Authorization", basicAuthHeader)
	telemResp, err := client.Do(telemReq)
	require.NoError(t, err)
	defer telemResp.Body.Close()
	assert.Equal(t, http.StatusOK, telemResp.StatusCode, "Telemetry events query should return 200")
}

func TestEnterpriseEndToEnd_AllEndpointsAndThreats(t *testing.T) {
	f := setupEnterpriseFixture(t)

	// Helper for executing requests through the full Caddy middleware pipeline
	execRequest := func(method, path string, body string, headers map[string]string) *httptest.ResponseRecorder {
		var bodyReader io.Reader
		if body != "" {
			bodyReader = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, path, bodyReader)
		req.RemoteAddr = "192.0.2.100:54321"
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		err := f.mw.ServeHTTP(rec, req, f.defaultNext)
		require.NoError(t, err)
		return rec
	}

	basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:admin"))
	authHeaders := map[string]string{
		"Authorization": basicAuth,
		"Content-Type":  "application/json",
	}

	// 1. OpenAPI 3.1 Schema Spec
	recOpenAPI := execRequest(http.MethodGet, "/.raiwall/api/openapi.json", "", nil)
	assert.Equal(t, http.StatusOK, recOpenAPI.Code)
	assert.Contains(t, recOpenAPI.Body.String(), "openapi")

	// 2. Embedded Admin UI Root
	recUI := execRequest(http.MethodGet, "/.raiwall/", "", nil)
	assert.Equal(t, http.StatusOK, recUI.Code)
	assert.Contains(t, strings.ToLower(recUI.Body.String()), "<!doctype html>")

	// 3. HTTP Basic Auth
	recUnauth := execRequest(http.MethodGet, "/.raiwall/api/v1/sites", "", nil)
	assert.Equal(t, http.StatusUnauthorized, recUnauth.Code)

	recBadAuth := execRequest(http.MethodGet, "/.raiwall/api/v1/sites", "", map[string]string{
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:wrongpass")),
	})
	assert.Equal(t, http.StatusUnauthorized, recBadAuth.Code)

	recAuth := execRequest(http.MethodGet, "/.raiwall/api/v1/sites", "", authHeaders)
	assert.Equal(t, http.StatusOK, recAuth.Code)

	// 4. IP Groups REST API (Task 94)
	// 4a. List IP Groups
	recListIPG := execRequest(http.MethodGet, "/.raiwall/api/v1/ip-groups", "", authHeaders)
	assert.Equal(t, http.StatusOK, recListIPG.Code)

	// 4b. Create IP Group
	recCreateIPG := execRequest(http.MethodPost, "/.raiwall/api/v1/ip-groups",
		`{"name":"threat_bypasses","description":"Whitelisted partners","type":"custom"}`, authHeaders)
	assert.Equal(t, http.StatusCreated, recCreateIPG.Code)

	// 4c. Add CIDR entry
	recAddEntry := execRequest(http.MethodPost, "/.raiwall/api/v1/ip-groups/threat_bypasses/entries",
		`{"cidr":"203.0.113.192/28","comment":"Partner network"}`, authHeaders)
	assert.Equal(t, http.StatusCreated, recAddEntry.Code)

	// 5. Response Templates REST API (Task 95)
	// 5a. List Templates
	recListTmpl := execRequest(http.MethodGet, "/.raiwall/api/v1/templates", "", authHeaders)
	assert.Equal(t, http.StatusOK, recListTmpl.Code)
	assert.Contains(t, recListTmpl.Body.String(), "403")

	// 5b. Get Template
	recGetTmpl := execRequest(http.MethodGet, "/.raiwall/api/v1/templates/403", "", authHeaders)
	assert.Equal(t, http.StatusOK, recGetTmpl.Code)

	// 5c. Update Template
	recUpdateTmpl := execRequest(http.MethodPut, "/.raiwall/api/v1/templates/403",
		`{"title":"Corporate Defense Gate","content_html":"<h1>Request Blocked - Access Denied: {{.BrandName}}</h1><p>ID: {{.EventID}}</p>","custom_css":"h1 { color: #f00; }","brand_name":"Enterprise Guard"}`, authHeaders)
	assert.Equal(t, http.StatusOK, recUpdateTmpl.Code)

	// 5d. Preview Template
	recPreviewTmpl := execRequest(http.MethodPost, "/.raiwall/api/v1/templates/403/preview",
		`{"content_html":"<h1>Custom Preview</h1>","brand_name":"Enterprise Guard"}`, authHeaders)
	assert.Equal(t, http.StatusOK, recPreviewTmpl.Code)
	assert.Contains(t, recPreviewTmpl.Body.String(), "Custom Preview")

	// 6. Live WAF Threat Detection (SQLi, XSS, CmdI, Path Traversal)
	// 6a. SQL Injection (Blocked with customized template)
	recSQLi := execRequest(http.MethodGet, "/search?q=%27%20OR%20%271%27=%271", "", nil)
	assert.Equal(t, http.StatusForbidden, recSQLi.Code)
	assert.Contains(t, recSQLi.Body.String(), "Enterprise Guard")

	// 6b. XSS Injection
	recXSS := execRequest(http.MethodPost, "/submit", "comment=<script>alert('xss')</script>", map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	assert.Equal(t, http.StatusForbidden, recXSS.Code)

	// 6c. Command Injection
	recCmdI := execRequest(http.MethodGet, "/exec?cmd=%3Bcat%20%2Fetc%2Fpasswd", "", nil)
	assert.Equal(t, http.StatusForbidden, recCmdI.Code)

	// 6d. Path Traversal
	recPath := execRequest(http.MethodGet, "/files?path=../../../../etc/passwd", "", nil)
	assert.Equal(t, http.StatusForbidden, recPath.Code)

	// 7. Benign Traffic Passthrough
	recBenign := execRequest(http.MethodGet, "/healthz", "", nil)
	assert.Equal(t, http.StatusOK, recBenign.Code)

	// 8. Telemetry Ingestion Query
	recTelem := execRequest(http.MethodGet, "/.raiwall/api/v1/telemetry/events?limit=10", "", authHeaders)
	assert.Equal(t, http.StatusOK, recTelem.Code)

	// Reset template 403 back to default
	recReset := execRequest(http.MethodPost, "/.raiwall/api/v1/templates/403/reset", "", authHeaders)
	assert.Equal(t, http.StatusOK, recReset.Code)
}
