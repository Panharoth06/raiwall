package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/stretchr/testify/require"
)

func TestAPI_RuleTestPlayground(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()

	token := "rw_admin_rule_test"
	require.NoError(t, store.CreateAPIKey(t.Context(), dbCreateAdminKey(token)))

	server.SetRuleTester(func(ctx *waf.RequestContext) (*waf.Verdict, error) {
		if ctx.Query == "q=attack" {
			return &waf.Verdict{
				Action:        waf.ActionBlock,
				RuleID:        "CRS_949110",
				Engine:        "crs",
				AnomalyScore:  5,
				ParanoiaLevel: 1,
				MatchedRules: []waf.RuleMatch{
					{RuleID: "942100", Message: "SQL Injection Attack Detected via libinjection", Severity: "critical", Engine: "crs"},
				},
			}, nil
		}
		return waf.VerdictAllow, nil
	})

	post := func(body string, authenticated bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rules/test", bytes.NewReader([]byte(body)))
		if authenticated {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)
		return w
	}

	t.Run("requires authentication", func(t *testing.T) {
		require.Equal(t, http.StatusUnauthorized, post(`{"method":"GET"}`, false).Code)
	})

	t.Run("returns CRS verdict", func(t *testing.T) {
		rec := post(`{"method":"GET","path":"/search","query":"q=attack","headers":{"Accept":"application/json"}}`, true)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		var result RuleTestResult
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
		require.Equal(t, waf.ActionBlock, result.Verdict.Action)
		require.Equal(t, "crs", result.Verdict.Engine)
		require.Equal(t, 5.0, result.Verdict.AnomalyScore)
		require.Len(t, result.Verdict.MatchedRules, 1)
	})

	t.Run("allows benign probe", func(t *testing.T) {
		rec := post(`{"method":"GET","path":"/search","query":"q=shoes"}`, true)
		require.Equal(t, http.StatusOK, rec.Code)
		var result RuleTestResult
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
		require.Equal(t, waf.ActionAllow, result.Verdict.Action)
	})

	t.Run("rejects malformed JSON", func(t *testing.T) {
		require.Equal(t, http.StatusBadRequest, post(`{`, true).Code)
	})
}
