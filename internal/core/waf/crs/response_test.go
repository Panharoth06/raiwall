package crs_test

import (
	"net/http"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/Panharoth06/raiwall/internal/core/waf/crs"
	"github.com/stretchr/testify/require"
)

func TestEngine_PairedResponseInspection(t *testing.T) {
	conf := crs.Config{
		Mode:              crs.ModeBlock,
		ParanoiaLevel:     1,
		InboundThreshold:  5,
		OutboundThreshold: 4,
		InspectResponse:   true,
		ResponseBodyLimit: 1024 * 1024,
		ResponseMimeTypes: []string{"text/html", "text/plain"},
	}
	engine, err := crs.New(conf)
	require.NoError(t, err)

	t.Run("benign request and response allow", func(t *testing.T) {
		reqCtx := &waf.RequestContext{
			Method:          "GET",
			Host:            "example.com",
			Path:            "/index.html",
			Headers:         http.Header{"Accept": {"text/html"}},
			InspectResponse: true,
		}
		reqVerdict, err := engine.InspectRequest(reqCtx)
		require.NoError(t, err)
		require.Equal(t, waf.ActionAllow, reqVerdict.Action)
		require.NotNil(t, reqCtx.Session)

		respCtx := &waf.ResponseContext{
			StatusCode: 200,
			Headers:    http.Header{"Content-Type": {"text/html"}},
			Body:       []byte("<html><body>Hello World</body></html>"),
			Session:    reqCtx.Session,
		}
		respVerdict, err := engine.InspectResponse(respCtx)
		require.NoError(t, err)
		require.Equal(t, waf.ActionAllow, respVerdict.Action)
	})

	t.Run("outbound sql leakage triggers block", func(t *testing.T) {
		reqCtx := &waf.RequestContext{
			Method:          "GET",
			Host:            "example.com",
			Path:            "/users",
			Headers:         http.Header{"Accept": {"text/html"}},
			InspectResponse: true,
		}
		reqVerdict, err := engine.InspectRequest(reqCtx)
		require.NoError(t, err)
		require.Equal(t, waf.ActionAllow, reqVerdict.Action)
		require.NotNil(t, reqCtx.Session)

		// Leakage matching CRS rule 951...
		respCtx := &waf.ResponseContext{
			StatusCode: 500,
			Headers:    http.Header{"Content-Type": {"text/html"}},
			Body:       []byte("Database error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'SELECT' at line 1"),
			Session:    reqCtx.Session,
		}
		respVerdict, err := engine.InspectResponse(respCtx)
		require.NoError(t, err)
		require.NotNil(t, respVerdict)
		require.Equal(t, waf.ActionBlock, respVerdict.Action)
		require.NotEmpty(t, respVerdict.MatchedRules)
	})

	t.Run("outbound leakage in audit mode does not block", func(t *testing.T) {
		auditConf := conf
		auditConf.Mode = crs.ModeAudit
		auditEngine, err := crs.New(auditConf)
		require.NoError(t, err)

		reqCtx := &waf.RequestContext{
			Method:          "GET",
			Host:            "example.com",
			Path:            "/users",
			Headers:         http.Header{"Accept": {"text/html"}},
			InspectResponse: true,
		}
		reqVerdict, err := auditEngine.InspectRequest(reqCtx)
		require.NoError(t, err)
		require.Equal(t, waf.ActionAllow, reqVerdict.Action)
		require.NotNil(t, reqCtx.Session)

		respCtx := &waf.ResponseContext{
			StatusCode: 500,
			Headers:    http.Header{"Content-Type": {"text/html"}},
			Body:       []byte("Database error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'SELECT' at line 1"),
			Session:    reqCtx.Session,
		}
		respVerdict, err := auditEngine.InspectResponse(respCtx)
		require.NoError(t, err)
		require.NotNil(t, respVerdict)
		require.Equal(t, waf.ActionAudit, respVerdict.Action)
	})
}
