package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/stretchr/testify/require"
)

const certTestToken = "rw_admin_cert_token"

func certRequest(t *testing.T, server *Server, method, path string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	var body *bytes.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		require.NoError(t, err)
		body = bytes.NewReader(raw)
	} else {
		body = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+certTestToken)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	return rec
}

func TestAPI_CertificateLifecycle(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()
	require.NoError(t, store.CreateAPIKey(t.Context(), dbCreateAdminKey(certTestToken)))

	// Unauthenticated access is rejected.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	// Self-signed creation.
	rec = certRequest(t, server, http.MethodPost, "/api/v1/certificates", map[string]any{
		"name":    "self-signed",
		"domains": []string{"app.example.com"},
		"source":  "self_signed",
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	var created CertificateDTO
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	require.NotEmpty(t, created.ID)
	require.Equal(t, control.CertSourceSelfSigned, created.Source)
	require.NotEmpty(t, created.CertificatePEM)
	require.NotEmpty(t, created.FingerprintSHA256)
	require.NotContains(t, rec.Body.String(), "key_pem")
	require.NotContains(t, rec.Body.String(), "encrypted_key")

	// Listing returns metadata without private material.
	rec = certRequest(t, server, http.MethodGet, "/api/v1/certificates", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotContains(t, rec.Body.String(), "encrypted_key")

	// Download returns PEM bytes.
	rec = certRequest(t, server, http.MethodGet, "/api/v1/certificates/"+created.ID+"/download", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "BEGIN CERTIFICATE")

	// Renew self-signed material.
	rec = certRequest(t, server, http.MethodPost, "/api/v1/certificates/"+created.ID+"/renew", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// Update name and auto-renew flag.
	autoRenew := false
	rec = certRequest(t, server, http.MethodPut, "/api/v1/certificates/"+created.ID, map[string]any{
		"name":       "renamed",
		"auto_renew": autoRenew,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var updated CertificateDTO
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updated))
	require.Equal(t, "renamed", updated.Name)
	require.False(t, updated.AutoRenew)

	// Delete.
	rec = certRequest(t, server, http.MethodDelete, "/api/v1/certificates/"+created.ID, nil)
	require.Equal(t, http.StatusOK, rec.Code)

	// Missing certificate.
	rec = certRequest(t, server, http.MethodGet, "/api/v1/certificates/"+created.ID, nil)
	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestAPI_CertificateValidation(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()
	require.NoError(t, store.CreateAPIKey(t.Context(), dbCreateAdminKey(certTestToken)))

	certPEM, keyPEM, _, err := control.GenerateSelfSigned([]string{"upload.example.com"}, time.Now().UTC())
	require.NoError(t, err)

	cases := []struct {
		name    string
		payload map[string]any
	}{
		{"missing domains", map[string]any{"name": "x", "source": "self_signed"}},
		{"unknown source", map[string]any{"name": "x", "domains": []string{"x.example.com"}, "source": "magic"}},
		{"upload without key", map[string]any{"name": "x", "domains": []string{"x.example.com"}, "source": "upload", "cert_pem": certPEM}},
		{"invalid domain", map[string]any{"name": "x", "domains": []string{"bad domain"}, "source": "self_signed"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := certRequest(t, server, http.MethodPost, "/api/v1/certificates", tc.payload)
			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		})
	}

	// Mismatched key pair is rejected.
	_, otherKey, _, err := control.GenerateSelfSigned([]string{"other.example.com"}, time.Now().UTC())
	require.NoError(t, err)
	rec := certRequest(t, server, http.MethodPost, "/api/v1/certificates", map[string]any{
		"name": "mismatch", "domains": []string{"upload.example.com"}, "source": "upload",
		"cert_pem": certPEM, "key_pem": otherKey,
	})
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "do not match")

	// Valid upload is accepted and never echoes the private key.
	rec = certRequest(t, server, http.MethodPost, "/api/v1/certificates", map[string]any{
		"name": "upload", "domains": []string{"upload.example.com"}, "source": "upload",
		"cert_pem": certPEM, "key_pem": keyPEM,
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	require.NotContains(t, rec.Body.String(), "PRIVATE KEY")
}

func TestAPI_CertificateCannotBeDeletedWhileInUse(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()
	require.NoError(t, store.CreateAPIKey(t.Context(), dbCreateAdminKey(certTestToken)))

	rec := certRequest(t, server, http.MethodPost, "/api/v1/certificates", map[string]any{
		"name": "site-cert", "domains": []string{"secure.example.com"}, "source": "self_signed",
	})
	require.Equal(t, http.StatusCreated, rec.Code)
	var cert CertificateDTO
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &cert))

	rec = certRequest(t, server, http.MethodPost, "/api/v1/sites", map[string]any{
		"name": "secure", "hostnames": []string{"secure.example.com"},
		"ports":          []map[string]any{{"port": 443, "scheme": "https"}},
		"ssl_mode":       "manual",
		"certificate_id": cert.ID,
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	rec = certRequest(t, server, http.MethodDelete, "/api/v1/certificates/"+cert.ID, nil)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "secure")
}

func TestAPI_SiteRoutingPayloadRoundTrip(t *testing.T) {
	server, store := setupTestServer(t)
	defer store.Close()
	require.NoError(t, store.CreateAPIKey(t.Context(), dbCreateAdminKey(certTestToken)))

	rec := certRequest(t, server, http.MethodPost, "/api/v1/sites", map[string]any{
		"name":            "Landing",
		"description":     "marketing redirect",
		"hostnames":       []string{"landing.example.com"},
		"ports":           []map[string]any{{"port": 80, "scheme": "http"}, {"port": 443, "scheme": "https"}},
		"ssl_mode":        "auto",
		"routing_type":    "redirect",
		"redirect_url":    "https://example.com/new",
		"redirect_status": 308,
		"load_balancing":  "least_conn",
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	var created SiteDTO
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	require.Equal(t, "redirect", created.RoutingType)
	require.Equal(t, "https://example.com/new", created.RedirectURL)
	require.Equal(t, 308, created.RedirectStatus)
	require.Equal(t, "auto", created.SSLMode)
	require.Equal(t, "least_conn", created.LoadBalancing)
	require.Len(t, created.Ports, 2)

	// A partial update keeps routing and TLS metadata intact.
	rec = certRequest(t, server, http.MethodPut, "/api/v1/sites/"+created.ID, map[string]any{
		"description": "updated note",
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var updated SiteDTO
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updated))
	require.Equal(t, "updated note", updated.Description)
	require.Equal(t, "redirect", updated.RoutingType)
	require.Equal(t, "https://example.com/new", updated.RedirectURL)
	require.Equal(t, []string{"landing.example.com"}, updated.Hostnames)
	require.Len(t, updated.Ports, 2)

	// Invalid routing combinations are rejected.
	badPayloads := []map[string]any{
		{
			"name": "bad-static", "hostnames": []string{"static.example.com"},
			"routing_type": "static",
		},
		{
			"name": "bad-redirect", "hostnames": []string{"redirect.example.com"},
			"routing_type": "redirect", "redirect_url": "example.com/no-scheme", "redirect_status": 302,
		},
		{
			"name": "bad-https", "hostnames": []string{"plain.example.com"},
			"ports": []map[string]any{{"port": 443, "scheme": "https"}}, "ssl_mode": "none",
		},
		{
			"name": "bad-upstream", "hostnames": []string{"proxy.example.com"},
			"routing_type": "proxy", "upstreams": []map[string]any{{"dial": ""}},
		},
		{
			"name": "manual-no-cert", "hostnames": []string{"manual.example.com"},
			"ssl_mode": "manual",
		},
	}
	for i, payload := range badPayloads {
		rec := certRequest(t, server, http.MethodPost, "/api/v1/sites", payload)
		require.Equal(t, http.StatusBadRequest, rec.Code, fmt.Sprintf("case %d: %s", i, rec.Body.String()))
	}
}
