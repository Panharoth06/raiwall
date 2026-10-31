package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/stretchr/testify/require"
)

func auditEvents(t *testing.T, store control.ControlStore, filter control.AuditFilter) []control.AuditEvent {
	t.Helper()
	events, err := store.ListAuditEvents(context.Background(), filter)
	require.NoError(t, err)
	return events
}

func TestAuditRecordsLoginSuccessAndFailure(t *testing.T) {
	server, store, _ := operatorTestServer(t)
	defer store.Close()

	bad, _ := json.Marshal(map[string]string{"username": "root", "password": "wrong"})
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(bad)))
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	failures := auditEvents(t, store, control.AuditFilter{Action: "login_failure"})
	require.Len(t, failures, 1)
	require.Equal(t, "root", failures[0].ActorName)
	require.Equal(t, 401, failures[0].StatusCode)
	require.NotEmpty(t, failures[0].ClientIP)
	require.Empty(t, failures[0].Detail, "audit rows must not contain credentials")

	login(t, server, "root", "correct-horse-battery")
	successes := auditEvents(t, store, control.AuditFilter{Action: "login_success"})
	require.Len(t, successes, 2, "one row per login; the helper logs in once before this test")
	require.Equal(t, "root", successes[0].ActorName)
	require.Equal(t, RoleAdmin, successes[0].Role)
}

func TestAuditRecordsMutationsAndOperatorChanges(t *testing.T) {
	server, store, cookie := operatorTestServer(t)
	defer store.Close()

	body := bytes.NewReader([]byte(`{"auto_apply":true}`))
	req := httptest.NewRequest(http.MethodPut, "/api/v1/system/auto-apply", body)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	updates := auditEvents(t, store, control.AuditFilter{Action: "update"})
	require.NotEmpty(t, updates)
	require.Equal(t, "root", updates[0].ActorName)
	require.Equal(t, http.MethodPut, updates[0].Method)
	require.Equal(t, "/api/v1/system/auto-apply", updates[0].Path)
	require.NotEmpty(t, updates[0].RequestID)

	// Credential-shaped requests must never be logged more than as metadata.
	bad, _ := json.Marshal(map[string]string{"username": "root", "password": "another-wrong-password"})
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(bad)))
	for _, event := range auditEvents(t, store, control.AuditFilter{}) {
		require.NotContains(t, event.Detail, "another-wrong-password")
		require.NotContains(t, event.Detail, "correct-horse-battery")
	}

	created := decodeAdminUser(t, operatorRequest(server, http.MethodPost, "/api/v1/users", cookie, "", map[string]any{
		"username": "audited", "password": "audited-strong-password", "role": RoleViewer,
	}))
	reset := operatorRequest(server, http.MethodPost, "/api/v1/users/"+created.User.ID+"/password", cookie, "", map[string]any{})
	require.Equal(t, http.StatusOK, reset.Code)

	resets := auditEvents(t, store, control.AuditFilter{Action: "password_reset"})
	require.Len(t, resets, 1)
	require.Equal(t, created.User.ID, resets[0].TargetID)
	require.Equal(t, "operator", resets[0].TargetType)
}

func TestAuditReadAPIRequiresAdminAndFilters(t *testing.T) {
	server, store, adminCookie := operatorTestServer(t)
	defer store.Close()
	createOperator(t, store, "auditviewer", "correct-horse-battery", RoleViewer)
	viewerCookie := login(t, server, "auditviewer", "correct-horse-battery")

	denied := operatorRequest(server, http.MethodGet, "/api/v1/audit", viewerCookie, "", nil)
	require.Equal(t, http.StatusForbidden, denied.Code)

	login(t, server, "root", "correct-horse-battery")
	ok := operatorRequest(server, http.MethodGet, "/api/v1/audit?action=login_success&limit=10", adminCookie, "", nil)
	require.Equal(t, http.StatusOK, ok.Code)
	var body struct {
		Events []control.AuditEvent `json:"events"`
		Limit  int                  `json:"limit"`
		Offset int                  `json:"offset"`
	}
	require.NoError(t, json.Unmarshal(ok.Body.Bytes(), &body))
	require.NotEmpty(t, body.Events)
	require.Equal(t, 10, body.Limit)
	for _, event := range body.Events {
		require.Equal(t, "login_success", event.Action)
	}

	bad := operatorRequest(server, http.MethodGet, "/api/v1/audit?from=not-a-time", adminCookie, "", nil)
	require.Equal(t, http.StatusBadRequest, bad.Code)
}
