package rate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRenderWaitingRoomPage(t *testing.T) {
	rec := httptest.NewRecorder()
	err := RenderWaitingRoomPage(rec, "queue-xyz-123", 42, 15, "/dashboard")
	if err != nil {
		t.Fatalf("RenderWaitingRoomPage failed: %v", err)
	}

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", rec.Code)
	}
	if rec.Header().Get("Cache-Control") != "no-store, no-cache, must-revalidate" {
		t.Errorf("expected no-store Cache-Control, got: %s", rec.Header().Get("Cache-Control"))
	}

	body := rec.Body.String()
	if !strings.Contains(body, "queue-xyz-123") {
		t.Errorf("body missing queue ID")
	}
	if !strings.Contains(body, "42") {
		t.Errorf("body missing initial position 42")
	}
	if !strings.Contains(body, "/dashboard") {
		t.Errorf("body missing redirect URL /dashboard")
	}
	if !strings.Contains(body, "rw_waiting_room_clearance") {
		t.Errorf("body missing clearance cookie name")
	}
}

func TestWriteWaitingRoomOverloadedJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteWaitingRoomOverloadedJSON(rec, 45)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "45" {
		t.Errorf("expected Retry-After 45, got %s", rec.Header().Get("Retry-After"))
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected application/json, got %s", rec.Header().Get("Content-Type"))
	}

	var resp WaitingRoomAPIOverloadedResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}
	if resp.Error != "server_overloaded" {
		t.Errorf("expected server_overloaded error, got: %s", resp.Error)
	}
	if resp.RetryAfter != 45 {
		t.Errorf("expected retry_after 45, got: %d", resp.RetryAfter)
	}
}

func TestRenderWaitingRoomPage_XSSSanitization(t *testing.T) {
	rec := httptest.NewRecorder()
	xssPayload := `/?q="></script><script>alert('xss')</script>`
	err := RenderWaitingRoomPage(rec, "q-xss", 5, 2, xssPayload)
	if err != nil {
		t.Fatalf("RenderWaitingRoomPage failed: %v", err)
	}

	body := rec.Body.String()
	// Verifies that unescaped </script> tag breakout is NOT present
	if strings.Contains(body, `</script><script>alert('xss')</script>`) {
		t.Errorf("Reflected XSS vulnerability detected: unescaped </script> found in output")
	}
	// Verifies that JSON-escaped HTML characters were used (\u003c/script\u003e)
	if !strings.Contains(body, `\u003c/script\u003e`) {
		t.Errorf("Expected JSON-escaped \\u003c/script\\u003e in template body")
	}
}

func TestRenderWaitingRoomPage_QueueCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	err := RenderWaitingRoomPage(rec, "cookie-test-id", 3, 1, "/checkout")
	if err != nil {
		t.Fatalf("RenderWaitingRoomPage failed: %v", err)
	}

	cookieHeader := rec.Header().Get("Set-Cookie")
	if !strings.Contains(cookieHeader, WaitingRoomQueueCookie+"=cookie-test-id") {
		t.Errorf("missing %s cookie in Set-Cookie header: %s", WaitingRoomQueueCookie, cookieHeader)
	}
}
