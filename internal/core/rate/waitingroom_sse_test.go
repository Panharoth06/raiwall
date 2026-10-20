package rate

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWaitingRoomManager_SSEStreaming(t *testing.T) {
	wm := NewWaitingRoomManager(WaitingRoomConfig{
		MaxConcurrentInFlight: 1,
		MaxQueueDepth:         10,
		AdmissionRate:         5,
		Secret:                "sse-test-secret-32-bytes-waiting",
	})
	defer wm.Close()

	// Fill in-flight capacity
	rel := wm.AcquireLease()
	defer rel()

	ip := net.ParseIP("198.51.100.2")
	ja4 := "t13d1516h2_ja4"

	entry, pos, wait, err := wm.Enqueue(ip, ja4)
	if err != nil {
		t.Fatalf("enqueue failed: %v", err)
	}

	// Test SSE Stream
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := httptest.NewRequest(http.MethodGet, "/.raiwall/waiting-room/events?id="+entry.ID, nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		wm.HandleSSE(rec, req, ip, ja4)
	}()

	// Wait for initial event
	time.Sleep(100 * time.Millisecond)

	// Admit the entry cleanly
	wm.AdmitEntry(entry.ID)

	// Wait for HandleSSE to complete
	wg.Wait()

	body := rec.Body.String()
	if !strings.Contains(body, "event: update") && !strings.Contains(body, "event: admitted") {
		t.Errorf("expected SSE event update or admitted in body: %s", body)
	}
	if !strings.Contains(body, "admitted") {
		t.Errorf("expected admission in SSE stream: %s", body)
	}
	_ = pos
	_ = wait
}

func TestWaitingRoomManager_SSE_NotFoundStatus(t *testing.T) {
	wm := NewWaitingRoomManager(WaitingRoomConfig{
		MaxConcurrentInFlight: 5,
		MaxQueueDepth:         10,
	})
	defer wm.Close()

	req := httptest.NewRequest(http.MethodGet, "/.raiwall/waiting-room/events?id=non-existent-id", nil)
	rec := httptest.NewRecorder()

	wm.HandleSSE(rec, req, net.ParseIP("192.0.2.1"), "ja4")
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected HTTP 404 for non-existent queue ID, got status %d", rec.Code)
	}
	if rec.Header().Get("Content-Type") == "text/event-stream" {
		t.Errorf("404 response must not be committed with text/event-stream headers")
	}
}

func TestWaitingRoomManager_TargetPaths(t *testing.T) {
	wm := NewWaitingRoomManager(WaitingRoomConfig{
		TargetPaths: []string{"/checkout", "/api/v1/tickets/*"},
	})
	defer wm.Close()

	if !wm.MatchesPath("/checkout") {
		t.Errorf("expected /checkout to match")
	}
	if !wm.MatchesPath("/checkout/step2") {
		t.Errorf("expected /checkout/step2 to match")
	}
	if !wm.MatchesPath("/api/v1/tickets/123") {
		t.Errorf("expected /api/v1/tickets/123 to match")
	}
	if wm.MatchesPath("/static/style.css") {
		t.Errorf("expected /static/style.css NOT to match")
	}
	if wm.MatchesPath("/home") {
		t.Errorf("expected /home NOT to match")
	}

	// Update paths
	wm.SetTargetPaths([]string{"/*"})
	if !wm.MatchesPath("/anything") {
		t.Errorf("expected /anything to match wildcard /*")
	}

	// Empty paths matches everything by default
	wm.SetTargetPaths(nil)
	if !wm.MatchesPath("/any-path") {
		t.Errorf("expected all paths to match when target paths are empty")
	}
}

func TestWaitingRoomManager_Metrics(t *testing.T) {
	wm := NewWaitingRoomManager(WaitingRoomConfig{
		MaxConcurrentInFlight: 1,
		MaxQueueDepth:         10,
		AdmissionRate:         1,
	})
	defer wm.Close()

	initial := wm.Metrics()
	if initial.TotalEnqueued != 0 || initial.TotalAdmitted != 0 {
		t.Errorf("expected 0 initial metrics, got %+v", initial)
	}

	ip := net.ParseIP("192.0.2.1")
	entry1, _, _, err := wm.Enqueue(ip, "ja4-1")
	if err != nil {
		t.Fatalf("enqueue error: %v", err)
	}
	entry2, _, _, err := wm.Enqueue(ip, "ja4-2")
	if err != nil {
		t.Fatalf("enqueue error: %v", err)
	}

	m1 := wm.Metrics()
	if m1.TotalEnqueued != 2 {
		t.Errorf("expected 2 enqueued, got %d", m1.TotalEnqueued)
	}
	if m1.PeakQueueDepth != 2 {
		t.Errorf("expected peak depth 2, got %d", m1.PeakQueueDepth)
	}
	if m1.TotalWaiting != 2 {
		t.Errorf("expected total waiting 2, got %d", m1.TotalWaiting)
	}

	// Admit entry1
	admitted := wm.AdmitEntry(entry1.ID)
	if !admitted {
		t.Fatalf("expected admit to succeed")
	}

	// Client 2 abandons (disconnects)
	wm.RemoveEntry(entry2.ID)

	m2 := wm.Metrics()
	if m2.TotalAdmitted != 1 {
		t.Errorf("expected 1 admitted, got %d", m2.TotalAdmitted)
	}
	if m2.TotalAbandoned != 1 {
		t.Errorf("expected 1 abandoned, got %d", m2.TotalAbandoned)
	}
	if m2.BounceRate != 50.0 {
		t.Errorf("expected 50%% bounce rate, got %f", m2.BounceRate)
	}
}
