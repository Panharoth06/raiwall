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

func TestWaitingRoomManager_TokenValidation(t *testing.T) {
	wm := NewWaitingRoomManager(WaitingRoomConfig{
		Secret:            "test-secret-waiting-room-32bytes",
		AdmissionTokenTTL: 10 * time.Minute,
	})
	defer wm.Close()

	ip := net.ParseIP("198.51.100.42")
	ja4 := "t13d1516h2_8daaf6152771_0123456789ab"

	token := wm.GenerateAdmissionToken(ip, ja4, 5*time.Minute)
	if token == "" {
		t.Fatalf("generated token is empty")
	}

	// Valid token
	if !wm.ValidateAdmissionToken(token, ip, ja4) {
		t.Errorf("expected token to be valid for matching ip and ja4")
	}

	// Mismatched IP
	otherIP := net.ParseIP("198.51.100.99")
	if wm.ValidateAdmissionToken(token, otherIP, ja4) {
		t.Errorf("token should be invalid for mismatched IP")
	}

	// Mismatched JA4
	if wm.ValidateAdmissionToken(token, ip, "other_ja4_signature") {
		t.Errorf("token should be invalid for mismatched JA4")
	}

	// Tampered signature
	tampered := token[:len(token)-4] + "ffff"
	if wm.ValidateAdmissionToken(tampered, ip, ja4) {
		t.Errorf("tampered token should be rejected")
	}

	// Expired token
	expiredToken := wm.GenerateAdmissionToken(ip, ja4, -1*time.Minute)
	if wm.ValidateAdmissionToken(expiredToken, ip, ja4) {
		t.Errorf("expired token should be rejected")
	}

	// Request with cookie
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.AddCookie(&http.Cookie{Name: WaitingRoomClearanceCookie, Value: token})
	if !wm.IsAdmitted(req, ip, ja4) {
		t.Errorf("IsAdmitted should return true for request with valid cookie")
	}
}

func TestWaitingRoomManager_LeaseAndQueue(t *testing.T) {
	wm := NewWaitingRoomManager(WaitingRoomConfig{
		MaxConcurrentInFlight: 2,
		MaxQueueDepth:         3,
		AdmissionRate:         10,
	})
	defer wm.Close()

	// Initially in-flight is 0, below max
	if wm.ShouldEnterWaitingRoom() {
		t.Fatalf("should not enter waiting room when under capacity")
	}

	// Acquire leases to fill capacity
	rel1 := wm.AcquireLease()
	rel2 := wm.AcquireLease()

	if wm.InFlightCount() != 2 {
		t.Errorf("expected 2 in-flight, got %d", wm.InFlightCount())
	}
	if !wm.ShouldEnterWaitingRoom() {
		t.Fatalf("should enter waiting room when at max capacity")
	}

	// Queue up to maxQueueDepth (3)
	ip := net.ParseIP("198.51.100.1")
	entry1, pos1, wait1, err := wm.Enqueue(ip, "ja4-1")
	if err != nil || pos1 != 1 || wait1 <= 0 {
		t.Fatalf("enqueue 1 failed: %v", err)
	}

	_, pos2, _, err := wm.Enqueue(ip, "ja4-2")
	if err != nil || pos2 != 2 {
		t.Fatalf("enqueue 2 failed: %v", err)
	}

	_, pos3, _, err := wm.Enqueue(ip, "ja4-3")
	if err != nil || pos3 != 3 {
		t.Fatalf("enqueue 3 failed: %v", err)
	}

	// 4th enqueue should be shed (hard queue limit reached)
	_, _, _, err = wm.Enqueue(ip, "ja4-4")
	if err == nil {
		t.Fatalf("expected load shedding error when exceeding maxQueueDepth")
	}
	if !strings.Contains(err.Error(), "load shed") {
		t.Errorf("unexpected error message: %v", err)
	}

	// Release 1 lease: admissionLoop should admit entry1
	rel1()
	rel2()

	// Wait briefly for admission loop
	select {
	case <-entry1.NotifyCh:
		// Successfully admitted!
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for entry1 admission")
	}

	pos, _, admitted := wm.GetPosition(entry1.ID)
	if !admitted || pos != 0 {
		t.Errorf("entry1 should be admitted, got pos=%d admitted=%v", pos, admitted)
	}
}

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
