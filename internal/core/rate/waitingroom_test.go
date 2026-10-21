package rate

import (
	"net"
	"net/http"
	"strings"
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

func TestWaitingRoomManager_NoQueueJumping(t *testing.T) {
	wm := NewWaitingRoomManager(WaitingRoomConfig{
		MaxConcurrentInFlight: 10,
		MaxQueueDepth:         20,
		AdmissionRate:         5,
	})
	defer wm.Close()

	// Initially in-flight is 0, queue is empty -> false
	if wm.ShouldEnterWaitingRoom() {
		t.Errorf("expected ShouldEnterWaitingRoom=false when in-flight is 0 and queue is empty")
	}

	// Enqueue a client
	_, _, _, err := wm.Enqueue(net.ParseIP("192.0.2.1"), "ja4-1")
	if err != nil {
		t.Fatalf("failed to enqueue: %v", err)
	}

	// Now queue depth is 1, even though in-flight is 0, new arrivals MUST enter waiting room
	if !wm.ShouldEnterWaitingRoom() {
		t.Errorf("queue jumping allowed! ShouldEnterWaitingRoom must be true when clients are waiting in queue")
	}
}

func TestWaitingRoomManager_FindActiveEntry(t *testing.T) {
	wm := NewWaitingRoomManager(WaitingRoomConfig{
		MaxConcurrentInFlight: 5,
		MaxQueueDepth:         10,
		AdmissionRate:         2,
	})
	defer wm.Close()

	entry, _, _, err := wm.Enqueue(net.ParseIP("192.0.2.55"), "ja4-active")
	if err != nil {
		t.Fatalf("enqueue error: %v", err)
	}

	pos, wait, admitted, found := wm.FindActiveEntry(entry.ID)
	if found == nil || found.ID != entry.ID {
		t.Fatalf("expected to find active entry")
	}
	if pos != 1 {
		t.Errorf("expected pos=1, got %d", pos)
	}
	if wait <= 0 {
		t.Errorf("expected positive wait time, got %d", wait)
	}
	if admitted {
		t.Errorf("expected admitted=false")
	}

	// Non-existent ID
	_, _, _, foundNone := wm.FindActiveEntry("unknown-id")
	if foundNone != nil {
		t.Errorf("expected nil for unknown ID")
	}
}

func TestWaitingRoomManager_PathPrefixMatching(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		prefix   string
		expected bool
	}{
		{"exact match /checkout", "/checkout", "/checkout", true},
		{"subpath match /checkout/step1", "/checkout/step1", "/checkout", true},
		{"prefix boundary safety /checkout_cancel", "/checkout_cancel", "/checkout", false},
		{"wildcard suffix /* match", "/tickets/buy", "/tickets/*", true},
		{"wildcard suffix boundary /tickets_cancel", "/tickets_cancel", "/tickets/*", false},
		{"wildcard suffix exact directory /tickets", "/tickets", "/tickets/*", true},
		{"wildcard without slash /api* matches /apikeys", "/apikeys", "/api*", true},
		{"wildcard with slash /api/* rejects /apikeys", "/apikeys", "/api/*", false},
		{"global wildcard /* matches anything", "/any/path", "/*", true},
		{"empty prefix matches anything", "/any/path", "", true},
		{"root prefix / matches anything", "/any/path", "/", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchesWaitingRoomPathPrefix(tc.path, tc.prefix)
			if got != tc.expected {
				t.Errorf("MatchesWaitingRoomPathPrefix(%q, %q) = %v; expected %v", tc.path, tc.prefix, got, tc.expected)
			}
		})
	}
}

func TestWaitingRoomManager_SetMaxConcurrent(t *testing.T) {
	wm := NewWaitingRoomManager(WaitingRoomConfig{
		MaxConcurrentInFlight: 5,
		MaxQueueDepth:         10,
	})
	defer wm.Close()

	if wm.MaxConcurrent() != 5 {
		t.Errorf("expected MaxConcurrent 5, got %d", wm.MaxConcurrent())
	}

	wm.SetMaxConcurrent(20)
	if wm.MaxConcurrent() != 20 {
		t.Errorf("expected updated MaxConcurrent 20, got %d", wm.MaxConcurrent())
	}

	// Negative/zero should be ignored
	wm.SetMaxConcurrent(-1)
	if wm.MaxConcurrent() != 20 {
		t.Errorf("expected MaxConcurrent unchanged on invalid input, got %d", wm.MaxConcurrent())
	}
}

func TestWaitingRoomManager_QueueMetricsCalculation(t *testing.T) {
	wm := NewWaitingRoomManager(WaitingRoomConfig{
		MaxConcurrentInFlight: 1,
		MaxQueueDepth:         10,
		AdmissionRate:         10,
	})
	defer wm.Close()

	m0 := wm.Metrics()
	if m0.ActiveInFlight != 0 || m0.TotalWaiting != 0 {
		t.Errorf("expected zero metrics initially, got %+v", m0)
	}

	// Enqueue client and verify metrics
	entry, _, _, err := wm.Enqueue(net.ParseIP("192.0.2.1"), "ja4")
	if err != nil {
		t.Fatalf("enqueue error: %v", err)
	}

	m1 := wm.Metrics()
	if m1.TotalWaiting != 1 || m1.PeakQueueDepth != 1 || m1.TotalEnqueued != 1 {
		t.Errorf("unexpected metrics after enqueue: %+v", m1)
	}

	// Remove entry (abandonment)
	wm.RemoveEntry(entry.ID)
	m2 := wm.Metrics()
	if m2.TotalAbandoned != 1 || m2.BounceRate != 100.0 {
		t.Errorf("expected 100%% bounce rate on abandoned entry, got %+v", m2)
	}
}
