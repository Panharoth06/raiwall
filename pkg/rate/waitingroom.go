package rate

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Default waiting room configuration constants.
const (
	DefaultMaxConcurrentInFlight int64         = 500
	DefaultMaxQueueDepth         int64         = 1000
	DefaultAdmissionRate         int64         = 50 // users per second
	DefaultAdmissionTokenTTL     time.Duration = 15 * time.Minute
	WaitingRoomEventsPath                      = "/.raiwall/waiting-room/events"
	WaitingRoomClearanceCookie                 = "rw_waiting_room_clearance"
)

// WaitingRoomConfig configures the Virtual Waiting Room engine.
type WaitingRoomConfig struct {
	MaxConcurrentInFlight int64
	MaxQueueDepth         int64
	AdmissionRate         int64 // admissions per second
	AdmissionTokenTTL     time.Duration
	Secret                string
	Logger                *zap.Logger
}

// QueueEntry records a client waiting in line.
type QueueEntry struct {
	ID          string
	ClientIP    string
	JA4         string
	EnteredAt   time.Time
	Admitted    bool
	NotifyCh    chan struct{}
	once        sync.Once
}

// WaitingRoomManager governs concurrent in-flight requests, user queueing, and SSE updates.
type WaitingRoomManager struct {
	maxConcurrent     int64
	maxQueueDepth     int64
	admissionRate     int64
	admissionTokenTTL time.Duration
	secret            []byte
	logger            *zap.Logger

	activeInFlight atomic.Int64
	mu             sync.Mutex
	queue          []*QueueEntry
	entries        map[string]*QueueEntry
	stopCh         chan struct{}
	closeOnce      sync.Once
}

// NewWaitingRoomManager creates and initializes a WaitingRoomManager.
func NewWaitingRoomManager(cfg WaitingRoomConfig) *WaitingRoomManager {
	maxConc := cfg.MaxConcurrentInFlight
	if maxConc <= 0 {
		maxConc = DefaultMaxConcurrentInFlight
	}
	maxQueue := cfg.MaxQueueDepth
	if maxQueue <= 0 {
		maxQueue = DefaultMaxQueueDepth
	}
	admitRate := cfg.AdmissionRate
	if admitRate <= 0 {
		admitRate = DefaultAdmissionRate
	}
	ttl := cfg.AdmissionTokenTTL
	if ttl <= 0 {
		ttl = DefaultAdmissionTokenTTL
	}

	secretBytes := []byte(cfg.Secret)
	if len(secretBytes) == 0 {
		secretBytes = make([]byte, 32)
		_, _ = rand.Read(secretBytes)
	}

	wm := &WaitingRoomManager{
		maxConcurrent:     maxConc,
		maxQueueDepth:     maxQueue,
		admissionRate:     admitRate,
		admissionTokenTTL: ttl,
		secret:            secretBytes,
		logger:            cfg.Logger,
		entries:           make(map[string]*QueueEntry),
		stopCh:            make(chan struct{}),
	}

	go wm.admissionLoop()

	return wm
}

// GenerateAdmissionToken signs an admission token bound to IP and JA4.
func (wm *WaitingRoomManager) GenerateAdmissionToken(ip net.IP, ja4 string, ttl time.Duration) string {
	if ttl == 0 {
		ttl = wm.admissionTokenTTL
	}
	ipStr := ""
	if ip != nil {
		ipStr = ip.String()
	}

	expiresAt := time.Now().Add(ttl).Unix()
	payload := fmt.Sprintf("%d:%s:%s", expiresAt, ipStr, ja4)

	mac := hmac.New(sha256.New, wm.secret)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf("%s:%s", payload, sig)
}

// ValidateAdmissionToken verifies that token is authentic, unexpired, and bound to IP + JA4.
func (wm *WaitingRoomManager) ValidateAdmissionToken(token string, ip net.IP, ja4 string) bool {
	parts := strings.Split(token, ":")
	if len(parts) != 4 {
		return false
	}

	expiresAtUnix, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}

	if time.Now().Unix() > expiresAtUnix {
		return false // Expired
	}

	tokenIP := parts[1]
	tokenJA4 := parts[2]
	providedSig := parts[3]

	ipStr := ""
	if ip != nil {
		ipStr = ip.String()
	}

	// Verify IP binding if token was bound to an IP
	if tokenIP != "" && ipStr != "" && tokenIP != ipStr {
		return false
	}
	// Verify JA4 binding if token was bound to JA4
	if tokenJA4 != "" && ja4 != "" && tokenJA4 != ja4 {
		return false
	}

	payload := fmt.Sprintf("%d:%s:%s", expiresAtUnix, tokenIP, tokenJA4)
	mac := hmac.New(sha256.New, wm.secret)
	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(providedSig), []byte(expectedSig))
}

// IsAdmitted checks if incoming request carries a valid admission token.
func (wm *WaitingRoomManager) IsAdmitted(r *http.Request, ip net.IP, ja4 string) bool {
	if r == nil {
		return false
	}

	// 1. Check header
	if token := r.Header.Get("X-Raiwall-Admission-Token"); token != "" {
		if wm.ValidateAdmissionToken(token, ip, ja4) {
			return true
		}
	}

	// 2. Check clearance cookie
	if cookie, err := r.Cookie(WaitingRoomClearanceCookie); err == nil && cookie.Value != "" {
		if wm.ValidateAdmissionToken(cookie.Value, ip, ja4) {
			return true
		}
	}

	return false
}

// AcquireLease increments the in-flight request count and returns a release callback.
func (wm *WaitingRoomManager) AcquireLease() func() {
	wm.activeInFlight.Add(1)
	var released int32
	return func() {
		if atomic.CompareAndSwapInt32(&released, 0, 1) {
			wm.activeInFlight.Add(-1)
		}
	}
}

// InFlightCount returns the current count of concurrent in-flight requests.
func (wm *WaitingRoomManager) InFlightCount() int64 {
	return wm.activeInFlight.Load()
}

// QueueDepth returns the count of currently queued clients waiting for admission.
func (wm *WaitingRoomManager) QueueDepth() int {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	return len(wm.queue)
}

// ShouldEnterWaitingRoom determines whether an unadmitted request must enter the queue.
func (wm *WaitingRoomManager) ShouldEnterWaitingRoom() bool {
	return wm.activeInFlight.Load() >= wm.maxConcurrent
}

// Enqueue adds a client to the waiting queue or sheds load if maxQueueDepth is exceeded.
func (wm *WaitingRoomManager) Enqueue(ip net.IP, ja4 string) (*QueueEntry, int, int, error) {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	if int64(len(wm.queue)) >= wm.maxQueueDepth {
		return nil, 0, 0, errors.New("waiting room queue full (load shed)")
	}

	ipStr := ""
	if ip != nil {
		ipStr = ip.String()
	}

	entry := &QueueEntry{
		ID:        uuid.New().String(),
		ClientIP:  ipStr,
		JA4:       ja4,
		EnteredAt: time.Now(),
		NotifyCh:  make(chan struct{}),
	}

	wm.queue = append(wm.queue, entry)
	wm.entries[entry.ID] = entry

	position := len(wm.queue)
	waitSeconds := int((int64(position) + wm.admissionRate - 1) / wm.admissionRate)

	return entry, position, waitSeconds, nil
}

// GetPosition returns the current position (1-based) of the given queue entry ID.
func (wm *WaitingRoomManager) GetPosition(id string) (int, int, bool) {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	entry, exists := wm.entries[id]
	if !exists {
		return 0, 0, false
	}
	if entry.Admitted {
		return 0, 0, true
	}

	for i, q := range wm.queue {
		if q.ID == id {
			pos := i + 1
			wait := int((int64(pos) + wm.admissionRate - 1) / wm.admissionRate)
			return pos, wait, false
		}
	}

	return 0, 0, false
}

// AdmitEntry immediately marks an entry as admitted and signals its notification channel.
func (wm *WaitingRoomManager) AdmitEntry(id string) bool {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	entry, exists := wm.entries[id]
	if !exists || entry.Admitted {
		return false
	}
	entry.Admitted = true
	entry.once.Do(func() {
		close(entry.NotifyCh)
	})
	return true
}

// RemoveEntry cleans up an entry from the queue (e.g. on client disconnect).
func (wm *WaitingRoomManager) RemoveEntry(id string) {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	delete(wm.entries, id)
	for i, q := range wm.queue {
		if q.ID == id {
			wm.queue = append(wm.queue[:i], wm.queue[i+1:]...)
			break
		}
	}
}

// HandleSSE serves the Server-Sent Events stream for a waiting client.
func (wm *WaitingRoomManager) HandleSSE(w http.ResponseWriter, r *http.Request, ip net.IP, ja4 string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	queueID := r.URL.Query().Get("id")
	if queueID == "" {
		http.Error(w, "Missing queue ID", http.StatusBadRequest)
		return
	}

	PrepareSSEHeaders(w)
	flusher.Flush()

	pos, wait, admitted := wm.GetPosition(queueID)
	if admitted {
		token := wm.GenerateAdmissionToken(ip, ja4, wm.admissionTokenTTL)
		_ = WriteSSE(w, "admitted", SSEUpdate{Position: 0, WaitSeconds: 0, Admitted: true, Token: token})
		flusher.Flush()
		return
	}
	if pos == 0 {
		http.Error(w, "Queue entry expired or not found", http.StatusNotFound)
		return
	}

	// Send initial status
	_ = WriteSSE(w, "update", SSEUpdate{Position: pos, WaitSeconds: wait, Admitted: false})
	flusher.Flush()

	wm.mu.Lock()
	entry := wm.entries[queueID]
	wm.mu.Unlock()
	if entry == nil {
		return
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			wm.RemoveEntry(queueID)
			return
		case <-entry.NotifyCh:
			// Admitted!
			token := wm.GenerateAdmissionToken(ip, ja4, wm.admissionTokenTTL)
			_ = WriteSSE(w, "admitted", SSEUpdate{Position: 0, WaitSeconds: 0, Admitted: true, Token: token})
			flusher.Flush()
			return
		case <-ticker.C:
			currentPos, currentWait, isAdmitted := wm.GetPosition(queueID)
			if isAdmitted {
				token := wm.GenerateAdmissionToken(ip, ja4, wm.admissionTokenTTL)
				_ = WriteSSE(w, "admitted", SSEUpdate{Position: 0, WaitSeconds: 0, Admitted: true, Token: token})
				flusher.Flush()
				return
			}
			if currentPos > 0 {
				_ = WriteSSE(w, "update", SSEUpdate{Position: currentPos, WaitSeconds: currentWait, Admitted: false})
				flusher.Flush()
			}
		}
	}
}

// admissionLoop periodically admits queued users according to admissionRate and available capacity.
func (wm *WaitingRoomManager) admissionLoop() {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-wm.stopCh:
			return
		case <-ticker.C:
			wm.processAdmissions()
		}
	}
}

func (wm *WaitingRoomManager) processAdmissions() {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	if len(wm.queue) == 0 {
		return
	}

	inFlight := wm.activeInFlight.Load()
	availableCapacity := wm.maxConcurrent - inFlight
	if availableCapacity <= 0 {
		return
	}

	// Per-tick admission allocation (5 ticks per second for 200ms)
	perTickLimit := (wm.admissionRate + 4) / 5
	if perTickLimit <= 0 {
		perTickLimit = 1
	}

	admitCount := int(availableCapacity)
	if int64(admitCount) > perTickLimit {
		admitCount = int(perTickLimit)
	}
	if admitCount > len(wm.queue) {
		admitCount = len(wm.queue)
	}

	for i := 0; i < admitCount; i++ {
		entry := wm.queue[i]
		entry.Admitted = true
		entry.once.Do(func() {
			close(entry.NotifyCh)
		})
	}

	wm.queue = wm.queue[admitCount:]
}

// Close terminates the admission loop.
func (wm *WaitingRoomManager) Close() error {
	wm.closeOnce.Do(func() {
		close(wm.stopCh)
	})
	return nil
}
