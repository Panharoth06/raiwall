package rate

import (
	"crypto/rand"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

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
	WaitingRoomQueueCookie                     = "rw_waiting_room_queue_id"
)

// WaitingRoomConfig configures the Virtual Waiting Room engine.
type WaitingRoomConfig struct {
	MaxConcurrentInFlight int64
	MaxQueueDepth         int64
	AdmissionRate         int64 // admissions per second
	AdmissionTokenTTL     time.Duration
	Secret                string
	TargetPaths           []string
	Logger                *zap.Logger
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

	muTarget          sync.RWMutex
	targetPaths       []string
	peakQueueDepth    atomic.Int64
	totalAdmitted     atomic.Int64
	totalEnqueued     atomic.Int64
	totalAbandoned    atomic.Int64
	totalWaitDuration atomic.Int64
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
		targetPaths:       cfg.TargetPaths,
		entries:           make(map[string]*QueueEntry),
		stopCh:            make(chan struct{}),
	}

	go wm.admissionLoop()

	return wm
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

// MaxConcurrent returns the configured max concurrent in-flight capacity.
func (wm *WaitingRoomManager) MaxConcurrent() int64 {
	if wm == nil {
		return 0
	}
	wm.mu.Lock()
	defer wm.mu.Unlock()
	return wm.maxConcurrent
}

// SetMaxConcurrent updates the max concurrent in-flight capacity in real time.
func (wm *WaitingRoomManager) SetMaxConcurrent(limit int64) {
	if wm == nil || limit <= 0 {
		return
	}
	wm.mu.Lock()
	defer wm.mu.Unlock()
	wm.maxConcurrent = limit
}

// ShouldEnterWaitingRoom determines whether an unadmitted request must enter the queue.
func (wm *WaitingRoomManager) ShouldEnterWaitingRoom() bool {
	if wm == nil {
		return false
	}
	wm.mu.Lock()
	defer wm.mu.Unlock()
	return len(wm.queue) > 0 || wm.activeInFlight.Load() >= wm.maxConcurrent
}

// Close terminates the admission loop.
func (wm *WaitingRoomManager) Close() error {
	wm.closeOnce.Do(func() {
		close(wm.stopCh)
	})
	return nil
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

	pos, wait, admitted := wm.GetPosition(queueID)
	if !admitted && pos == 0 {
		http.Error(w, "Queue entry expired or not found", http.StatusNotFound)
		return
	}

	PrepareSSEHeaders(w)
	flusher.Flush()

	if admitted {
		token := wm.GenerateAdmissionToken(ip, ja4, wm.admissionTokenTTL)
		_ = WriteSSE(w, "admitted", SSEUpdate{Position: 0, WaitSeconds: 0, Admitted: true, Token: token})
		flusher.Flush()
		wm.RemoveEntry(queueID)
		return
	}

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
			token := wm.GenerateAdmissionToken(ip, ja4, wm.admissionTokenTTL)
			_ = WriteSSE(w, "admitted", SSEUpdate{Position: 0, WaitSeconds: 0, Admitted: true, Token: token})
			flusher.Flush()
			wm.RemoveEntry(queueID)
			return
		case <-ticker.C:
			currentPos, currentWait, isAdmitted := wm.GetPosition(queueID)
			if isAdmitted {
				token := wm.GenerateAdmissionToken(ip, ja4, wm.admissionTokenTTL)
				_ = WriteSSE(w, "admitted", SSEUpdate{Position: 0, WaitSeconds: 0, Admitted: true, Token: token})
				flusher.Flush()
				wm.RemoveEntry(queueID)
				return
			}
			if currentPos > 0 {
				_ = WriteSSE(w, "update", SSEUpdate{Position: currentPos, WaitSeconds: currentWait, Admitted: false})
				flusher.Flush()
			}
		}
	}
}

func (wm *WaitingRoomManager) admissionLoop() {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	evictTicker := time.NewTicker(30 * time.Second)
	defer evictTicker.Stop()

	for {
		select {
		case <-wm.stopCh:
			return
		case <-ticker.C:
			wm.processAdmissions()
		case <-evictTicker.C:
			wm.evictStaleEntries()
		}
	}
}

func (wm *WaitingRoomManager) evictStaleEntries() {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-5 * time.Minute)

	for id, entry := range wm.entries {
		if entry.EnteredAt.Before(cutoff) {
			if !entry.Admitted {
				wm.totalAbandoned.Add(1)
			}
			delete(wm.entries, id)
		}
	}

	n := 0
	for _, entry := range wm.queue {
		if !entry.EnteredAt.Before(cutoff) {
			wm.queue[n] = entry
			n++
		}
	}
	wm.queue = wm.queue[:n]
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
			wm.totalAdmitted.Add(1)
			wm.totalWaitDuration.Add(time.Since(entry.EnteredAt).Nanoseconds())
		})
	}

	wm.queue = wm.queue[admitCount:]
}
