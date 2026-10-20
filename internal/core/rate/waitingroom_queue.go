package rate

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
)

// QueueEntry records a client waiting in line.
type QueueEntry struct {
	ID        string
	ClientIP  string
	JA4       string
	EnteredAt time.Time
	Admitted  bool
	NotifyCh  chan struct{}
	once      sync.Once
}

// QueueDepth returns the count of currently queued clients waiting for admission.
func (wm *WaitingRoomManager) QueueDepth() int {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	return len(wm.queue)
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

	wm.totalEnqueued.Add(1)
	qLen := int64(len(wm.queue))
	for {
		peak := wm.peakQueueDepth.Load()
		if qLen <= peak || wm.peakQueueDepth.CompareAndSwap(peak, qLen) {
			break
		}
	}

	position := len(wm.queue)
	waitSeconds := int((int64(position) + wm.admissionRate - 1) / wm.admissionRate)

	return entry, position, waitSeconds, nil
}

// GetPosition returns the current position (1-based) of the given queue entry ID.
func (wm *WaitingRoomManager) GetPosition(id string) (int, int, bool) {
	if wm == nil || id == "" {
		return 0, 0, false
	}
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

// FindActiveEntry checks if an entry is active in the queue and returns its current position and wait time.
func (wm *WaitingRoomManager) FindActiveEntry(id string) (int, int, bool, *QueueEntry) {
	if wm == nil || id == "" {
		return 0, 0, false, nil
	}
	wm.mu.Lock()
	defer wm.mu.Unlock()

	entry, exists := wm.entries[id]
	if !exists {
		return 0, 0, false, nil
	}
	if entry.Admitted {
		return 0, 0, true, entry
	}

	for i, q := range wm.queue {
		if q.ID == id {
			pos := i + 1
			wait := int((int64(pos) + wm.admissionRate - 1) / wm.admissionRate)
			return pos, wait, false, entry
		}
	}

	return 0, 0, false, nil
}

// AdmitEntry immediately marks an entry as admitted and signals its notification channel.
func (wm *WaitingRoomManager) AdmitEntry(id string) bool {
	if wm == nil || id == "" {
		return false
	}
	wm.mu.Lock()
	defer wm.mu.Unlock()

	entry, exists := wm.entries[id]
	if !exists || entry.Admitted {
		return false
	}
	entry.Admitted = true
	entry.once.Do(func() {
		close(entry.NotifyCh)
		wm.totalAdmitted.Add(1)
		wm.totalWaitDuration.Add(time.Since(entry.EnteredAt).Nanoseconds())
	})
	return true
}

// RemoveEntry cleans up an entry from the queue (e.g. on client disconnect).
func (wm *WaitingRoomManager) RemoveEntry(id string) {
	if wm == nil || id == "" {
		return
	}
	wm.mu.Lock()
	defer wm.mu.Unlock()

	entry, exists := wm.entries[id]
	if exists && !entry.Admitted {
		wm.totalAbandoned.Add(1)
	}

	delete(wm.entries, id)
	for i, q := range wm.queue {
		if q.ID == id {
			wm.queue = append(wm.queue[:i], wm.queue[i+1:]...)
			break
		}
	}
}

// Clear removes all active entries and clears the waiting queue (useful for test resets).
func (wm *WaitingRoomManager) Clear() {
	if wm == nil {
		return
	}
	wm.mu.Lock()
	defer wm.mu.Unlock()
	wm.queue = wm.queue[:0]
	wm.entries = make(map[string]*QueueEntry)
	wm.peakQueueDepth.Store(0)
	wm.totalAdmitted.Store(0)
	wm.totalEnqueued.Store(0)
	wm.totalAbandoned.Store(0)
	wm.totalWaitDuration.Store(0)
}
