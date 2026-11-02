package caddy

import "sync/atomic"

// InflightBudget tracks global in-flight buffered response bytes for inspection.
// It prevents out-of-memory errors when multiple large responses are processed concurrently.
type InflightBudget struct {
	maxBytes int64
	current  atomic.Int64
}

// NewInflightBudget creates a new budget with the specified byte cap.
func NewInflightBudget(maxBytes int64) *InflightBudget {
	if maxBytes <= 0 {
		maxBytes = 64 * 1024 * 1024 // 64 MiB default
	}
	return &InflightBudget{maxBytes: maxBytes}
}

// Reserve attempts to allocate n bytes from the in-flight budget.
func (b *InflightBudget) Reserve(n int64) bool {
	if b == nil || n <= 0 {
		return true
	}
	val := b.current.Add(n)
	if val > b.maxBytes {
		b.current.Add(-n)
		return false
	}
	return true
}

// Release returns n bytes back to the in-flight budget.
func (b *InflightBudget) Release(n int64) {
	if b != nil && n > 0 {
		b.current.Add(-n)
	}
}

// Current returns the current buffered bytes count.
func (b *InflightBudget) Current() int64 {
	if b == nil {
		return 0
	}
	return b.current.Load()
}
