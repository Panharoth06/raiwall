package telemetry

import (
	"sync"
	"time"
)

const (
	// DefaultAlertCooldown is the default suppression window per (IP + RuleID).
	DefaultAlertCooldown = 5 * time.Minute
)

// AlertDebouncer tracks recent incident alerts using a sliding window cache
// to suppress alert fatigue and summarize burst attacks.
type AlertDebouncer struct {
	mu          sync.Mutex
	cooldown    time.Duration
	lastAlerts  map[string]time.Time
	burstCounts map[string]int
}

// NewAlertDebouncer constructs an AlertDebouncer with the specified cooldown window.
func NewAlertDebouncer(cooldown time.Duration) *AlertDebouncer {
	if cooldown <= 0 {
		cooldown = DefaultAlertCooldown
	}
	return &AlertDebouncer{
		cooldown:    cooldown,
		lastAlerts:  make(map[string]time.Time),
		burstCounts: make(map[string]int),
	}
}

// ShouldAlert evaluates whether an incident for the given event should trigger an alert.
// Returns shouldAlert (true/false) and the number of suppressed duplicate occurrences since last alert.
func (d *AlertDebouncer) ShouldAlert(event *ForensicEvent) (bool, int) {
	if event == nil {
		return false, 0
	}

	key := event.ClientIP + ":" + event.RuleID
	now := time.Now()

	d.mu.Lock()
	defer d.mu.Unlock()

	lastTime, exists := d.lastAlerts[key]
	if !exists || now.Sub(lastTime) >= d.cooldown {
		suppressed := d.burstCounts[key]
		d.lastAlerts[key] = now
		d.burstCounts[key] = 0
		return true, suppressed
	}

	// Within cooldown window: suppress and increment burst count
	d.burstCounts[key]++
	return false, d.burstCounts[key]
}

// Reset clears the internal cache for a specific key (useful in testing or manual unblocks).
func (d *AlertDebouncer) Reset(clientIP, ruleID string) {
	key := clientIP + ":" + ruleID
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.lastAlerts, key)
	delete(d.burstCounts, key)
}

// Cleanup removes entries that have been idle for longer than 2x cooldown.
func (d *AlertDebouncer) Cleanup() {
	now := time.Now()
	threshold := 2 * d.cooldown

	d.mu.Lock()
	defer d.mu.Unlock()

	for k, t := range d.lastAlerts {
		if now.Sub(t) > threshold {
			delete(d.lastAlerts, k)
			delete(d.burstCounts, k)
		}
	}
}
