package rate

import (
	"strings"
)

// WaitingRoomMetrics captures real-time virtual waiting room queue performance.
type WaitingRoomMetrics struct {
	ActiveInFlight int64   `json:"active_in_flight"`
	TotalWaiting   int64   `json:"total_waiting"`
	PeakQueueDepth int64   `json:"peak_queue_depth"`
	AvgWaitSeconds float64 `json:"avg_wait_seconds"`
	BounceRate     float64 `json:"bounce_rate"`
	TotalAdmitted  int64   `json:"total_admitted"`
	TotalEnqueued  int64   `json:"total_enqueued"`
	TotalAbandoned int64   `json:"total_abandoned"`
}

// MatchesPath checks whether the given request path matches configured waiting room target prefixes.
// If no target paths are configured, all paths match by default.
func (wm *WaitingRoomManager) MatchesPath(path string) bool {
	if wm == nil {
		return false
	}
	wm.muTarget.RLock()
	defer wm.muTarget.RUnlock()

	if len(wm.targetPaths) == 0 {
		return true
	}

	for _, prefix := range wm.targetPaths {
		prefix = strings.TrimSpace(prefix)
		if prefix == "" || prefix == "/*" || prefix == "/" {
			return true
		}
		cleanPrefix := strings.TrimSuffix(prefix, "/*")
		cleanPrefix = strings.TrimSuffix(cleanPrefix, "*")
		if path == cleanPrefix || strings.HasPrefix(path, cleanPrefix+"/") || strings.HasPrefix(path, cleanPrefix) {
			return true
		}
	}
	return false
}

// SetTargetPaths dynamically configures path prefixes subject to waiting room queueing.
func (wm *WaitingRoomManager) SetTargetPaths(paths []string) {
	if wm == nil {
		return
	}
	wm.muTarget.Lock()
	defer wm.muTarget.Unlock()
	wm.targetPaths = make([]string, len(paths))
	copy(wm.targetPaths, paths)
}

// TargetPaths returns a copy of configured target paths.
func (wm *WaitingRoomManager) TargetPaths() []string {
	if wm == nil {
		return nil
	}
	wm.muTarget.RLock()
	defer wm.muTarget.RUnlock()
	res := make([]string, len(wm.targetPaths))
	copy(res, wm.targetPaths)
	return res
}

// Metrics computes real-time waiting room queue telemetry.
func (wm *WaitingRoomManager) Metrics() WaitingRoomMetrics {
	if wm == nil {
		return WaitingRoomMetrics{}
	}

	wm.mu.Lock()
	waitingCount := int64(len(wm.queue))
	wm.mu.Unlock()

	admitted := wm.totalAdmitted.Load()
	enqueued := wm.totalEnqueued.Load()
	abandoned := wm.totalAbandoned.Load()
	waitDuration := wm.totalWaitDuration.Load()

	var avgWaitSec float64
	if admitted > 0 {
		avgWaitSec = float64(waitDuration) / float64(admitted) / 1e9
	}

	var bounceRate float64
	if enqueued > 0 {
		bounceRate = (float64(abandoned) / float64(enqueued)) * 100.0
	}

	return WaitingRoomMetrics{
		ActiveInFlight: wm.activeInFlight.Load(),
		TotalWaiting:   waitingCount,
		PeakQueueDepth: wm.peakQueueDepth.Load(),
		AvgWaitSeconds: avgWaitSec,
		BounceRate:     bounceRate,
		TotalAdmitted:  admitted,
		TotalEnqueued:  enqueued,
		TotalAbandoned: abandoned,
	}
}
