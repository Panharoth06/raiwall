package caddy

import (
	"time"

	"go.uber.org/zap"
)

// telemetryFailureLogInterval bounds how often a persistent store outage is
// logged; the Prometheus counter still records every lost event.
const telemetryFailureLogInterval = time.Minute

// telemetryWriteFailureReporter returns the ring buffer error callback. The
// ring buffer invokes it from its single worker goroutine, so the closure's
// rate-limit state needs no lock.
func (m *Middleware) telemetryWriteFailureReporter() func(error, int) {
	var lastLog time.Time
	var suppressed int
	return func(err error, events int) {
		if m.metrics != nil {
			m.metrics.RecordTelemetryWriteFailed(float64(events))
		}
		if m.logger == nil {
			return
		}
		now := time.Now()
		if !lastLog.IsZero() && now.Sub(lastLog) < telemetryFailureLogInterval {
			suppressed += events
			return
		}
		m.logger.Error("telemetry store rejected forensic batch; events lost",
			zap.Error(err),
			zap.Int("events", events),
			zap.Int("suppressed_since_last_log", suppressed))
		lastLog = now
		suppressed = 0
	}
}

// TelemetryStats reports ring buffer counters for the control API /status.
func (m *Middleware) TelemetryStats() map[string]uint64 {
	if m.ringBuffer == nil {
		return nil
	}
	return map[string]uint64{
		"enqueued":     m.ringBuffer.Enqueued(),
		"flushed":      m.ringBuffer.Flushed(),
		"dropped":      m.ringBuffer.Dropped(),
		"write_failed": m.ringBuffer.Failed(),
	}
}
