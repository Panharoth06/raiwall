package caddy

import (
	"errors"
	"testing"

	"github.com/Panharoth06/raiwall/internal/core/telemetry"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestTelemetryWriteFailureReporterCountsAndRateLimits(t *testing.T) {
	core, logs := observer.New(zap.ErrorLevel)
	m := &Middleware{logger: zap.New(core), metrics: telemetry.NewMetrics(prometheus.NewRegistry())}

	report := m.telemetryWriteFailureReporter()
	for range 3 {
		report(errors.New("insert failed"), 5)
	}

	if got := testutil.ToFloat64(m.metrics.TelemetryFailedTotal); got != 15 {
		t.Fatalf("write_failed counter = %v, want 15", got)
	}
	if logs.Len() != 1 {
		t.Fatalf("expected 1 rate-limited log line, got %d", logs.Len())
	}
}
