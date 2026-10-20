package alerts

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/telemetry"
)

type mockAlertSender struct {
	sentCount atomic.Int32
	lastURL   string
	lastMsg   string
}

func (m *mockAlertSender) Send(ctx context.Context, rawURL, message string) error {
	m.sentCount.Add(1)
	m.lastURL = rawURL
	m.lastMsg = message
	return nil
}

func TestAlertDebouncer_SuppressionAndReset(t *testing.T) {
	debouncer := telemetry.NewAlertDebouncer(100 * time.Millisecond)

	event := &telemetry.ForensicEvent{
		ClientIP: "1.2.3.4",
		RuleID:   "SQLI_RULE",
	}

	should, burst := debouncer.ShouldAlert(event)
	if !should || burst != 0 {
		t.Fatalf("expected first event to alert, got should=%v burst=%d", should, burst)
	}

	should, burst = debouncer.ShouldAlert(event)
	if should || burst != 1 {
		t.Fatalf("expected second event to be suppressed, got should=%v burst=%d", should, burst)
	}

	should, burst = debouncer.ShouldAlert(event)
	if should || burst != 2 {
		t.Fatalf("expected third event to be suppressed, got should=%v burst=%d", should, burst)
	}

	time.Sleep(120 * time.Millisecond)

	should, burst = debouncer.ShouldAlert(event)
	if !should || burst != 2 {
		t.Fatalf("expected post-cooldown event to alert with burst=2, got should=%v burst=%d", should, burst)
	}
}

func TestAlertEngine_DispatchFiltering(t *testing.T) {
	sender := &mockAlertSender{}
	channels := []AlertChannel{
		{
			Name:   "slack-critical",
			URL:    "slack://hooks.slack.com/services/test",
			Events: []string{"block", "ban"},
		},
	}

	engine := NewAlertEngine(channels, 50*time.Millisecond, sender)

	ctx := context.Background()

	allowEvent := &telemetry.ForensicEvent{
		EventID:  "evt-allow",
		ClientIP: "10.0.0.1",
		Action:   "allow",
		Severity: "info",
	}
	_ = engine.Dispatch(ctx, allowEvent)
	if sender.sentCount.Load() != 0 {
		t.Errorf("expected 0 alerts for allow action, got %d", sender.sentCount.Load())
	}

	blockEvent := &telemetry.ForensicEvent{
		EventID:   "evt-block",
		ClientIP:  "10.0.0.1",
		Host:      "api.example.com",
		Path:      "/admin",
		Method:    "GET",
		Action:    "block",
		Severity:  "high",
		RuleID:    "SQLI_RULE",
		Timestamp: time.Now(),
		GeoData: telemetry.GeoData{
			Country: "US",
			City:    "New York",
			ASN:     12345,
		},
	}
	_ = engine.Dispatch(ctx, blockEvent)
	if sender.sentCount.Load() != 1 {
		t.Errorf("expected 1 alert for block action, got %d", sender.sentCount.Load())
	}
	if !strings.Contains(sender.lastMsg, "SQLI_RULE") || !strings.Contains(sender.lastMsg, "New York") {
		t.Errorf("expected rich incident context in alert, got:\n%s", sender.lastMsg)
	}

	_ = engine.Dispatch(ctx, blockEvent)
	if sender.sentCount.Load() != 1 {
		t.Errorf("expected duplicate alert to be suppressed, sentCount=%d", sender.sentCount.Load())
	}
}
