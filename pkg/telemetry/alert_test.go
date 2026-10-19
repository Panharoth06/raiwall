package telemetry

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
	debouncer := NewAlertDebouncer(100 * time.Millisecond)

	event := &ForensicEvent{
		ClientIP: "1.2.3.4",
		RuleID:   "SQLI_RULE",
	}

	// 1st occurrence -> should alert
	should, burst := debouncer.ShouldAlert(event)
	if !should || burst != 0 {
		t.Fatalf("expected first event to alert, got should=%v burst=%d", should, burst)
	}

	// 2nd occurrence immediately -> should suppress
	should, burst = debouncer.ShouldAlert(event)
	if should || burst != 1 {
		t.Fatalf("expected second event to be suppressed, got should=%v burst=%d", should, burst)
	}

	// 3rd occurrence immediately -> should suppress
	should, burst = debouncer.ShouldAlert(event)
	if should || burst != 2 {
		t.Fatalf("expected third event to be suppressed, got should=%v burst=%d", should, burst)
	}

	// Wait for cooldown to expire
	time.Sleep(120 * time.Millisecond)

	// 4th occurrence -> should alert and report 2 suppressed burst events
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

	// 1. "allow" event -> should NOT match channel triggers
	allowEvent := &ForensicEvent{
		EventID:  "evt-allow",
		ClientIP: "10.0.0.1",
		Action:   "allow",
		Severity: "info",
	}
	_ = engine.Dispatch(ctx, allowEvent)
	if sender.sentCount.Load() != 0 {
		t.Errorf("expected 0 alerts for allow action, got %d", sender.sentCount.Load())
	}

	// 2. "block" event -> should match and dispatch
	blockEvent := &ForensicEvent{
		EventID:   "evt-block",
		ClientIP:  "10.0.0.1",
		Host:      "api.example.com",
		Path:      "/admin",
		Method:    "GET",
		Action:    "block",
		Severity:  "high",
		RuleID:    "SQLI_RULE",
		Timestamp: time.Now(),
		GeoData: GeoData{
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

	// 3. Duplicate block event during cooldown -> debounced
	_ = engine.Dispatch(ctx, blockEvent)
	if sender.sentCount.Load() != 1 {
		t.Errorf("expected duplicate alert to be suppressed, sentCount=%d", sender.sentCount.Load())
	}
}

func TestHTTPAlertSender_URLParsing(t *testing.T) {
	var targetURL string
	mockClient := &http.Client{
		Transport: mockRoundTripper(func(r *http.Request) (*http.Response, error) {
			targetURL = r.URL.String()
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewBufferString("ok")),
			}, nil
		}),
	}

	sender := NewHTTPAlertSender(mockClient)
	ctx := context.Background()

	// Slack
	_ = sender.Send(ctx, "slack://hooks.slack.com/services/T00/B00/X00", "test message")
	if !strings.HasPrefix(targetURL, "https://hooks.slack.com") {
		t.Errorf("expected slack target URL, got %s", targetURL)
	}

	// Telegram
	_ = sender.Send(ctx, "telegram://123456:ABC-DEF@telegram?chat_id=987654", "test message")
	if !strings.Contains(targetURL, "api.telegram.org/bot123456:ABC-DEF/sendMessage") {
		t.Errorf("expected telegram bot URL, got %s", targetURL)
	}

	// Discord
	_ = sender.Send(ctx, "discord://discord.com/api/webhooks/123/xyz", "test message")
	if !strings.HasPrefix(targetURL, "https://discord.com/api/webhooks/123/xyz") {
		t.Errorf("expected discord target URL, got %s", targetURL)
	}
}
