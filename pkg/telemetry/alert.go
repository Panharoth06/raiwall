package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AlertSender is the interface for transmitting alert messages to external destinations.
type AlertSender interface {
	Send(ctx context.Context, rawURL, message string) error
}

// AlertChannel defines a notification endpoint with event filtering and cooldown.
type AlertChannel struct {
	Name     string        `json:"name"`
	URL      string        `json:"url"`
	Events   []string      `json:"events"` // actions/severities to alert on (e.g. "block", "ban", "critical")
	Cooldown time.Duration `json:"cooldown"`
}

// Matches checks if the given ForensicEvent matches the channel's configured event triggers.
func (c *AlertChannel) Matches(event *ForensicEvent) bool {
	if len(c.Events) == 0 {
		return event.Action == "block" || event.Action == "ban" || event.Severity == "critical" || event.Severity == "high"
	}
	for _, ev := range c.Events {
		evLower := strings.ToLower(ev)
		if strings.EqualFold(event.Action, evLower) ||
			strings.EqualFold(event.Severity, evLower) ||
			strings.EqualFold(event.RuleID, evLower) {
			return true
		}
	}
	return false
}

// AlertEngine orchestrates sliding-window debounced incident notifications across channels.
type AlertEngine struct {
	channels  []AlertChannel
	debouncer *AlertDebouncer
	sender    AlertSender
}

// NewAlertEngine constructs an AlertEngine with configured channels and debouncer.
func NewAlertEngine(channels []AlertChannel, cooldown time.Duration, sender AlertSender) *AlertEngine {
	if sender == nil {
		sender = NewHTTPAlertSender(&http.Client{Timeout: 10 * time.Second})
	}
	return &AlertEngine{
		channels:  channels,
		debouncer: NewAlertDebouncer(cooldown),
		sender:    sender,
	}
}

// Dispatch processes an event, applies debouncing, and fans out formatted alerts to matching channels.
func (e *AlertEngine) Dispatch(ctx context.Context, event *ForensicEvent) error {
	if event == nil || len(e.channels) == 0 {
		return nil
	}

	shouldAlert, burstCount := e.debouncer.ShouldAlert(event)
	if !shouldAlert {
		return nil // Suppressed by debouncer
	}

	message := FormatAlert(event, burstCount)

	var lastErr error
	for _, ch := range e.channels {
		if ch.Matches(event) {
			if err := e.sender.Send(ctx, ch.URL, message); err != nil {
				lastErr = err
			}
		}
	}

	return lastErr
}

// FormatAlert renders a concise, human-readable notification for ChatOps channels.
func FormatAlert(event *ForensicEvent, burstCount int) string {
	var sb strings.Builder

	sb.WriteString("🚨 [RAIWALL WAF ALERT] Security Threat Detected\n")
	sb.WriteString(fmt.Sprintf("• Timestamp: %s\n", event.Timestamp.UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("• Action:    %s (Severity: %s)\n", strings.ToUpper(event.Action), event.Severity))
	if event.RuleID != "" {
		sb.WriteString(fmt.Sprintf("• Rule ID:   %s\n", event.RuleID))
	}
	geo := ""
	if event.GeoData.Country != "" {
		geo = fmt.Sprintf(" (%s", event.GeoData.Country)
		if event.GeoData.City != "" {
			geo += ", " + event.GeoData.City
		}
		if event.GeoData.ASN > 0 {
			geo += fmt.Sprintf(", AS%d", event.GeoData.ASN)
		}
		geo += ")"
	}
	sb.WriteString(fmt.Sprintf("• Client IP: %s%s\n", event.ClientIP, geo))
	sb.WriteString(fmt.Sprintf("• Request:   %s %s%s\n", event.Method, event.Host, event.Path))
	sb.WriteString(fmt.Sprintf("• Status:    %d\n", event.StatusCode))

	if burstCount > 0 {
		sb.WriteString(fmt.Sprintf("⚡ Note: %d duplicate attacks suppressed during cooldown window.\n", burstCount))
	}

	return sb.String()
}

// HTTPAlertSender sends alerts over HTTP/Webhook to Slack, Discord, Telegram, or generic webhooks.
type HTTPAlertSender struct {
	client *http.Client
}

// NewHTTPAlertSender creates a new HTTPAlertSender.
func NewHTTPAlertSender(client *http.Client) *HTTPAlertSender {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &HTTPAlertSender{client: client}
}

// Send parses notification URLs and dispatches standard JSON/Webhook payloads.
func (s *HTTPAlertSender) Send(ctx context.Context, rawURL, message string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse alert url: %w", err)
	}

	var postURL string
	var payload interface{}

	switch strings.ToLower(u.Scheme) {
	case "slack":
		// slack://hook.slack.com/services/XXX/YYY/ZZZ -> https://hooks.slack.com/services/XXX/YYY/ZZZ
		postURL = "https://" + u.Host + u.Path
		payload = map[string]string{"text": message}

	case "discord":
		// discord://discord.com/api/webhooks/XXX/YYY -> https://discord.com/api/webhooks/XXX/YYY
		postURL = "https://" + u.Host + u.Path
		payload = map[string]string{"content": message}

	case "telegram":
		// telegram://botToken@telegram?chat_id=12345 or telegram://12345:ABC-DEF@telegram
		token := u.User.Username()
		if pass, ok := u.User.Password(); ok {
			token = token + ":" + pass
		}
		chatID := u.Query().Get("chat_id")
		if chatID == "" {
			chatID = u.Query().Get("chats")
		}
		postURL = fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
		payload = map[string]string{
			"chat_id": chatID,
			"text":    message,
		}

	case "http", "https":
		postURL = rawURL
		payload = map[string]string{"text": message, "content": message}

	default:
		// Generic webhook
		cleanURL := strings.TrimPrefix(rawURL, u.Scheme+"://")
		postURL = "https://" + cleanURL
		payload = map[string]string{"text": message}
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal alert payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, postURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("create alert request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send alert to %s: %w", postURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("alert endpoint returned HTTP %d", resp.StatusCode)
	}

	return nil
}
