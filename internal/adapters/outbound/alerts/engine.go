package alerts

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/telemetry"
)

// AlertChannel defines a notification endpoint with event filtering and cooldown.
type AlertChannel struct {
	Name     string        `json:"name"`
	URL      string        `json:"url"`
	Events   []string      `json:"events"`
	Cooldown time.Duration `json:"cooldown"`
}

// Matches checks if the given ForensicEvent matches the channel's configured event triggers.
func (c *AlertChannel) Matches(event *telemetry.ForensicEvent) bool {
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
	debouncer *telemetry.AlertDebouncer
	sender    AlertSender
}

// NewAlertEngine constructs an AlertEngine with configured channels and debouncer.
func NewAlertEngine(channels []AlertChannel, cooldown time.Duration, sender AlertSender) *AlertEngine {
	if sender == nil {
		sender = NewHTTPAlertSender(&http.Client{Timeout: 10 * time.Second})
	}
	return &AlertEngine{
		channels:  channels,
		debouncer: telemetry.NewAlertDebouncer(cooldown),
		sender:    sender,
	}
}

// Dispatch processes an event, applies debouncing, and fans out formatted alerts to matching channels.
func (e *AlertEngine) Dispatch(ctx context.Context, event *telemetry.ForensicEvent) error {
	if event == nil || len(e.channels) == 0 {
		return nil
	}

	shouldAlert, burstCount := e.debouncer.ShouldAlert(event)
	if !shouldAlert {
		return nil
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
func FormatAlert(event *telemetry.ForensicEvent, burstCount int) string {
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
	if event.JA4 != "" {
		sb.WriteString(fmt.Sprintf("• JA4:       %s\n", event.JA4))
	}
	sb.WriteString(fmt.Sprintf("• Request:   %s %s%s\n", event.Method, event.Host, event.Path))
	if event.MatchedToken != "" {
		sb.WriteString(fmt.Sprintf("• Matched:   %s in %s\n", event.MatchedToken, event.PayloadLocation))
	}
	if burstCount > 0 {
		sb.WriteString(fmt.Sprintf("⚡ [%d duplicate events suppressed during cooldown]\n", burstCount))
	}

	return sb.String()
}
