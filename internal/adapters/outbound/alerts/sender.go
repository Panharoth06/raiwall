package alerts

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

// HTTPAlertSender sends alert webhooks to HTTP/S, Slack, Discord, and Telegram endpoints.
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
		postURL = "https://" + u.Host + u.Path
		payload = map[string]string{"text": message}

	case "discord":
		postURL = "https://" + u.Host + u.Path
		payload = map[string]string{"content": message}

	case "telegram":
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
