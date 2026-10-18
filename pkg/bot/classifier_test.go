package bot

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Panharoth06/raiwall/pkg/engine"
)

func TestBotClassifier(t *testing.T) {
	classifier := NewBotClassifier()

	tests := []struct {
		name         string
		userAgent    string
		ja4          string
		host         string
		wantIsBot    bool
		wantSpoofed  bool
		wantCategory BotCategory
		wantAction   engine.Action
		wantStatus   int
	}{
		{
			name:         "Legitimate Chrome Browser",
			userAgent:    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
			ja4:          "t13d1516h2_normal_chrome_hash",
			host:         "example.com",
			wantIsBot:    false,
			wantSpoofed:  false,
			wantCategory: BotCategoryBrowser,
			wantAction:   engine.ActionAllow,
			wantStatus:   0,
		},
		{
			name:         "Known cURL Tool UA",
			userAgent:    "curl/8.4.0",
			ja4:          "",
			host:         "example.com",
			wantIsBot:    true,
			wantSpoofed:  false,
			wantCategory: BotCategoryCLI,
			wantAction:   engine.ActionAllow,
			wantStatus:   0,
		},
		{
			name:         "Known sqlmap Scanner",
			userAgent:    "sqlmap/1.7#dev (http://sqlmap.org)",
			ja4:          "",
			host:         "example.com",
			wantIsBot:    true,
			wantSpoofed:  false,
			wantCategory: BotCategoryScanner,
			wantAction:   engine.ActionBlock,
			wantStatus:   http.StatusForbidden,
		},
		{
			name:         "cURL JA4 spoofing Chrome UA",
			userAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
			ja4:          "t13d1516h2_curl_default",
			host:         "example.com",
			wantIsBot:    true,
			wantSpoofed:  true,
			wantCategory: BotCategoryCLI,
			wantAction:   engine.ActionBlock,
			wantStatus:   http.StatusForbidden,
		},
		{
			name:         "Python Requests JA4 spoofing Firefox UA",
			userAgent:    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
			ja4:          "t13d1516h2_8daaf6152771_0100742d1fc0",
			host:         "example.com",
			wantIsBot:    true,
			wantSpoofed:  true,
			wantCategory: BotCategoryLibrary,
			wantAction:   engine.ActionBlock,
			wantStatus:   http.StatusForbidden,
		},
		{
			name:         "Browser UA with ALPN 00 anomaly (spoofed)",
			userAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
			ja4:          "t13d151600_unknown_hash",
			host:         "example.com",
			wantIsBot:    true,
			wantSpoofed:  true,
			wantCategory: BotCategoryLibrary,
			wantAction:   engine.ActionBlock,
			wantStatus:   http.StatusForbidden,
		},
		{
			name:         "Browser UA with missing SNI (sni='i') for domain host (spoofed)",
			userAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
			ja4:          "t13i1516h2_unknown_hash",
			host:         "example.com",
			wantIsBot:    true,
			wantSpoofed:  true,
			wantCategory: BotCategoryLibrary,
			wantAction:   engine.ActionBlock,
			wantStatus:   http.StatusForbidden,
		},
		{
			name:         "Empty User-Agent",
			userAgent:    "",
			ja4:          "",
			host:         "example.com",
			wantIsBot:    true,
			wantSpoofed:  false,
			wantCategory: BotCategoryUnknown,
			wantAction:   engine.ActionAllow,
			wantStatus:   0,
		},
		{
			name:         "Browser UA connecting to IPv6 address without SNI (not spoofed)",
			userAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
			ja4:          "t13i1516h2_some_hash",
			host:         "[2001:db8::1]",
			wantIsBot:    false,
			wantSpoofed:  false,
			wantCategory: BotCategoryBrowser,
			wantAction:   engine.ActionAllow,
			wantStatus:   0,
		},
		{
			name:         "cURL JA4 spoofing lowercase chrome UA",
			userAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/124.0.0.0 safari/537.36",
			ja4:          "t13d1516h2_curl_default",
			host:         "example.com",
			wantIsBot:    true,
			wantSpoofed:  true,
			wantCategory: BotCategoryCLI,
			wantAction:   engine.ActionBlock,
			wantStatus:   http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://"+tt.host+"/test", nil)
			req.Host = tt.host
			if tt.userAgent != "" {
				req.Header.Set("User-Agent", tt.userAgent)
			} else {
				req.Header.Del("User-Agent")
			}

			verdict := classifier.Classify(req, tt.ja4)
			if verdict.IsBot != tt.wantIsBot {
				t.Errorf("IsBot = %v, want %v", verdict.IsBot, tt.wantIsBot)
			}
			if verdict.IsSpoofed != tt.wantSpoofed {
				t.Errorf("IsSpoofed = %v, want %v", verdict.IsSpoofed, tt.wantSpoofed)
			}
			if verdict.BotCategory != tt.wantCategory {
				t.Errorf("BotCategory = %v, want %v", verdict.BotCategory, tt.wantCategory)
			}
			if verdict.Action != tt.wantAction {
				t.Errorf("Action = %v, want %v", verdict.Action, tt.wantAction)
			}
			if verdict.StatusCode != tt.wantStatus {
				t.Errorf("StatusCode = %v, want %v", verdict.StatusCode, tt.wantStatus)
			}
		})
	}
}

func TestCustomSignatures(t *testing.T) {
	customJA4 := "t13d9999h2_custom_tool_hash"
	classifier := NewBotClassifier(
		WithCustomSignature(customJA4, KnownSignature{
			ToolName:    "evil-bot",
			BotCategory: BotCategoryScanner,
			Description: "Custom Evil Bot",
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	verdict := classifier.Classify(req, customJA4)
	if !verdict.IsBot || verdict.ToolName != "evil-bot" || verdict.Action != engine.ActionBlock {
		t.Fatalf("Custom signature failed: %+v", verdict)
	}
}
