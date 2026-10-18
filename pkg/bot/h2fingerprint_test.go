package bot

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Panharoth06/raiwall/pkg/engine"
)

func TestHTTP2Fingerprint_ParseAndCompute(t *testing.T) {
	raw := "1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p"
	fp, err := ParseH2Fingerprint(raw)
	if err != nil {
		t.Fatalf("ParseH2Fingerprint failed: %v", err)
	}

	if len(fp.Settings) != 4 {
		t.Errorf("Settings count = %d, want 4", len(fp.Settings))
	}
	if fp.WindowUpdate != 15663105 {
		t.Errorf("WindowUpdate = %d, want 15663105", fp.WindowUpdate)
	}
	if len(fp.PseudoHeaderOrder) != 4 {
		t.Errorf("PseudoHeaderOrder count = %d, want 4", len(fp.PseudoHeaderOrder))
	}

	computed := ComputeH2Fingerprint(fp)
	if computed != raw {
		t.Errorf("ComputeH2Fingerprint() = %q, want %q", computed, raw)
	}

	hash := ComputeH2Hash(fp)
	if len(hash) != 32 {
		t.Errorf("ComputeH2Hash() length = %d, want 32", len(hash))
	}
}

func TestHTTP2Fingerprint_ContextAndHeaderExtraction(t *testing.T) {
	fp := &HTTP2Fingerprint{
		Settings:          []HTTP2Setting{{ID: 1, Value: 65536}},
		WindowUpdate:      65535,
		PseudoHeaderOrder: []string{"m", "a", "s", "p"},
	}

	// 1. Context extraction
	ctx := WithHTTP2Fingerprint(context.Background(), fp)
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil).WithContext(ctx)
	extracted := ExtractHTTP2Fingerprint(req)
	if extracted == nil || extracted.WindowUpdate != 65535 {
		t.Fatalf("Context extraction failed: %+v", extracted)
	}

	// 2. Header extraction
	req2 := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req2.Header.Set("X-HTTP2-Fingerprint", "1:65536|65535|0|m,a,s,p")
	extracted2 := ExtractHTTP2Fingerprint(req2)
	if extracted2 == nil || extracted2.WindowUpdate != 65535 {
		t.Fatalf("Header extraction failed: %+v", extracted2)
	}
}

func TestHTTP2Fingerprint_Correlation(t *testing.T) {
	classifier := NewBotClassifier()

	tests := []struct {
		name        string
		userAgent   string
		h2Raw       string
		wantSpoofed bool
		wantAction  engine.Action
	}{
		{
			name:        "Chrome with matching Chrome pseudo-headers (m,a,s,p)",
			userAgent:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
			h2Raw:       "1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p",
			wantSpoofed: false,
			wantAction:  engine.ActionAllow,
		},
		{
			name:        "Chrome claiming UA with Firefox pseudo-headers (m,p,a,s)",
			userAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
			h2Raw:       "1:65536,4:131072,5:16384|12517377|0|m,p,a,s",
			wantSpoofed: true,
			wantAction:  engine.ActionBlock,
		},
		{
			name:        "Firefox claiming UA with Chrome pseudo-headers (m,a,s,p)",
			userAgent:   "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
			h2Raw:       "1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p",
			wantSpoofed: true,
			wantAction:  engine.ActionBlock,
		},
		{
			name:        "Chrome claiming UA with Go net/http settings (2:0)",
			userAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
			h2Raw:       "2:0|1048576|0|m,a,s,p",
			wantSpoofed: true,
			wantAction:  engine.ActionBlock,
		},
		{
			name:        "Safari claiming UA with Chrome pseudo-headers (m,a,s,p)",
			userAgent:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
			h2Raw:       "1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p",
			wantSpoofed: true,
			wantAction:  engine.ActionBlock,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://example.com/search", nil)
			req.Header.Set("User-Agent", tt.userAgent)
			req.Header.Set("X-HTTP2-Fingerprint", tt.h2Raw)

			verdict := classifier.Classify(req, "")
			if verdict.IsSpoofed != tt.wantSpoofed {
				t.Errorf("IsSpoofed = %v, want %v (reason: %s)", verdict.IsSpoofed, tt.wantSpoofed, verdict.Reason)
			}
			if verdict.Action != tt.wantAction {
				t.Errorf("Action = %v, want %v", verdict.Action, tt.wantAction)
			}
		})
	}
}
