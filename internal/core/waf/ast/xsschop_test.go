package ast

import (
	"context"
	"strings"
	"testing"
	"time"

)

func TestXSSChop_BenignInputs(t *testing.T) {
	chop := NewXSSChop()
	ctx := context.Background()

	benignInputs := []string{
		"",
		"Hello World",
		"12345",
		"user@example.com",
		"Search query for shoes & socks",
		"100% cotton - blue",
		"2026-10-18T12:00:00Z",
		"simple text with no tags",
	}

	for _, input := range benignInputs {
		t.Run("benign: "+input, func(t *testing.T) {
			verdict, err := chop.Verify(ctx, input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if verdict.Action != ActionAllow {
				t.Errorf("expected ActionAllow for benign input %q, got %v (%s)", input, verdict.Action, verdict.Reason)
			}
		})
	}
}

func TestXSSChop_XSSVectors(t *testing.T) {
	chop := NewXSSChop()
	ctx := context.Background()

	xssVectors := []struct {
		name    string
		payload string
	}{
		{
			name:    "script tag injection",
			payload: "><script>alert(1)</script>",
		},
		{
			name:    "attribute breakout with event handler",
			payload: "\" onerror=alert(1)",
		},
		{
			name:    "image tag with onerror handler",
			payload: "<img src=x onerror=alert(1)>",
		},
		{
			name:    "javascript pseudo-protocol",
			payload: "javascript:alert(1)",
		},
		{
			name:    "iframe injection",
			payload: "\"><iframe src=\"https://evil.com\"></iframe>",
		},
		{
			name:    "svg with onload handler",
			payload: "<svg onload=alert(document.domain)>",
		},
		{
			name:    "data:text/html pseudo-protocol",
			payload: "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
		},
	}

	for _, tc := range xssVectors {
		t.Run(tc.name, func(t *testing.T) {
			verdict, err := chop.Verify(ctx, tc.payload)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if verdict.Action != ActionBlock {
				t.Errorf("expected ActionBlock for payload %q, got %v", tc.payload, verdict.Action)
			}
			if verdict.RuleID != "SEMANTIC_XSS" {
				t.Errorf("expected RuleID SEMANTIC_XSS, got %q", verdict.RuleID)
			}
			if !strings.Contains(verdict.Reason, "Cross-site scripting detected") {
				t.Errorf("expected Reason to mention Cross-site scripting, got %q", verdict.Reason)
			}
		})
	}
}

func TestXSSChop_32KBCap(t *testing.T) {
	chop := NewXSSChop()
	ctx := context.Background()

	// Create payload larger than 32 KB (33 KB)
	largePayload := strings.Repeat("A", 33*1024) + "<script>alert(1)</script>"

	verdict, err := chop.Verify(ctx, largePayload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Exceeding 32KB is skipped by AST verifier (rely on lexical triage)
	if verdict.Action != ActionAllow {
		t.Errorf("expected ActionAllow (skip) for >32KB parameter, got %v", verdict.Action)
	}
}

func TestXSSChop_Timeout(t *testing.T) {
	chop := &XSSChop{
		MaxParamSize: DefaultMaxParamSize,
		Timeout:      1 * time.Nanosecond,
	}

	input := "<div><p>some complex html tree structure for parsing</p></div>"
	verdict, err := chop.Verify(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if verdict.Action == ActionAudit {
		if verdict.RuleID != "PARSER_TIMEOUT" {
			t.Errorf("expected RuleID PARSER_TIMEOUT, got %q", verdict.RuleID)
		}
	}
}
