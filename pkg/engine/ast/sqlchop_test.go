package ast

import (
	"context"
	"strings"
	"testing"
	"time"

)

func TestSQLChop_BenignInputs(t *testing.T) {
	chop := NewSQLChop()
	ctx := context.Background()

	benignInputs := []string{
		"",
		"12345",
		"john_doe",
		"john.doe@example.com",
		"Hello world, this is a normal search string",
		"category-sports",
		"2026-10-18T12:00:00Z",
		"order_by_date_asc",
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

func TestSQLChop_SQLiVectors(t *testing.T) {
	chop := NewSQLChop()
	ctx := context.Background()

	sqliVectors := []struct {
		name    string
		payload string
	}{
		{
			name:    "quoted boolean tautology single quote",
			payload: "' OR '1'='1",
		},
		{
			name:    "quoted union select",
			payload: "' UNION SELECT username, password FROM users --",
		},
		{
			name:    "comment truncation",
			payload: "admin' --",
		},
		{
			name:    "stacked query with drop",
			payload: "'; DROP TABLE users; --",
		},
		{
			name:    "unquoted boolean tautology",
			payload: "1 OR 1=1",
		},
		{
			name:    "unquoted union select",
			payload: "1 UNION SELECT 1, 2, 3",
		},
		{
			name:    "time-delay sleep function",
			payload: "1; SELECT SLEEP(5)",
		},
		{
			name:    "benchmark attack function",
			payload: "1 AND BENCHMARK(1000000,MD5('test'))",
		},
	}

	for _, tc := range sqliVectors {
		t.Run(tc.name, func(t *testing.T) {
			verdict, err := chop.Verify(ctx, tc.payload)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if verdict.Action != ActionBlock {
				t.Errorf("expected ActionBlock for payload %q, got %v", tc.payload, verdict.Action)
			}
			if verdict.RuleID != "SEMANTIC_SQLI" {
				t.Errorf("expected RuleID SEMANTIC_SQLI, got %q", verdict.RuleID)
			}
			if !strings.Contains(verdict.Reason, "SQL injection detected") {
				t.Errorf("expected Reason to mention SQL injection, got %q", verdict.Reason)
			}
		})
	}
}

func TestSQLChop_32KBCap(t *testing.T) {
	chop := NewSQLChop()
	ctx := context.Background()

	// Create payload larger than 32 KB (33 KB)
	largePayload := strings.Repeat("A", 33*1024) + "' OR '1'='1"

	verdict, err := chop.Verify(ctx, largePayload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Per spec: parameter > 32KB is skipped by AST verifier (rely on lexical triage), so AST returns ActionAllow
	if verdict.Action != ActionAllow {
		t.Errorf("expected ActionAllow (skip) for >32KB parameter, got %v", verdict.Action)
	}
}

func TestSQLChop_Timeout(t *testing.T) {
	// Create verifier with extremely tiny timeout (1 nanosecond)
	chop := &SQLChop{
		MaxParamSize: DefaultMaxParamSize,
		Timeout:      1 * time.Nanosecond,
	}

	// Give it an input that requires multiple token scans
	input := "SELECT * FROM super_long_table_name WHERE a = 1 AND b = 2 AND c = 3 AND d = 4 OR e = 5"
	verdict, err := chop.Verify(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it either allowed or timed out cleanly
	if verdict.Action == ActionAudit {
		if verdict.RuleID != "PARSER_TIMEOUT" {
			t.Errorf("expected RuleID PARSER_TIMEOUT, got %q", verdict.RuleID)
		}
	}
}
