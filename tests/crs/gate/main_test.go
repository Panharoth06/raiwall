package main

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func writeReport(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}
	return path
}

func TestParseReportCountsApplicableResults(t *testing.T) {
	path := writeReport(t, `{
		"run": 6,
		"success": ["942100-1", "942100-2"],
		"failed": ["942100-3", "941100-1"],
		"skipped": ["920100-1", "920100-2"],
		"ignored": [],
		"forced-pass": [],
		"forced-fail": ["930100-1"]
	}`)

	result, err := parseReport(path, nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if result.passed != 2 || result.failed != 3 {
		t.Fatalf("got passed=%d failed=%d, want 2/3", result.passed, result.failed)
	}
	if len(result.failedIDs) != 3 || result.failedIDs[2] != "930100-1" {
		t.Fatalf("unexpected failed ids: %v", result.failedIDs)
	}
	if rate := result.passRate(); rate < 39.9 || rate > 40.1 {
		t.Fatalf("pass rate = %v, want 40", rate)
	}
}

func TestParseReportFiltersByIncludeIDs(t *testing.T) {
	path := writeReport(t, `{
		"run": 5,
		"success": ["942100-1", "920100-1"],
		"failed": ["942200-1", "920200-1"],
		"skipped": [],
		"forced-pass": [],
		"forced-fail": []
	}`)

	result, err := parseReport(path, regexp.MustCompile(`^94`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if result.passed != 1 || result.failed != 1 {
		t.Fatalf("got passed=%d failed=%d, want 1/1", result.passed, result.failed)
	}
	if len(result.failedIDs) != 1 || result.failedIDs[0] != "942200-1" {
		t.Fatalf("unexpected failed ids: %v", result.failedIDs)
	}
}

func TestParseReportIncludesForcedPass(t *testing.T) {
	path := writeReport(t, `{"run": 2, "success": ["x-1"], "failed": [], "forced-pass": ["x-2"], "forced-fail": []}`)
	result, err := parseReport(path, nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if result.passed != 2 || result.failed != 0 {
		t.Fatalf("got %+v, want 2 passed", result)
	}
}

func TestParseReportEmpty(t *testing.T) {
	path := writeReport(t, `{"run": 0, "success": [], "failed": [], "skipped": ["x-1"]}`)
	result, err := parseReport(path, nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if result.total() != 0 {
		t.Fatalf("expected no applicable results, got %+v", result)
	}
}

func TestParseReportRejectsGarbage(t *testing.T) {
	if _, err := parseReport(writeReport(t, "not json"), nil); err == nil {
		t.Fatal("expected an error for a non-JSON report")
	}
}
