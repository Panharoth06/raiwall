// Command gate enforces the CRS parity thresholds from a go-ftw JSON report.
//
// go-ftw -o json prints one summary object:
//
//	{"run": 10, "success": ["942100-1"], "failed": ["942100-2"], "skipped": [...]}
//
// Skipped tests are not applicable and are excluded from the pass rate. An
// optional --include-ids regex restricts both lists to a family so one report
// can feed both the overall and the critical-family gates. A report with no
// applicable results is a failure so a crashed run cannot pass silently.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
)

type report struct {
	Run        int      `json:"run"`
	Success    []string `json:"success"`
	Failed     []string `json:"failed"`
	Skipped    []string `json:"skipped"`
	Ignored    []string `json:"ignored"`
	ForcedPass []string `json:"forced-pass"`
	ForcedFail []string `json:"forced-fail"`
}

type stats struct {
	passed    int
	failed    int
	failedIDs []string
}

func (s stats) total() int { return s.passed + s.failed }

func (s stats) passRate() float64 {
	if s.total() == 0 {
		return 0
	}
	return float64(s.passed) * 100 / float64(s.total())
}

func parseReport(path string, include *regexp.Regexp) (stats, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return stats{}, fmt.Errorf("read report: %w", err)
	}

	var result report
	if err := json.Unmarshal(data, &result); err != nil {
		return stats{}, fmt.Errorf("parse report JSON: %w", err)
	}

	filter := func(ids []string) []string {
		if include == nil {
			return ids
		}
		kept := make([]string, 0, len(ids))
		for _, id := range ids {
			if include.MatchString(id) {
				kept = append(kept, id)
			}
		}
		return kept
	}

	passed := append(filter(result.Success), filter(result.ForcedPass)...)
	failedIDs := append(filter(result.Failed), filter(result.ForcedFail)...)
	return stats{passed: len(passed), failed: len(failedIDs), failedIDs: failedIDs}, nil
}

func main() {
	reportPath := flag.String("report", "", "go-ftw JSON report file")
	minOverall := flag.Float64("min-overall", 95, "minimum overall pass percentage")
	requireZeroFailures := flag.Bool("require-zero-failures", false, "fail if any test fails")
	includeIDs := flag.String("include-ids", "", "only count test IDs matching this Go regex")
	label := flag.String("label", "CRS parity", "name printed in the summary")
	flag.Parse()

	if *reportPath == "" {
		fmt.Fprintln(os.Stderr, "gate: --report is required")
		os.Exit(2)
	}

	var include *regexp.Regexp
	if *includeIDs != "" {
		compiled, err := regexp.Compile(*includeIDs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gate: invalid --include-ids: %v\n", err)
			os.Exit(2)
		}
		include = compiled
	}

	result, err := parseReport(*reportPath, include)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gate: %v\n", err)
		os.Exit(2)
	}
	if result.total() == 0 {
		fmt.Fprintf(os.Stderr, "gate: no applicable results parsed from %s\n", *reportPath)
		os.Exit(1)
	}

	fmt.Printf("%s: %d passed, %d failed (%.1f%%, threshold %.1f%%)\n",
		*label, result.passed, result.failed, result.passRate(), *minOverall)

	failed := false
	if result.passRate() < *minOverall {
		fmt.Printf("%s: overall pass rate below threshold\n", *label)
		failed = true
	}
	if *requireZeroFailures && result.failed > 0 {
		fmt.Printf("%s: %d failing tests (zero tolerated)\n", *label, result.failed)
		failed = true
	}
	if failed && len(result.failedIDs) > 0 {
		limit := min(len(result.failedIDs), 40)
		fmt.Printf("failed tests (first %d): %v\n", limit, result.failedIDs[:limit])
	}
	if failed {
		os.Exit(1)
	}
}
