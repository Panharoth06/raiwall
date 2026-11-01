package api

import (
	"net/url"
	"testing"
)

func TestParseEventQuery(t *testing.T) {
	t.Run("valid filters", func(t *testing.T) {
		q := url.Values{
			"engine":       {"CRS"},
			"min_score":    {"5.5"},
			"min_severity": {"High"},
			"limit":        {"10"},
			"offset":       {"20"},
			"start_time":   {"2026-10-01T00:00:00Z"},
		}
		p, err := parseEventQuery(q)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.Engine != "crs" || p.MinSeverity != "high" || p.Limit != 10 || p.Offset != 20 {
			t.Fatalf("unexpected params: %+v", p)
		}
		if p.MinAnomalyScore == nil || *p.MinAnomalyScore != 5.5 {
			t.Fatalf("expected min score 5.5, got %v", p.MinAnomalyScore)
		}
		if p.StartTime.IsZero() {
			t.Fatal("expected start time to be parsed")
		}
	})

	t.Run("no filters", func(t *testing.T) {
		p, err := parseEventQuery(url.Values{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.MinAnomalyScore != nil || p.Engine != "" {
			t.Fatalf("expected empty filters, got %+v", p)
		}
	})

	invalid := map[string]url.Values{
		"engine":     {"engine": {"modsec"}},
		"score text": {"min_score": {"abc"}},
		"score neg":  {"min_score": {"-1"}},
		"score nan":  {"min_score": {"NaN"}},
		"severity":   {"min_severity": {"severe"}},
		"start time": {"start_time": {"yesterday"}},
		"end time":   {"end_time": {"2026-10-01"}},
		"limit":      {"limit": {"ten"}},
		"offset neg": {"offset": {"-5"}},
	}
	for name, q := range invalid {
		t.Run("rejects "+name, func(t *testing.T) {
			if _, err := parseEventQuery(q); err == nil {
				t.Fatalf("expected error for %v", q)
			}
		})
	}
}
