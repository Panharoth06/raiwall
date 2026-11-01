package api

import (
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/telemetry"
)

// eventEngines are the detection engines that stamp forensic events.
var eventEngines = map[string]bool{"semantic": true, "crs": true}

// parseEventQuery converts events-list query parameters into store criteria.
// Malformed values are rejected rather than ignored so a typo never silently
// widens the result set.
func parseEventQuery(q url.Values) (telemetry.QueryParams, error) {
	params := telemetry.QueryParams{
		ClientIP: q.Get("client_ip"),
		Action:   q.Get("action"),
		RuleID:   q.Get("rule_id"),
		Country:  q.Get("country"),
	}

	if sev := strings.TrimSpace(q.Get("min_severity")); sev != "" {
		if telemetry.SeveritiesAtLeast(sev) == nil {
			return params, fmt.Errorf("invalid min_severity %q: use info, low, medium, high or critical", sev)
		}
		params.MinSeverity = strings.ToLower(sev)
	}

	if engine := strings.TrimSpace(q.Get("engine")); engine != "" {
		engine = strings.ToLower(engine)
		if !eventEngines[engine] {
			return params, fmt.Errorf("invalid engine %q: use semantic or crs", engine)
		}
		params.Engine = engine
	}

	if raw := strings.TrimSpace(q.Get("min_score")); raw != "" {
		score, err := strconv.ParseFloat(raw, 64)
		if err != nil || math.IsNaN(score) || math.IsInf(score, 0) || score < 0 {
			return params, fmt.Errorf("invalid min_score %q: must be a non-negative number", raw)
		}
		params.MinAnomalyScore = &score
	}

	var err error
	if params.StartTime, err = parseQueryTime(q, "start_time"); err != nil {
		return params, err
	}
	if params.EndTime, err = parseQueryTime(q, "end_time"); err != nil {
		return params, err
	}
	if params.Limit, err = parseQueryInt(q, "limit"); err != nil {
		return params, err
	}
	if params.Offset, err = parseQueryInt(q, "offset"); err != nil {
		return params, err
	}
	return params, nil
}

func parseQueryTime(q url.Values, key string) (time.Time, error) {
	raw := strings.TrimSpace(q.Get(key))
	if raw == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid %s %q: must be RFC3339", key, raw)
	}
	return t, nil
}

func parseQueryInt(q url.Values, key string) (int, error) {
	raw := strings.TrimSpace(q.Get(key))
	if raw == "" {
		return 0, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("invalid %s %q: must be a non-negative integer", key, raw)
	}
	return v, nil
}
