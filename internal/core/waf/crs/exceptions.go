package crs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// exceptionRuleIDBase keeps synthetic exception rules clear of the CRS and
// setup ID ranges.
const exceptionRuleIDBase = 9_500_000

// Exception is a false-positive suppression translated into a Coraza ctl
// action. Host, path, and method conditions scope it to matching requests.
type Exception struct {
	Host       string
	PathPrefix string
	PathRegex  string
	Method     string
	Location   string
	ParamName  string
	RuleID     int
}

// Suppression is the ctl action an exception applies to a numeric CRS rule.
type Suppression struct {
	RuleID     int
	Collection string
	Key        string
}

// Directive renders the ctl action used in a SecRule.
func (s Suppression) Directive() string {
	if s.Key == "" {
		return fmt.Sprintf("ctl:ruleRemoveById=%d", s.RuleID)
	}
	return fmt.Sprintf("ctl:ruleRemoveTargetById=%d;%s:%s", s.RuleID, s.Collection, s.Key)
}

// SuppressionFor maps an exception's rule, location, and parameter onto a ctl
// action. Semantic rule IDs ("SEMANTIC_SQLI") and "*" have no CRS equivalent.
func SuppressionFor(ruleID, location, paramName string) (Suppression, bool) {
	id, ok := parseNumericRuleID(ruleID)
	if !ok {
		return Suppression{}, false
	}
	param := strings.TrimSpace(paramName)
	if param == "" || param == "*" {
		return Suppression{RuleID: id}, true
	}
	return Suppression{RuleID: id, Collection: collectionFor(location), Key: param}, true
}

func parseNumericRuleID(raw string) (int, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "*" {
		return 0, false
	}
	// Canonical IDs are "crs:942100" or "pack:<id>:10001"; accept a bare ID too.
	if idx := strings.LastIndexAny(trimmed, ":_"); idx >= 0 {
		trimmed = trimmed[idx+1:]
	}
	id, err := strconv.Atoi(trimmed)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

// collectionFor maps a location onto the Coraza collection CRS rules inspect.
// Query, body, JSON, and multipart parameters all land in ARGS so the removal
// matches rules that target ARGS; headers and cookies use their own sections.
func collectionFor(location string) string {
	switch strings.ToLower(strings.TrimSpace(location)) {
	case "header":
		return "REQUEST_HEADERS"
	case "cookie":
		return "REQUEST_COOKIES"
	default:
		return "ARGS"
	}
}

// validateExceptions rejects values that cannot be embedded safely in a
// SecRule directive, plus invalid path regexes.
func validateExceptions(exceptions []Exception) error {
	for i, exc := range exceptions {
		values := map[string]string{
			"host":        exc.Host,
			"path_prefix": exc.PathPrefix,
			"path_regex":  exc.PathRegex,
			"method":      exc.Method,
			"location":    exc.Location,
			"param_name":  exc.ParamName,
		}
		for name, value := range values {
			if strings.ContainsAny(value, "\"\r\n") {
				return fmt.Errorf("exception %d %s contains an unsupported character", i, name)
			}
		}
		if strings.ContainsAny(exc.ParamName, " \t;") {
			return fmt.Errorf("exception %d param_name contains an unsupported character", i)
		}
		if exc.RuleID <= 0 {
			return fmt.Errorf("exception %d has no numeric rule id", i)
		}
		if exc.PathRegex != "" {
			if _, err := regexp.Compile(exc.PathRegex); err != nil {
				return fmt.Errorf("exception %d path_regex: %w", i, err)
			}
		}
	}
	return nil
}

// exceptionDirectives renders one phase-1 rule (or chain) per exception. They
// are emitted before the CRS includes so the ctl action is in force when the
// detection rules run.
func exceptionDirectives(exceptions []Exception) string {
	if len(exceptions) == 0 {
		return ""
	}
	sorted := append([]Exception(nil), exceptions...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return exceptionSortKey(sorted[i]) < exceptionSortKey(sorted[j])
	})

	var b strings.Builder
	for i, exc := range sorted {
		id := exceptionRuleIDBase + i
		action := Suppression{RuleID: exc.RuleID}.Directive()
		if exc.ParamName != "" && exc.ParamName != "*" {
			action = Suppression{
				RuleID:     exc.RuleID,
				Collection: collectionFor(exc.Location),
				Key:        exc.ParamName,
			}.Directive()
		}

		conditions := exceptionConditions(exc)
		if len(conditions) == 0 {
			fmt.Fprintf(&b, "SecAction \"id:%d,phase:1,pass,nolog,%s\"\n", id, action)
			continue
		}
		for j, cond := range conditions {
			switch {
			case len(conditions) == 1:
				fmt.Fprintf(&b, "SecRule %s \"%s\" \"id:%d,phase:1,pass,nolog,%s\"\n",
					cond.variable, cond.operator, id, action)
			case j == 0:
				fmt.Fprintf(&b, "SecRule %s \"%s\" \"id:%d,phase:1,pass,nolog,chain\"\n",
					cond.variable, cond.operator, id)
			case j == len(conditions)-1:
				fmt.Fprintf(&b, "SecRule %s \"%s\" \"%s\"\n", cond.variable, cond.operator, action)
			default:
				fmt.Fprintf(&b, "SecRule %s \"%s\" \"chain\"\n", cond.variable, cond.operator)
			}
		}
	}
	return b.String()
}

type secCondition struct {
	variable string
	operator string
}

func exceptionConditions(exc Exception) []secCondition {
	var conditions []secCondition
	if host := strings.TrimSpace(exc.Host); host != "" && host != "*" {
		if strings.HasPrefix(host, "*.") {
			suffix := regexp.QuoteMeta(host[1:])
			conditions = append(conditions, secCondition{
				variable: "REQUEST_HEADERS:Host",
				operator: "@rx (?i)(^|" + suffix + ")(:[0-9]+)?$",
			})
		} else {
			conditions = append(conditions, secCondition{
				variable: "REQUEST_HEADERS:Host",
				operator: "@streq " + host,
			})
		}
	}
	if prefix := strings.TrimSpace(exc.PathPrefix); prefix != "" {
		conditions = append(conditions, secCondition{variable: "REQUEST_FILENAME", operator: "@beginsWith " + prefix})
	}
	if pattern := strings.TrimSpace(exc.PathRegex); pattern != "" {
		conditions = append(conditions, secCondition{variable: "REQUEST_FILENAME", operator: "@rx " + pattern})
	}
	if method := strings.TrimSpace(exc.Method); method != "" && method != "*" {
		conditions = append(conditions, secCondition{variable: "REQUEST_METHOD", operator: "@streq " + strings.ToUpper(method)})
	}
	return conditions
}

func exceptionSortKey(exc Exception) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%09d",
		exc.Host, exc.PathPrefix, exc.PathRegex, exc.Method, exc.Location, exc.ParamName, exc.RuleID)
}

// Fingerprint returns a stable hash of everything that affects the compiled
// ruleset and its enforcement. Per-app policy caches key on this value; the
// exception set is part of it, so a new exception recompiles the policy.
func (c Config) Fingerprint() string {
	c = normalizeConfig(c)
	h := sha256.New()
	h.Write([]byte(c.Mode))
	if c.Disabled {
		h.Write([]byte("disabled"))
	}
	h.Write([]byte(directives(c)))
	return hex.EncodeToString(h.Sum(nil))
}
