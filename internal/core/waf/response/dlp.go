package response

import (
	"bytes"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/waf"
)

// Mode selects how DLP findings affect the response.
type Mode string

const (
	ModeAudit  Mode = "audit"
	ModeRedact Mode = "redact"
	ModeBlock  Mode = "block"
)

// Config controls outbound inspection. BodyLimit is the number of bytes
// scanned; HardCap is the maximum number buffered before inspection is
// abandoned and the response is streamed.
type Config struct {
	Enabled          bool
	Mode             string
	InspectHeaders   bool
	InspectBody      bool
	BodyLimit        int
	HardCap          int
	Decompress       bool
	ContentTypes     []string
	MaxInflightBytes int64
	DLP              DLPConfig
}

// DLPConfig controls the outbound data-loss-prevention detectors.
type DLPConfig struct {
	Enabled           bool
	Action            string
	DetectPAN         bool
	DetectSecrets     bool
	DetectJWT         bool
	DetectPrivateKeys bool
	Redaction         string
	MaxScanBytes      int
}

// Finding is one sanitized DLP hit. The matched secret is intentionally not
// stored here so telemetry can never leak it.
type Finding struct {
	RuleID   string
	Category string
	Location string
	Severity string
}

// Result is the outcome of inspecting one response.
type Result struct {
	Verdict  *waf.Verdict
	Findings []Finding
	Body     []byte
	Redacted bool
	Truncated bool
}

type redactSpan struct {
	start int
	end   int
}

type detector struct {
	ruleID      string
	category    string
	severity    string
	pattern     *regexp.Regexp
	group       int
	body        bool
	headerNames map[string]struct{}
	fastFilter  func([]byte) bool
	validate    func([]byte) bool
	scan        func(scan []byte, maxMatches int) [][]int
}

// Engine is an immutable compiled DLP ruleset. Deploys compile a new engine
// and swap the pointer, so no request observes a partial ruleset.
type Engine struct {
	cfg       Config
	detectors []detector
}

// New compiles the configured detectors.
func New(cfg Config) (*Engine, error) {
	cfg = normalizeConfig(cfg)
	engine := &Engine{cfg: cfg}
	if !cfg.Enabled || !cfg.DLP.Enabled {
		return engine, nil
	}
	if cfg.DLP.DetectPAN {
		engine.detectors = append(engine.detectors, detector{
			ruleID:     "dlp_pan",
			category:   "payment-card",
			severity:   "high",
			pattern:    panPattern,
			body:       true,
			fastFilter: func(b []byte) bool { return bytes.IndexAny(b, "0123456789") != -1 },
			validate:   validPAN,
			scan:       scanPAN,
		})
	}
	if cfg.DLP.DetectJWT {
		engine.detectors = append(engine.detectors, detector{
			ruleID:     "dlp_jwt",
			category:   "jwt",
			severity:   "high",
			pattern:    regexp.MustCompile(`eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b`),
			body:       true,
			fastFilter: func(b []byte) bool { return bytes.Contains(b, []byte("eyJ")) },
			validate:   func([]byte) bool { return true },
		})
	}
	if cfg.DLP.DetectPrivateKeys {
		engine.detectors = append(engine.detectors, detector{
			ruleID:     "dlp_private_key",
			category:   "private-key",
			severity:   "critical",
			pattern:    regexp.MustCompile(`(?s)-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----.*?(?:-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----|$)`),
			body:       true,
			fastFilter: func(b []byte) bool { return bytes.Contains(b, []byte("-----BEGIN")) },
			validate:   func([]byte) bool { return true },
		})
	}
	if cfg.DLP.DetectSecrets {
		engine.detectors = append(engine.detectors,
			detector{
				ruleID:     "dlp_cloud_key",
				category:   "cloud-access-key",
				severity:   "high",
				pattern:    regexp.MustCompile(`(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
				body:       true,
				fastFilter: func(b []byte) bool { return bytes.Contains(b, []byte("AKIA")) || bytes.Contains(b, []byte("ASIA")) },
				validate:   func([]byte) bool { return true },
			},
			detector{
				ruleID:     "dlp_secret",
				category:   "secret",
				severity:   "medium",
				pattern:    secretWindowPattern,
				group:      1,
				body:       true,
				fastFilter: hasSecretKeyword,
				validate:   func([]byte) bool { return true },
				scan:       scanSecrets,
			},
			detector{
				ruleID:      "dlp_auth_header",
				category:    "authorization-header",
				severity:    "high",
				pattern:     regexp.MustCompile(`(?i)^(?:bearer|basic)\s+\S{8,}$`),
				headerNames: headerSet("Authorization", "Proxy-Authorization", "X-Api-Key", "X-Auth-Token"),
				validate:    func([]byte) bool { return true },
			},
		)
	}
	return engine, nil
}

// Name returns the engine identifier.
func (e *Engine) Name() string { return "dlp" }

// Config returns the normalized configuration.
func (e *Engine) Config() Config { return e.cfg }

// Inspect evaluates response headers and body. It never returns a raw secret
// in the verdict; matched values stay in the process.
func (e *Engine) Inspect(ctx *waf.ResponseContext) *Result {
	result := &Result{Verdict: waf.VerdictAllow}
	if e == nil || e.cfg.Disabled() || ctx == nil {
		return result
	}

	action := e.action()
	var findings []Finding
	if e.cfg.InspectHeaders {
		findings = append(findings, e.scanHeaders(ctx.Headers)...)
	}
	if e.cfg.InspectBody && len(ctx.Body) > 0 {
		needRedact := (action == ModeRedact)
		bodyFindings, redacted, truncated := e.scanBody(ctx.Body, needRedact)
		findings = append(findings, bodyFindings...)
		result.Truncated = truncated
		if needRedact && redacted != nil {
			result.Body = redacted
			result.Redacted = true
		}
	}
	if len(findings) == 0 {
		return result
	}
	result.Findings = findings
	result.Verdict = e.verdict(findings, action)
	return result
}

func (e *Engine) action() Mode {
	action := strings.ToLower(strings.TrimSpace(e.cfg.DLP.Action))
	switch action {
	case string(ModeBlock):
		return ModeBlock
	case string(ModeRedact):
		return ModeRedact
	case string(ModeAudit):
		return ModeAudit
	}
	switch strings.ToLower(strings.TrimSpace(e.cfg.Mode)) {
	case string(ModeBlock):
		return ModeBlock
	case string(ModeRedact):
		return ModeRedact
	default:
		return ModeAudit
	}
}

func (e *Engine) verdict(findings []Finding, action Mode) *waf.Verdict {
	first := findings[0]
	v := &waf.Verdict{
		Action:          waf.ActionAudit,
		RuleID:          first.RuleID,
		Reason:          fmt.Sprintf("DLP detected %s in %s", first.Category, first.Location),
		AttackCategory:  "dlp",
		Engine:          "dlp",
		Severity:        first.Severity,
		PayloadLocation: first.Location,
		MatchedToken:    first.Category,
	}
	if action == ModeBlock {
		v.Action = waf.ActionBlock
		v.StatusCode = http.StatusForbidden
	}
	seen := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		if _, ok := seen[finding.RuleID]; ok {
			continue
		}
		seen[finding.RuleID] = struct{}{}
		v.MatchedRules = append(v.MatchedRules, waf.RuleMatch{
			RuleID:   finding.RuleID,
			Message:  "Outbound DLP: " + finding.Category,
			Severity: finding.Severity,
			Engine:   "dlp",
		})
	}
	return v
}

func (e *Engine) scanHeaders(headers http.Header) []Finding {
	if headers == nil {
		return nil
	}
	var findings []Finding
	for name, values := range headers {
		for _, value := range values {
			valBytes := []byte(value)
			for _, det := range e.detectors {
				if det.headerNames == nil {
					continue
				}
				if _, ok := det.headerNames[strings.ToLower(name)]; !ok {
					continue
				}
				match := det.pattern.Find(valBytes)
				if match == nil || !det.validate(match) {
					continue
				}
				findings = append(findings, Finding{
					RuleID:   det.ruleID,
					Category: det.category,
					Location: "ResponseHeader:" + name,
					Severity: det.severity,
				})
			}
		}
	}
	return findings
}

func (e *Engine) scanBody(body []byte, needRedact bool) ([]Finding, []byte, bool) {
	limit := e.cfg.DLP.MaxScanBytes
	if limit <= 0 {
		limit = 1024 * 1024
	}
	scan := body
	truncated := false
	if len(scan) > limit {
		scan = scan[:limit]
		truncated = true
	}
	var findings []Finding
	var spans []redactSpan
	deadline := time.Now().Add(25 * time.Millisecond)
	for _, det := range e.detectors {
		if !det.body {
			continue
		}
		if det.fastFilter != nil && !det.fastFilter(scan) {
			continue
		}
		if time.Now().After(deadline) {
			truncated = true
			break
		}
		var submatches [][]int
		if det.scan != nil {
			submatches = det.scan(scan, 64)
		} else {
			submatches = det.pattern.FindAllSubmatchIndex(scan, 64)
		}
		for _, idx := range submatches {
			if idx == nil {
				continue
			}
			start, end := idx[0], idx[1]
			if start > 0 && isWordChar(scan[start-1]) {
				continue
			}
			if det.group > 0 && len(idx) > det.group*2+1 {
				start, end = idx[det.group*2], idx[det.group*2+1]
			}
			if start < 0 || end <= start {
				continue
			}
			token := scan[start:end]
			if !det.validate(token) {
				continue
			}
			findings = append(findings, Finding{
				RuleID:   det.ruleID,
				Category: det.category,
				Location: "ResponseBody",
				Severity: det.severity,
			})
			if needRedact {
				spans = append(spans, redactSpan{start: start, end: end})
			}
		}
	}
	if !needRedact || len(spans) == 0 {
		return findings, nil, truncated
	}
	redacted := redactSpans(body, spans, e.redaction())
	return findings, redacted, truncated
}

func (e *Engine) redaction() string {
	if mask := strings.TrimSpace(e.cfg.DLP.Redaction); mask != "" {
		return mask
	}
	return "[REDACTED]"
}

func redactSpans(body []byte, spans []redactSpan, mask string) []byte {
	if len(spans) == 0 {
		return body
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start == spans[j].start {
			return spans[i].end > spans[j].end
		}
		return spans[i].start < spans[j].start
	})
	replacement := []byte(mask)
	var out bytes.Buffer
	out.Grow(len(body))
	last := 0
	for _, s := range spans {
		if s.start < last || s.start >= len(body) || s.end > len(body) || s.end <= s.start {
			continue
		}
		out.Write(body[last:s.start])
		out.Write(replacement)
		last = s.end
	}
	if last < len(body) {
		out.Write(body[last:])
	}
	return out.Bytes()
}

func hasSecretKeyword(b []byte) bool {
	return bytes.Contains(b, []byte("key")) || bytes.Contains(b, []byte("KEY")) ||
		bytes.Contains(b, []byte("Key")) || bytes.Contains(b, []byte("secret")) ||
		bytes.Contains(b, []byte("SECRET")) || bytes.Contains(b, []byte("Secret")) ||
		bytes.Contains(b, []byte("token")) || bytes.Contains(b, []byte("TOKEN")) ||
		bytes.Contains(b, []byte("Token")) || bytes.Contains(b, []byte("pass")) ||
		bytes.Contains(b, []byte("PASS")) || bytes.Contains(b, []byte("Pass"))
}

func isWordChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

var secretKeywords = [][]byte{
	[]byte("api_key"),
	[]byte("apikey"),
	[]byte("api-key"),
	[]byte("client_secret"),
	[]byte("client-secret"),
	[]byte("clientsecret"),
	[]byte("secret"),
	[]byte("token"),
	[]byte("password"),
	[]byte("passwd"),
}

var secretWindowPattern = regexp.MustCompile(`^(?i)(?:api[_-]?key|secret|token|password|passwd|client[_-]?secret)["']?\s*[:=]\s*["']?([A-Za-z0-9_\-./+=]{12,512})["']?`)

func scanSecrets(scan []byte, maxMatches int) [][]int {
	if len(scan) == 0 {
		return nil
	}
	lower := bytes.ToLower(scan)
	var matches [][]int
	seenHits := make(map[int]struct{})
	for _, kw := range secretKeywords {
		pos := 0
		for pos < len(lower) {
			idx := bytes.Index(lower[pos:], kw)
			if idx == -1 {
				break
			}
			hit := pos + idx
			pos = hit + len(kw)
			if hit > 0 && isWordChar(scan[hit-1]) {
				continue
			}
			if _, seen := seenHits[hit]; seen {
				continue
			}
			seenHits[hit] = struct{}{}
			endWin := hit + 600
			if endWin > len(scan) {
				endWin = len(scan)
			}
			sub := secretWindowPattern.FindSubmatchIndex(scan[hit:endWin])
			if sub != nil {
				translated := make([]int, len(sub))
				for i := range sub {
					if sub[i] >= 0 {
						translated[i] = sub[i] + hit
					} else {
						translated[i] = -1
					}
				}
				matches = append(matches, translated)
				if len(matches) >= maxMatches {
					return matches
				}
			}
		}
	}
	return matches
}

var panPattern = regexp.MustCompile(`^(?:\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,7}|\d{4}[ -]?\d{6}[ -]?\d{5}|\d{13,19})$`)

func scanPAN(scan []byte, maxMatches int) [][]int {
	if len(scan) < 13 {
		return nil
	}
	var matches [][]int
	n := len(scan)
	i := 0
	for i < n {
		if scan[i] < '0' || scan[i] > '9' {
			i++
			continue
		}
		if i > 0 && isWordChar(scan[i-1]) {
			for i < n && isWordChar(scan[i]) {
				i++
			}
			continue
		}
		start := i
		digits := 0
		invalid := false
		for i < n {
			c := scan[i]
			if c >= '0' && c <= '9' {
				digits++
				i++
			} else if c == ' ' || c == '-' {
				if i+1 < n && scan[i+1] >= '0' && scan[i+1] <= '9' {
					i++
				} else {
					break
				}
			} else if isWordChar(c) {
				invalid = true
				for i < n && isWordChar(scan[i]) {
					i++
				}
				break
			} else {
				break
			}
		}
		if invalid {
			continue
		}
		end := i
		if digits >= 13 && digits <= 19 && (end-start) >= 13 && (end-start) <= 30 {
			candidate := scan[start:end]
			if panPattern.Match(candidate) {
				matches = append(matches, []int{start, end})
				if len(matches) >= maxMatches {
					return matches
				}
			}
		}
	}
	return matches
}

func (c Config) Disabled() bool {
	return !c.Enabled || !c.DLP.Enabled
}

func normalizeConfig(cfg Config) Config {
	if cfg.BodyLimit <= 0 {
		cfg.BodyLimit = 1024 * 1024
	}
	if cfg.HardCap <= 0 {
		cfg.HardCap = 8 * 1024 * 1024
	}
	if cfg.HardCap < cfg.BodyLimit {
		cfg.HardCap = cfg.BodyLimit
	}
	if cfg.DLP.MaxScanBytes <= 0 || cfg.DLP.MaxScanBytes > cfg.BodyLimit {
		cfg.DLP.MaxScanBytes = cfg.BodyLimit
	}
	if len(cfg.ContentTypes) == 0 {
		cfg.ContentTypes = []string{
			"text/html", "text/plain", "text/xml", "application/xml",
			"application/json", "application/javascript", "text/javascript",
		}
	}
	return cfg
}

// Fingerprint identifies a compiled engine for cache sharing.
func (c Config) Fingerprint() string {
	c = normalizeConfig(c)
	return fmt.Sprintf("%t|%s|%t|%t|%d|%d|%t|%s|%t|%s|%t|%t|%t|%s|%d",
		c.Enabled, c.Mode, c.InspectHeaders, c.InspectBody, c.BodyLimit, c.HardCap,
		c.Decompress, strings.Join(c.ContentTypes, ","),
		c.DLP.DetectPAN, c.DLP.Action,
		c.DLP.DetectSecrets, c.DLP.DetectJWT, c.DLP.DetectPrivateKeys,
		c.DLP.Redaction, c.DLP.MaxScanBytes)
}

func headerSet(names ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(names))
	for _, name := range names {
		out[strings.ToLower(name)] = struct{}{}
	}
	return out
}

// validPAN implements the Luhn checksum used by payment cards.
func validPAN(value []byte) bool {
	var digits [24]int
	count := 0
	for _, b := range value {
		if b >= '0' && b <= '9' {
			if count >= len(digits) {
				return false
			}
			digits[count] = int(b - '0')
			count++
		}
	}
	if count < 13 || count > 19 {
		return false
	}
	sum := 0
	double := false
	for i := count - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}
