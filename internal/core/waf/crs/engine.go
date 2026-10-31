// Package crs runs the OWASP Core Rule Set through Coraza behind the WAF
// engine port. CRS performs its own transformations and anomaly scoring; the
// semantic engine's normalizer is intentionally not applied to its input.
package crs

import (
	"embed"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	ctypes "github.com/corazawaf/coraza/v3/types"
)

//go:embed crs-setup.conf rules/*.conf rules/*.data
var rulesFS embed.FS

// Default anomaly thresholds mirror the CRS defaults.
const (
	DefaultInboundThreshold  = 5
	DefaultOutboundThreshold = 4
	DefaultMaxBodySize       = 1024 * 1024
	DefaultParanoiaLevel     = 1
	MaxMatchedRules          = 16
)

// Mode selects whether CRS interruptions block or only audit.
type Mode string

const (
	ModeBlock Mode = "block"
	ModeAudit Mode = "audit"
)

// Config controls a compiled CRS policy.
type Config struct {
	Mode              Mode
	ParanoiaLevel     int
	InboundThreshold  int
	OutboundThreshold int
	MaxBodySize       int
}

// Engine is a compiled Coraza WAF configured with OWASP CRS.
type Engine struct {
	waf  coraza.WAF
	conf Config
}

// New compiles the embedded CRS for one policy. Compilation happens once at
// provisioning; transactions are created per request and are cheap.
func New(conf Config) (*Engine, error) {
	conf = normalizeConfig(conf)

	cfg := coraza.NewWAFConfig().
		WithRootFS(rulesFS).
		WithRequestBodyAccess().
		WithRequestBodyLimit(conf.MaxBodySize).
		WithRequestBodyInMemoryLimit(conf.MaxBodySize).
		WithDirectives(directives(conf))

	instance, err := coraza.NewWAF(cfg)
	if err != nil {
		return nil, fmt.Errorf("compile OWASP CRS (PL%d): %w", conf.ParanoiaLevel, err)
	}
	return &Engine{waf: instance, conf: conf}, nil
}

func normalizeConfig(conf Config) Config {
	if conf.ParanoiaLevel < 1 || conf.ParanoiaLevel > 4 {
		conf.ParanoiaLevel = DefaultParanoiaLevel
	}
	if conf.InboundThreshold <= 0 {
		conf.InboundThreshold = DefaultInboundThreshold
	}
	if conf.OutboundThreshold <= 0 {
		conf.OutboundThreshold = DefaultOutboundThreshold
	}
	if conf.MaxBodySize <= 0 {
		conf.MaxBodySize = DefaultMaxBodySize
	}
	switch Mode(strings.ToLower(string(conf.Mode))) {
	case ModeBlock:
		conf.Mode = ModeBlock
	default:
		conf.Mode = ModeAudit
	}
	return conf
}

// directives sets the paranoia level and thresholds before REQUEST-901
// initializes defaults, then loads the vendored CRS.
func directives(conf Config) string {
	return fmt.Sprintf(`
SecRuleEngine On
SecAction "id:900000,phase:1,pass,nolog,t:none,tag:'OWASP_CRS',setvar:tx.blocking_paranoia_level=%d"
SecAction "id:900001,phase:1,pass,nolog,t:none,tag:'OWASP_CRS',setvar:tx.detection_paranoia_level=%d"
SecAction "id:900110,phase:1,pass,nolog,t:none,setvar:tx.inbound_anomaly_score_threshold=%d"
SecAction "id:900120,phase:1,pass,nolog,t:none,setvar:tx.outbound_anomaly_score_threshold=%d"
Include crs-setup.conf
Include rules/REQUEST-*.conf
Include rules/RESPONSE-*.conf
`, conf.ParanoiaLevel, conf.ParanoiaLevel, conf.InboundThreshold, conf.OutboundThreshold)
}

// Name returns the identifier for this engine.
func (e *Engine) Name() string {
	return "crs"
}

// InspectRequest feeds the request into Coraza and maps the interruption to a
// Raivall verdict. The transaction runs all request phases, including body
// inspection, before the verdict is produced.
func (e *Engine) InspectRequest(ctx *waf.RequestContext) (*waf.Verdict, error) {
	if ctx == nil {
		return waf.VerdictAllow, nil
	}

	tx := e.waf.NewTransaction()
	defer func() { _ = tx.Close() }()

	client := ""
	if ctx.ClientIP != nil {
		client = ctx.ClientIP.String()
	}
	tx.ProcessConnection(client, 0, ctx.Host, 0)
	tx.SetServerName(ctx.Host)

	uri := ctx.Path
	if ctx.Query != "" {
		uri += "?" + ctx.Query
	}
	tx.ProcessURI(uri, ctx.Method, "HTTP/1.1")

	if ctx.Query != "" {
		if values, err := url.ParseQuery(ctx.Query); err == nil {
			for key, vals := range values {
				for _, val := range vals {
					tx.AddGetRequestArgument(key, val)
				}
			}
		}
	}

	// Go's http.Header excludes Host; CRS rules inspect REQUEST_HEADERS:Host.
	tx.AddRequestHeader("Host", ctx.Host)
	for key, values := range ctx.Headers {
		for _, value := range values {
			tx.AddRequestHeader(key, value)
		}
	}

	if it := tx.ProcessRequestHeaders(); it != nil {
		return e.verdict(tx, it), nil
	}

	if len(ctx.Body) > 0 {
		it, _, err := tx.WriteRequestBody(ctx.Body)
		if err != nil {
			return nil, fmt.Errorf("crs request body: %w", err)
		}
		if it != nil {
			return e.verdict(tx, it), nil
		}
	}

	it, err := tx.ProcessRequestBody()
	if err != nil {
		return nil, fmt.Errorf("crs request evaluation: %w", err)
	}
	if it == nil {
		it = tx.Interruption()
	}
	if it == nil {
		return waf.VerdictAllow, nil
	}
	return e.verdict(tx, it), nil
}

// InspectResponse is intentionally disabled until response inspection is
// implemented as a paired request/response transaction (Phase 1B).
//
// A standalone transaction skips phase-1 CRS initialization, leaving
// tx.outbound_anomaly_score_threshold unset; rule 959100 then matches every
// response (0 >= 0). Returning allow is safer than emitting a false positive
// for every request.
func (e *Engine) InspectResponse(_ *waf.ResponseContext) (*waf.Verdict, error) {
	return waf.VerdictAllow, nil
}

func (e *Engine) verdict(tx ctypes.Transaction, it *ctypes.Interruption) *waf.Verdict {
	action := waf.ActionBlock
	if e.conf.Mode == ModeAudit {
		action = waf.ActionAudit
	}

	v := &waf.Verdict{
		Action:         action,
		RuleID:         fmt.Sprintf("CRS_%d", it.RuleID),
		Reason:         fmt.Sprintf("OWASP CRS rule %d (%s)", it.RuleID, it.Action),
		AttackCategory: "crs",
		Engine:         "crs",
		AnomalyScore:   anomalyScore(tx),
		ParanoiaLevel:  e.conf.ParanoiaLevel,
	}
	if it.Status > 0 {
		v.StatusCode = it.Status
	}

	for _, match := range tx.MatchedRules() {
		meta := match.Rule()
		v.MatchedRules = append(v.MatchedRules, waf.RuleMatch{
			RuleID:   strconv.Itoa(meta.ID()),
			Message:  match.Message(),
			Severity: meta.Severity().String(),
			Engine:   "crs",
		})
		if len(v.MatchedRules) >= MaxMatchedRules {
			break
		}
	}
	return v
}

// txVariables is implemented by Coraza's concrete transaction. The public
// types.Transaction interface does not expose variables, but the method set
// does, so a narrow assertion reads the anomaly score without importing
// Coraza internals.
type txVariables interface {
	Variables() plugintypes.TransactionVariables
}

func anomalyScore(tx ctypes.Transaction) float64 {
	vars, ok := tx.(txVariables)
	if !ok {
		return 0
	}
	txVars := vars.Variables().TX()
	for _, key := range []string{"blocking_inbound_anomaly_score", "anomaly_score"} {
		values := txVars.Get(key)
		if len(values) == 0 {
			continue
		}
		score, err := strconv.ParseFloat(values[0], 64)
		if err == nil {
			return score
		}
	}
	return 0
}
