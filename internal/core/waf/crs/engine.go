// Package crs runs OWASP CRS and imported ModSecurity rules through Coraza
// behind the WAF engine port. Coraza performs its own transformations and
// anomaly scoring; the semantic engine's normalizer is intentionally not
// applied to its input.
package crs

import (
	"fmt"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/corazawaf/coraza/v3"
	ctypes "github.com/corazawaf/coraza/v3/types"
)

// Default anomaly thresholds mirror the CRS defaults.
const (
	DefaultInboundThreshold  = 5
	DefaultOutboundThreshold = 4
	DefaultMaxBodySize       = 1024 * 1024
	DefaultParanoiaLevel     = 1
	MaxMatchedRules          = 16
)

// Mode selects whether Coraza interruptions block or only audit.
type Mode string

const (
	ModeBlock Mode = "block"
	ModeAudit Mode = "audit"
)

// Pack is one imported directive bundle. Files are mounted under
// packs/<safe ID>/ and every .conf file is included in lexical order.
type Pack struct {
	ID             string
	ReplaceBuiltin bool
	Directives     string
	Files          map[string]string
}

// Override changes one compiled rule after the ruleset is loaded.
type Override struct {
	RuleID   int
	Disabled bool
	Alert    bool
	Severity string
}

// Config controls a compiled Coraza policy.
type Config struct {
	Mode              Mode
	ParanoiaLevel     int
	InboundThreshold  int
	OutboundThreshold int
	MaxBodySize       int
	InspectResponse   bool
	ResponseBodyLimit int
	ResponseMimeTypes []string
	// Disabled skips inspection entirely without recompiling.
	Disabled  bool
	Packs     []Pack
	Overrides []Override
	// Exceptions are translated into phase-1 ctl actions that remove scoped
	// CRS rules before they run.
	Exceptions []Exception
}

// Session holds an active Coraza transaction for paired request/response inspection.
type Session struct {
	tx     ctypes.Transaction
	set    *compiledSet
	closed atomic.Bool
}

// Close releases the Coraza transaction resources exactly once.
func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	if s.closed.CompareAndSwap(false, true) {
		return s.tx.Close()
	}
	return nil
}

// compiledSet is one immutable Coraza instance and its associated policy.
type compiledSet struct {
	waf      coraza.WAF
	conf     Config
	alert    map[int]struct{}
	severity map[int]string
}

// Engine is a compiled Coraza WAF. Deploys compile a new set and swap the
// pointer atomically, so requests never observe a partial ruleset.
type Engine struct {
	set atomic.Pointer[compiledSet]
}

// New compiles the configured ruleset once.
func New(conf Config) (*Engine, error) {
	engine := &Engine{}
	if err := engine.Reload(conf); err != nil {
		return nil, err
	}
	return engine, nil
}

// Reload compiles a new ruleset and swaps it in only on success.
func (e *Engine) Reload(conf Config) error {
	conf = normalizeConfig(conf)
	set, err := compile(conf)
	if err != nil {
		return err
	}
	e.set.Store(set)
	return nil
}

func compile(conf Config) (*compiledSet, error) {
	if err := validateExceptions(conf.Exceptions); err != nil {
		return nil, fmt.Errorf("compile Coraza exceptions: %w", err)
	}
	cfg := coraza.NewWAFConfig().
		WithRootFS(buildOverlayFS(conf)).
		WithRequestBodyAccess().
		WithRequestBodyLimit(conf.MaxBodySize).
		WithRequestBodyInMemoryLimit(conf.MaxBodySize)

	if conf.InspectResponse {
		limit := conf.ResponseBodyLimit
		if limit <= 0 {
			limit = DefaultMaxBodySize
		}
		cfg = cfg.WithResponseBodyAccess().
			WithResponseBodyLimit(limit)
		if len(conf.ResponseMimeTypes) > 0 {
			cfg = cfg.WithResponseBodyMimeTypes(conf.ResponseMimeTypes)
		}
	}

	cfg = cfg.WithDirectives(directives(conf))

	instance, err := coraza.NewWAF(cfg)
	if err != nil {
		return nil, fmt.Errorf("compile Coraza ruleset (PL%d): %w", conf.ParanoiaLevel, err)
	}
	alert := make(map[int]struct{})
	severity := make(map[int]string)
	for _, override := range conf.Overrides {
		if override.Disabled {
			continue
		}
		if override.Alert {
			alert[override.RuleID] = struct{}{}
		}
		if value := strings.ToLower(strings.TrimSpace(override.Severity)); value != "" {
			severity[override.RuleID] = value
		}
	}
	return &compiledSet{waf: instance, conf: conf, alert: alert, severity: severity}, nil
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
	if conf.ResponseBodyLimit <= 0 {
		conf.ResponseBodyLimit = DefaultMaxBodySize
	}
	switch Mode(strings.ToLower(string(conf.Mode))) {
	case ModeBlock:
		conf.Mode = ModeBlock
	default:
		conf.Mode = ModeAudit
	}
	return conf
}

// Name returns the identifier for this engine.
func (e *Engine) Name() string {
	return "crs"
}

// InspectRequest feeds the request into Coraza and maps the interruption to a
// Raiwall verdict. When response inspection is enabled, the transaction is
// preserved in ctx.Session for paired response evaluation.
func (e *Engine) InspectRequest(ctx *waf.RequestContext) (*waf.Verdict, error) {
	set := e.set.Load()
	if set == nil || set.conf.Disabled || ctx == nil {
		return waf.VerdictAllow, nil
	}

	tx := set.waf.NewTransaction()
	session := &Session{tx: tx, set: set}
	shouldClose := true
	defer func() {
		if shouldClose {
			_ = session.Close()
		}
	}()

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
		return verdict(set, tx, it), nil
	}

	if len(ctx.Body) > 0 {
		it, _, err := tx.WriteRequestBody(ctx.Body)
		if err != nil {
			return nil, fmt.Errorf("crs request body: %w", err)
		}
		if it != nil {
			return verdict(set, tx, it), nil
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
		if ctx.InspectResponse && set.conf.InspectResponse {
			shouldClose = false
			ctx.Session = session
		}
		return waf.VerdictAllow, nil
	}
	return verdict(set, tx, it), nil
}

// InspectResponse evaluates response headers and body using the paired Coraza transaction.
func (e *Engine) InspectResponse(ctx *waf.ResponseContext) (*waf.Verdict, error) {
	if ctx == nil || ctx.Session == nil {
		return waf.VerdictAllow, nil
	}
	sess, ok := ctx.Session.(*Session)
	if !ok || sess == nil {
		return waf.VerdictAllow, nil
	}
	defer func() { _ = sess.Close() }()

	set := sess.set
	tx := sess.tx
	if set == nil || set.conf.Disabled || tx == nil {
		return waf.VerdictAllow, nil
	}

	for key, values := range ctx.Headers {
		for _, value := range values {
			tx.AddResponseHeader(key, value)
		}
	}

	if it := tx.ProcessResponseHeaders(ctx.StatusCode, "HTTP/1.1"); it != nil {
		return verdict(set, tx, it), nil
	}

	if len(ctx.Body) > 0 {
		it, _, err := tx.WriteResponseBody(ctx.Body)
		if err != nil {
			return nil, fmt.Errorf("crs response body: %w", err)
		}
		if it != nil {
			return verdict(set, tx, it), nil
		}
	}

	it, err := tx.ProcessResponseBody()
	if err != nil {
		return nil, fmt.Errorf("crs response evaluation: %w", err)
	}
	if it == nil {
		it = tx.Interruption()
	}
	if it == nil {
		return waf.VerdictAllow, nil
	}
	return verdict(set, tx, it), nil
}
