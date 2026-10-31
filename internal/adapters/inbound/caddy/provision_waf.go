package caddy

import (
	"fmt"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/Panharoth06/raiwall/internal/core/waf/crs"
	"github.com/Panharoth06/raiwall/internal/core/waf/cve"
	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func (m *Middleware) provisionWAF(_ caddy.Context) error {
	// Provision Exception Engine early so it can be wired into SemanticEngine
	if m.exceptionEngine.Load() == nil {
		if m.ExceptionConfig != nil && len(m.ExceptionConfig.Rules) > 0 {
			eng, err := acl.NewExceptionEngine(m.ExceptionConfig.Rules...)
			if err != nil {
				return fmt.Errorf("provision exception engine: %w", err)
			}
			m.exceptionEngine.Store(eng)
		} else {
			eng, _ := acl.NewExceptionEngine()
			m.exceptionEngine.Store(eng)
		}
	}

	if m.engine == nil {
		var opts []waf.SemanticOption
		if m.ASTTimeout > 0 {
			opts = append(opts, waf.WithASTTimeout(time.Duration(m.ASTTimeout)))
		}
		if m.MaxParamSize > 0 {
			opts = append(opts, waf.WithMaxParamSize(m.MaxParamSize))
		}
		if ee := m.exceptionEngine.Load(); ee != nil {
			opts = append(opts, waf.WithExceptionEngine(ee))
		}
		// Resolve per-app semantic matrices live from the atomic config snapshot.
		opts = append(opts, waf.WithMatrixSource(control.SnapshotMatrixSource{}))
		// Virtual-patch signatures (inner rules) run as Stage 0 ahead of triage.
		if innerRules, err := cve.NewBundled(); err == nil {
			innerRules.SetStateSource(control.SnapshotInnerRuleState)
			opts = append(opts, waf.WithInnerRules(innerRules))
		} else if m.logger != nil {
			m.logger.Error("cve virtual-patch library failed to load; inner rules disabled", zap.Error(err))
		}
		semantic := waf.NewSemanticEngine(opts...)
		m.engine = semantic

		// OWASP CRS runs as a second engine after the semantic funnel. It has
		// its own normalization and anomaly scoring, so it receives the raw
		// request unchanged. CRS mode is audit by default to allow tuning.
		if m.CRSEnabled {
			crsEngine, err := crs.New(crs.Config{
				Mode:              crs.Mode(m.CRSMode),
				ParanoiaLevel:     m.CRSParanoiaLevel,
				InboundThreshold:  m.CRSInboundThreshold,
				OutboundThreshold: m.CRSOutboundThreshold,
				MaxBodySize:       MaxInspectionBodySize,
			})
			if err != nil {
				return fmt.Errorf("provision OWASP CRS engine: %w", err)
			}
			m.crsEngine = crsEngine
			m.engine = waf.NewCompositeEngine(semantic, crsEngine)
			if m.logger != nil {
				m.logger.Info("OWASP CRS enabled",
					zap.String("mode", m.CRSMode),
					zap.Int("paranoia_level", m.CRSParanoiaLevel),
				)
			}
		}
	} else if setter, ok := m.engine.(interface{ SetExceptionEngine(waf.ExceptionMatcher) }); ok {
		setter.SetExceptionEngine(m.exceptionEngine.Load())
	}

	return nil
}
