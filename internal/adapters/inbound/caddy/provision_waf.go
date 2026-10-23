package caddy

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/Panharoth06/raiwall/internal/core/waf/cve"
	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func (m *Middleware) provisionWAF(_ caddy.Context) error {
	// Provision Exception Engine early so it can be wired into SemanticEngine
	if m.exceptionEngine == nil {
		if m.ExceptionConfig != nil && len(m.ExceptionConfig.Rules) > 0 {
			eng, err := acl.NewExceptionEngine(m.ExceptionConfig.Rules...)
			if err != nil {
				return fmt.Errorf("provision exception engine: %w", err)
			}
			m.exceptionEngine = eng
		} else {
			m.exceptionEngine, _ = acl.NewExceptionEngine()
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
		if m.exceptionEngine != nil {
			opts = append(opts, waf.WithExceptionEngine(m.exceptionEngine))
		}
		// Resolve per-app semantic matrices live from the atomic config snapshot.
		opts = append(opts, waf.WithMatrixSource(control.SnapshotMatrixSource{}))
		// Virtual-patch signatures (inner rules) run as Stage 0 ahead of triage.
		if innerRules, err := cve.NewBundled(); err == nil {
			opts = append(opts, waf.WithInnerRules(innerRules))
		} else if m.logger != nil {
			m.logger.Error("cve virtual-patch library failed to load; inner rules disabled", zap.Error(err))
		}
		m.engine = waf.NewSemanticEngine(opts...)
	} else if sem, ok := m.engine.(*waf.SemanticEngine); ok {
		sem.SetExceptionEngine(m.exceptionEngine)
	}

	m.bufferPool = &sync.Pool{
		New: func() any {
			return new(bytes.Buffer)
		},
	}
	return nil
}
