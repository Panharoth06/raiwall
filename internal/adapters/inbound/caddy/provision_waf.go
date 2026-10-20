package caddy

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/acl"
	"github.com/Panharoth06/raiwall/internal/core/waf"
	"github.com/caddyserver/caddy/v2"
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
