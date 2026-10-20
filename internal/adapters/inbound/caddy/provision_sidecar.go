package caddy

import (
	"fmt"

	"github.com/Panharoth06/raiwall/internal/adapters/inbound/grpc"
	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func (m *Middleware) provisionSidecar(_ caddy.Context) error {
	if m.SidecarConfig != nil {
		listenAddr := m.SidecarConfig.Listen
		if listenAddr == "" {
			listenAddr = grpc.DefaultListenAddr
		}
		maxBodySize := int(m.SidecarConfig.MaxBodySize)
		if maxBodySize <= 0 {
			maxBodySize = grpc.DefaultMaxBodySize
		}

		m.sidecarServer = grpc.NewServer(grpc.ExtProcConfig{
			ListenAddr:  listenAddr,
			MaxBodySize: maxBodySize,
			WAFEngine:   m.engine,
			RingBuffer:  m.ringBuffer,
		})
		if err := m.sidecarServer.Start(); err != nil {
			return fmt.Errorf("failed to start Envoy ext_proc sidecar server on %s: %w", listenAddr, err)
		}
		if m.logger != nil {
			m.logger.Info("started Envoy ext_proc sidecar server", zap.String("listen", listenAddr))
		}
	}

	return nil
}
