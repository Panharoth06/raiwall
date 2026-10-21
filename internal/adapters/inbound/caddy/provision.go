package caddy

import (
	"fmt"
	"net/http"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"github.com/caddyserver/caddy/v2"
)

// Provision sets up the middleware instance.
func (m *Middleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)

	if m.Mode == "" {
		m.Mode = string(control.ModeDefense)
	}
	parsedMode, err := control.ParseRunMode(m.Mode)
	if err != nil {
		return fmt.Errorf("provision raiwall: %w", err)
	}
	m.runMode = parsedMode

	if m.BlockStatusCode == 0 {
		m.BlockStatusCode = http.StatusForbidden
	}
	if m.BlockResponseBody == "" {
		m.BlockResponseBody = defaultBlockHTML
	}
	if m.OfflineStatusCode == 0 {
		m.OfflineStatusCode = http.StatusServiceUnavailable
	}
	if m.OfflineResponseBody == "" {
		m.OfflineResponseBody = defaultOfflineHTML
	}

	m.StripHeaders = CanonicalizeHeaderList(m.StripHeaders)

	if err := m.provisionWAF(ctx); err != nil {
		return err
	}
	if err := m.provisionBot(ctx); err != nil {
		return err
	}
	if err := m.provisionRate(ctx); err != nil {
		return err
	}
	if err := m.provisionACL(ctx); err != nil {
		return err
	}
	if err := m.provisionAuth(ctx); err != nil {
		return err
	}
	if err := m.provisionStorage(ctx); err != nil {
		return err
	}
	if err := m.provisionTelemetry(ctx); err != nil {
		return err
	}
	if err := m.provisionControl(ctx); err != nil {
		return err
	}
	if err := m.provisionSidecar(ctx); err != nil {
		return err
	}

	return nil
}
