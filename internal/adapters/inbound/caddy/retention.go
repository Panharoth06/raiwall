package caddy

import (
	"context"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
	"go.uber.org/zap"
)

const (
	retentionInterval = time.Hour
	defaultSnapshots  = 200
	defaultAuditAge   = 365 * 24 * time.Hour
)

// startRetention runs one prune pass and then hourly. It keeps snapshot history
// bounded, expires sessions, and enforces audit retention.
func (m *Middleware) startRetention() {
	if m.controlStore == nil || m.retentionStop != nil {
		return
	}
	stop := make(chan struct{})
	m.retentionStop = stop
	m.retentionWG.Add(1)
	go func() {
		defer m.retentionWG.Done()
		m.pruneRetention(context.Background())

		ticker := time.NewTicker(retentionInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				m.pruneRetention(context.Background())
			}
		}
	}()
}

// pruneRetention removes expired sessions, old audit rows, and snapshots
// outside the retention window. The active snapshot is never deleted.
func (m *Middleware) pruneRetention(ctx context.Context) {
	if m.controlStore == nil {
		return
	}
	keep := defaultSnapshots
	auditAge := defaultAuditAge
	if m.ControlConfig != nil {
		if m.ControlConfig.SnapshotRetention > 0 {
			keep = m.ControlConfig.SnapshotRetention
		}
		if m.ControlConfig.AuditRetention > 0 {
			auditAge = time.Duration(m.ControlConfig.AuditRetention)
		}
	}

	active := uint64(0)
	if snapshot := control.GetActiveSnapshot(); snapshot != nil {
		active = snapshot.Version
	}
	if _, err := m.controlStore.PruneSnapshots(ctx, keep, active); err != nil && m.logger != nil {
		m.logger.Warn("failed to prune configuration snapshots", zap.Error(err))
	}

	now := time.Now().UTC()
	if _, err := m.controlStore.DeleteExpiredAdminSessions(ctx, now); err != nil && m.logger != nil {
		m.logger.Warn("failed to prune expired operator sessions", zap.Error(err))
	}
	if auditAge > 0 {
		if _, err := m.controlStore.DeleteAuditEventsBefore(ctx, now.Add(-auditAge)); err != nil && m.logger != nil {
			m.logger.Warn("failed to prune audit events", zap.Error(err))
		}
	}
}

// stopRetention terminates the cleanup worker.
func (m *Middleware) stopRetention() {
	if m.retentionStop != nil {
		close(m.retentionStop)
		m.retentionStop = nil
	}
	m.retentionWG.Wait()
}
