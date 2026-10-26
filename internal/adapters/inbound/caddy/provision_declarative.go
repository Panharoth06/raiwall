package caddy

import (
	"context"
	"fmt"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control/declarative"
	"go.uber.org/zap"
)

// syncDeclarative reconciles raiwall.yaml resources into the control store and
// deploys a new snapshot only when the compiled content changed.
func (m *Middleware) syncDeclarative() error {
	if m.controlStore == nil || m.DeclarativeConfig == nil {
		return nil
	}

	started := time.Now()
	result, err := declarative.Sync(context.Background(), m.controlStore, m.DeclarativeConfig)
	if m.logger != nil {
		for _, warning := range result.Warnings {
			m.logger.Warn("declarative configuration warning", zap.String("detail", warning))
		}
	}
	if err != nil {
		return fmt.Errorf("declarative configuration sync failed: %w", err)
	}

	if result.Changed() {
		if m.templateManager != nil {
			_ = m.templateManager.LoadFromStore(context.Background(), m.controlStore)
		}
		if m.ipGroupMgr != nil {
			m.syncIPGroupsWithStore(m.controlStore, m.ipGroupMgr)
		}
	}

	deployed, err := declarative.Apply(context.Background(), m.controlStore)
	if err != nil {
		return err
	}

	if m.logger != nil {
		fields := []zap.Field{
			zap.Int("created", result.Created),
			zap.Int("updated", result.Updated),
			zap.Int("deleted", result.Deleted),
			zap.Int("skipped", result.Skipped),
			zap.Bool("snapshot_deployed", deployed),
			zap.Duration("took", time.Since(started)),
		}
		if result.Changed() || deployed {
			m.logger.Info("declarative configuration reconciled", fields...)
		} else {
			m.logger.Debug("declarative configuration unchanged", fields...)
		}
	}
	return nil
}
