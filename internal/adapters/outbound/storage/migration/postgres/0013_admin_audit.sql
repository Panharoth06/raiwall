-- Migration 0013: append-only control-plane audit log.
-- Rows are only inserted and pruned by retention; no update/delete API exists.

CREATE TABLE IF NOT EXISTS raiwall_admin_audit (
    id               TEXT PRIMARY KEY,
    occurred_at      TIMESTAMPTZ NOT NULL,
    actor_type       TEXT NOT NULL DEFAULT 'system',
    actor_id         TEXT NOT NULL DEFAULT '',
    actor_name       TEXT NOT NULL DEFAULT '',
    role             TEXT NOT NULL DEFAULT '',
    action           TEXT NOT NULL,
    target_type      TEXT NOT NULL DEFAULT '',
    target_id        TEXT NOT NULL DEFAULT '',
    method           TEXT NOT NULL DEFAULT '',
    path             TEXT NOT NULL DEFAULT '',
    status_code      INTEGER NOT NULL DEFAULT 0,
    request_id       TEXT NOT NULL DEFAULT '',
    client_ip        TEXT NOT NULL DEFAULT '',
    user_agent       TEXT NOT NULL DEFAULT '',
    snapshot_version BIGINT NOT NULL DEFAULT 0,
    detail           TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_raiwall_admin_audit_time ON raiwall_admin_audit(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_raiwall_admin_audit_actor ON raiwall_admin_audit(actor_id);
CREATE INDEX IF NOT EXISTS idx_raiwall_admin_audit_action ON raiwall_admin_audit(action);
