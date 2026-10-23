-- Migration 0007: Zero-trust per-app auth gate state

ALTER TABLE raiwall_apps ADD COLUMN IF NOT EXISTS auth_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE raiwall_apps ADD COLUMN IF NOT EXISTS auth_bypass_paths TEXT NOT NULL DEFAULT '[]';

CREATE TABLE IF NOT EXISTS raiwall_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS raiwall_identity_auth_log (
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    username TEXT NOT NULL,
    app_id TEXT NOT NULL DEFAULT '',
    host TEXT NOT NULL DEFAULT '',
    method TEXT NOT NULL DEFAULT 'directory',
    result TEXT NOT NULL,
    client_ip TEXT NOT NULL DEFAULT '',
    country TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (created_at, username, result)
);
