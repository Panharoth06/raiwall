-- Raiwall Control Plane Schema (SQLite)

CREATE TABLE IF NOT EXISTS raiwall_apps (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    hostnames TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'defense',
    upstreams TEXT NOT NULL DEFAULT '[]',
    block_status_code INTEGER NOT NULL DEFAULT 403,
    block_response_body TEXT NOT NULL DEFAULT '',
    offline_status_code INTEGER NOT NULL DEFAULT 503,
    offline_response_body TEXT NOT NULL DEFAULT '',
    custom_headers TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_raiwall_apps_mode ON raiwall_apps(mode);

CREATE TABLE IF NOT EXISTS raiwall_exceptions (
    id TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    host TEXT NOT NULL DEFAULT '*',
    path_regex TEXT NOT NULL DEFAULT '',
    path_prefix TEXT NOT NULL DEFAULT '',
    method TEXT NOT NULL DEFAULT '*',
    location TEXT NOT NULL DEFAULT '*',
    param_name TEXT NOT NULL DEFAULT '',
    param_regex TEXT NOT NULL DEFAULT '',
    rule_id TEXT NOT NULL DEFAULT '*',
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_raiwall_exceptions_host ON raiwall_exceptions(host);
CREATE INDEX IF NOT EXISTS idx_raiwall_exceptions_active ON raiwall_exceptions(is_active);

CREATE TABLE IF NOT EXISTS raiwall_acl_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    expression TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT 'block',
    priority INTEGER NOT NULL DEFAULT 0,
    status_code INTEGER NOT NULL DEFAULT 403,
    redirect_url TEXT NOT NULL DEFAULT '',
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_raiwall_acl_priority ON raiwall_acl_rules(priority DESC);
CREATE INDEX IF NOT EXISTS idx_raiwall_acl_active ON raiwall_acl_rules(is_active);

CREATE TABLE IF NOT EXISTS raiwall_rate_policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '*',
    tier1_rate INTEGER NOT NULL DEFAULT 100,
    tier1_burst INTEGER NOT NULL DEFAULT 50,
    tier1_period_sec INTEGER NOT NULL DEFAULT 60,
    tier2_threshold INTEGER NOT NULL DEFAULT 10,
    tier2_period_sec INTEGER NOT NULL DEFAULT 60,
    tier2_ban_duration_sec INTEGER NOT NULL DEFAULT 3600,
    tier3_threshold INTEGER NOT NULL DEFAULT 20,
    tier3_ban_duration_sec INTEGER NOT NULL DEFAULT 86400,
    waiting_room_enabled INTEGER NOT NULL DEFAULT 0,
    waiting_room_capacity INTEGER NOT NULL DEFAULT 1000,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_raiwall_rate_policies_host ON raiwall_rate_policies(host);
CREATE INDEX IF NOT EXISTS idx_raiwall_rate_policies_active ON raiwall_rate_policies(is_active);

CREATE TABLE IF NOT EXISTS raiwall_bot_configs (
    id TEXT PRIMARY KEY,
    host TEXT NOT NULL DEFAULT '*',
    pow_enabled INTEGER NOT NULL DEFAULT 0,
    pow_difficulty INTEGER NOT NULL DEFAULT 4,
    trap_urls TEXT NOT NULL DEFAULT '[]',
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_raiwall_bot_configs_host ON raiwall_bot_configs(host);
CREATE INDEX IF NOT EXISTS idx_raiwall_bot_configs_active ON raiwall_bot_configs(is_active);

CREATE TABLE IF NOT EXISTS raiwall_config_snapshots (
    version INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_data TEXT NOT NULL,
    author TEXT NOT NULL DEFAULT 'system',
    description TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_raiwall_snapshots_created ON raiwall_config_snapshots(created_at DESC);

CREATE TABLE IF NOT EXISTS raiwall_users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer',
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_raiwall_users_username ON raiwall_users(username);

CREATE TABLE IF NOT EXISTS raiwall_api_keys (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL DEFAULT 'viewer',
    expires_at TIMESTAMP,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_raiwall_api_keys_hash ON raiwall_api_keys(key_hash);
