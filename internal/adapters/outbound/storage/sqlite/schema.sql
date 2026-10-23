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
    proxy_settings TEXT NOT NULL DEFAULT '{}',
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
    waiting_room_paths TEXT NOT NULL DEFAULT '[]',
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

CREATE TABLE IF NOT EXISTS raiwall_forwarding_rules (
    id TEXT PRIMARY KEY,
    app_id TEXT NOT NULL,
    prefix TEXT NOT NULL,
    upstreams TEXT NOT NULL DEFAULT '[]',
    strip_prefix INTEGER NOT NULL DEFAULT 0,
    host_header_override TEXT NOT NULL DEFAULT '',
    comment TEXT NOT NULL DEFAULT '',
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_raiwall_forwarding_rules_app ON raiwall_forwarding_rules(app_id);
CREATE INDEX IF NOT EXISTS idx_raiwall_forwarding_rules_active ON raiwall_forwarding_rules(is_active);

CREATE TABLE IF NOT EXISTS raiwall_api_resources (
    id TEXT PRIMARY KEY,
    app_id TEXT NOT NULL,
    method TEXT NOT NULL,
    path_pattern TEXT NOT NULL,
    content_type TEXT NOT NULL DEFAULT '',
    hit_count INTEGER NOT NULL DEFAULT 1,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(app_id, method, path_pattern)
);
CREATE INDEX IF NOT EXISTS idx_raiwall_api_resources_app ON raiwall_api_resources(app_id);

CREATE TABLE IF NOT EXISTS raiwall_ip_groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    type TEXT NOT NULL DEFAULT 'custom',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_raiwall_ip_groups_name ON raiwall_ip_groups(name);

CREATE TABLE IF NOT EXISTS raiwall_ip_group_entries (
    id TEXT PRIMARY KEY,
    group_id TEXT NOT NULL REFERENCES raiwall_ip_groups(id) ON DELETE CASCADE,
    cidr_or_ip TEXT NOT NULL,
    comment TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_raiwall_ip_group_entries_group ON raiwall_ip_group_entries(group_id);

CREATE TABLE IF NOT EXISTS raiwall_response_templates (
    id TEXT PRIMARY KEY,
    status_code INTEGER NOT NULL UNIQUE,
    title TEXT NOT NULL DEFAULT '',
    content_html TEXT NOT NULL DEFAULT '',
    custom_css TEXT NOT NULL DEFAULT '',
    brand_name TEXT NOT NULL DEFAULT 'Raiwall',
    logo_url TEXT NOT NULL DEFAULT '',
    is_custom INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_raiwall_templates_status ON raiwall_response_templates(status_code);

CREATE TABLE IF NOT EXISTS raiwall_detector_config (
    module TEXT PRIMARY KEY,
    mode TEXT NOT NULL DEFAULT 'balance',
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS raiwall_app_semantic_policies (
    app_id TEXT PRIMARY KEY,
    policy TEXT NOT NULL DEFAULT '{}',
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS raiwall_inner_rule_disabled (
    rule_id TEXT PRIMARY KEY,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

