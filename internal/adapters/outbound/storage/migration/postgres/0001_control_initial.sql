-- Raiwall Control Plane Initial Schema (PostgreSQL)

CREATE TABLE IF NOT EXISTS raiwall_apps (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    hostnames TEXT NOT NULL,
    mode VARCHAR(32) NOT NULL DEFAULT 'defense',
    upstreams TEXT NOT NULL DEFAULT '[]',
    block_status_code INT NOT NULL DEFAULT 403,
    block_response_body TEXT NOT NULL DEFAULT '',
    offline_status_code INT NOT NULL DEFAULT 503,
    offline_response_body TEXT NOT NULL DEFAULT '',
    custom_headers TEXT NOT NULL DEFAULT '{}',
    proxy_settings TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_raiwall_apps_mode ON raiwall_apps(mode);

CREATE TABLE IF NOT EXISTS raiwall_exceptions (
    id VARCHAR(64) PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    host VARCHAR(255) NOT NULL DEFAULT '*',
    path_regex TEXT NOT NULL DEFAULT '',
    path_prefix TEXT NOT NULL DEFAULT '',
    method VARCHAR(32) NOT NULL DEFAULT '*',
    location VARCHAR(64) NOT NULL DEFAULT '*',
    param_name VARCHAR(255) NOT NULL DEFAULT '',
    param_regex TEXT NOT NULL DEFAULT '',
    rule_id VARCHAR(64) NOT NULL DEFAULT '*',
    is_active INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_raiwall_exceptions_host ON raiwall_exceptions(host);
CREATE INDEX IF NOT EXISTS idx_raiwall_exceptions_active ON raiwall_exceptions(is_active);

CREATE TABLE IF NOT EXISTS raiwall_acl_rules (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    expression TEXT NOT NULL,
    action VARCHAR(32) NOT NULL DEFAULT 'block',
    priority INT NOT NULL DEFAULT 0,
    status_code INT NOT NULL DEFAULT 403,
    redirect_url TEXT NOT NULL DEFAULT '',
    is_active INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_raiwall_acl_priority ON raiwall_acl_rules(priority DESC);
CREATE INDEX IF NOT EXISTS idx_raiwall_acl_active ON raiwall_acl_rules(is_active);

CREATE TABLE IF NOT EXISTS raiwall_rate_policies (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    host VARCHAR(255) NOT NULL DEFAULT '*',
    tier1_rate BIGINT NOT NULL DEFAULT 100,
    tier1_burst BIGINT NOT NULL DEFAULT 50,
    tier1_period_sec BIGINT NOT NULL DEFAULT 60,
    tier2_threshold BIGINT NOT NULL DEFAULT 10,
    tier2_period_sec BIGINT NOT NULL DEFAULT 60,
    tier2_ban_duration_sec BIGINT NOT NULL DEFAULT 3600,
    tier3_threshold BIGINT NOT NULL DEFAULT 20,
    tier3_ban_duration_sec BIGINT NOT NULL DEFAULT 86400,
    waiting_room_enabled INT NOT NULL DEFAULT 0,
    waiting_room_capacity BIGINT NOT NULL DEFAULT 1000,
    waiting_room_paths TEXT NOT NULL DEFAULT '[]',
    is_active INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_raiwall_rate_policies_host ON raiwall_rate_policies(host);
CREATE INDEX IF NOT EXISTS idx_raiwall_rate_policies_active ON raiwall_rate_policies(is_active);

CREATE TABLE IF NOT EXISTS raiwall_bot_configs (
    id VARCHAR(64) PRIMARY KEY,
    host VARCHAR(255) NOT NULL DEFAULT '*',
    pow_enabled INT NOT NULL DEFAULT 0,
    pow_difficulty INT NOT NULL DEFAULT 4,
    trap_urls TEXT NOT NULL DEFAULT '[]',
    is_active INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_raiwall_bot_configs_host ON raiwall_bot_configs(host);
CREATE INDEX IF NOT EXISTS idx_raiwall_bot_configs_active ON raiwall_bot_configs(is_active);

CREATE TABLE IF NOT EXISTS raiwall_config_snapshots (
    version BIGSERIAL PRIMARY KEY,
    snapshot_data TEXT NOT NULL,
    author VARCHAR(255) NOT NULL DEFAULT 'system',
    description TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_raiwall_snapshots_created ON raiwall_config_snapshots(created_at DESC);

CREATE TABLE IF NOT EXISTS raiwall_users (
    id VARCHAR(64) PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(64) NOT NULL DEFAULT 'viewer',
    is_active INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_raiwall_users_username ON raiwall_users(username);

CREATE TABLE IF NOT EXISTS raiwall_api_keys (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) NOT NULL UNIQUE,
    role VARCHAR(64) NOT NULL DEFAULT 'viewer',
    expires_at TIMESTAMPTZ,
    is_active INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_raiwall_api_keys_hash ON raiwall_api_keys(key_hash);

CREATE TABLE IF NOT EXISTS raiwall_forwarding_rules (
    id VARCHAR(64) PRIMARY KEY,
    app_id VARCHAR(64) NOT NULL,
    prefix TEXT NOT NULL,
    upstreams TEXT NOT NULL DEFAULT '[]',
    strip_prefix INT NOT NULL DEFAULT 0,
    host_header_override TEXT NOT NULL DEFAULT '',
    comment TEXT NOT NULL DEFAULT '',
    is_active INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_raiwall_forwarding_rules_app ON raiwall_forwarding_rules(app_id);
CREATE INDEX IF NOT EXISTS idx_raiwall_forwarding_rules_active ON raiwall_forwarding_rules(is_active);

CREATE TABLE IF NOT EXISTS raiwall_api_resources (
    id VARCHAR(64) PRIMARY KEY,
    app_id VARCHAR(64) NOT NULL,
    method VARCHAR(32) NOT NULL,
    path_pattern TEXT NOT NULL,
    content_type TEXT NOT NULL DEFAULT '',
    hit_count BIGINT NOT NULL DEFAULT 1,
    last_seen TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_raiwall_api_resources UNIQUE(app_id, method, path_pattern)
);
CREATE INDEX IF NOT EXISTS idx_raiwall_api_resources_app ON raiwall_api_resources(app_id);
