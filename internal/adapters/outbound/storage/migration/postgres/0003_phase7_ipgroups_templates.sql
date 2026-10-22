-- Phase 7: IP Groups & Deterministic Response Templates (PostgreSQL)

CREATE TABLE IF NOT EXISTS raiwall_ip_groups (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    type VARCHAR(32) NOT NULL DEFAULT 'custom',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_raiwall_ip_groups_name ON raiwall_ip_groups(name);

CREATE TABLE IF NOT EXISTS raiwall_ip_group_entries (
    id VARCHAR(64) PRIMARY KEY,
    group_id VARCHAR(64) NOT NULL REFERENCES raiwall_ip_groups(id) ON DELETE CASCADE,
    cidr_or_ip VARCHAR(255) NOT NULL,
    comment TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_raiwall_ip_group_entries_group ON raiwall_ip_group_entries(group_id);

CREATE TABLE IF NOT EXISTS raiwall_response_templates (
    id VARCHAR(64) PRIMARY KEY,
    status_code INT NOT NULL UNIQUE,
    title VARCHAR(255) NOT NULL DEFAULT '',
    content_html TEXT NOT NULL DEFAULT '',
    custom_css TEXT NOT NULL DEFAULT '',
    brand_name VARCHAR(255) NOT NULL DEFAULT 'Raiwall',
    logo_url TEXT NOT NULL DEFAULT '',
    is_custom INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_raiwall_templates_status ON raiwall_response_templates(status_code);
