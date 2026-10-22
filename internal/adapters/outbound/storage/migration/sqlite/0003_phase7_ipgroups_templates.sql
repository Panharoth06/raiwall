-- Phase 7: IP Groups & Deterministic Response Templates (SQLite)

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
