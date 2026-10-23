-- Migration 0005: Inner Rules (CVE virtual patch) runtime state
-- Presence of a row marks the signature as disabled; bundled rules are enabled by default.

CREATE TABLE IF NOT EXISTS raiwall_inner_rule_disabled (
    rule_id TEXT PRIMARY KEY,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
