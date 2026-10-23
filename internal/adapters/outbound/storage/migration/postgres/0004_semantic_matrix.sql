-- Migration 0004: Semantic Detection Matrix (SafeLine parity)
-- Global per-module operating modes and per-application override policies.

CREATE TABLE IF NOT EXISTS raiwall_detector_config (
    module TEXT PRIMARY KEY,
    mode TEXT NOT NULL DEFAULT 'balance',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS raiwall_app_semantic_policies (
    app_id TEXT PRIMARY KEY,
    policy TEXT NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
