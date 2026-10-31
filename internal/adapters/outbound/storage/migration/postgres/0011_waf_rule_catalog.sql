-- Migration 0011: WAF rule catalog, per-rule overrides, and detection policies.
-- Packs are self-contained so snapshots can reproduce detection behavior on rollback.

CREATE TABLE IF NOT EXISTS raiwall_rule_packs (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    version         TEXT NOT NULL DEFAULT '1.0.0',
    type            TEXT NOT NULL,
    priority        INTEGER NOT NULL DEFAULT 100,
    enabled         INTEGER NOT NULL DEFAULT 1,
    replace_builtin INTEGER NOT NULL DEFAULT 0,
    rules_json      TEXT NOT NULL DEFAULT '[]',
    directives      TEXT NOT NULL DEFAULT '',
    files_json      TEXT NOT NULL DEFAULT '{}',
    checksum        TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_raiwall_rule_packs_name_version
    ON raiwall_rule_packs(name, version);

CREATE TABLE IF NOT EXISTS raiwall_rule_overrides (
    canonical_id TEXT PRIMARY KEY,
    enabled      INTEGER,
    severity     TEXT NOT NULL DEFAULT '',
    action       TEXT NOT NULL DEFAULT '',
    updated_by   TEXT NOT NULL DEFAULT '',
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS raiwall_waf_policies (
    id                     TEXT PRIMARY KEY,
    scope                  TEXT NOT NULL,
    app_id                 TEXT NOT NULL DEFAULT '',
    detection_mode         TEXT NOT NULL DEFAULT 'inherit',
    sensitivity            TEXT NOT NULL DEFAULT 'inherit',
    semantic_overrides     TEXT NOT NULL DEFAULT '{}',
    crs_enabled            INTEGER,
    crs_paranoia_level     INTEGER,
    crs_inbound_threshold  INTEGER,
    crs_outbound_threshold INTEGER,
    disabled_pack_ids      TEXT NOT NULL DEFAULT '[]',
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_raiwall_waf_policies_scope_app
    ON raiwall_waf_policies(scope, app_id);

-- Preserve legacy CVE toggles under the canonical namespace.
INSERT INTO raiwall_rule_overrides (canonical_id, enabled, action)
SELECT 'cve:' || rule_id, 0, 'off' FROM raiwall_inner_rule_disabled
ON CONFLICT (canonical_id) DO NOTHING;
