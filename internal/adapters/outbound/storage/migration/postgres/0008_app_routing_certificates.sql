-- Migration 0008: Application routing/TLS metadata and managed certificates.

ALTER TABLE raiwall_apps ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';
ALTER TABLE raiwall_apps ADD COLUMN IF NOT EXISTS ports TEXT NOT NULL DEFAULT '[{"port":80,"scheme":"http"}]';
ALTER TABLE raiwall_apps ADD COLUMN IF NOT EXISTS ssl_mode TEXT NOT NULL DEFAULT 'none';
ALTER TABLE raiwall_apps ADD COLUMN IF NOT EXISTS certificate_id TEXT NOT NULL DEFAULT '';
ALTER TABLE raiwall_apps ADD COLUMN IF NOT EXISTS routing_type TEXT NOT NULL DEFAULT 'proxy';
ALTER TABLE raiwall_apps ADD COLUMN IF NOT EXISTS document_root TEXT NOT NULL DEFAULT '';
ALTER TABLE raiwall_apps ADD COLUMN IF NOT EXISTS redirect_url TEXT NOT NULL DEFAULT '';
ALTER TABLE raiwall_apps ADD COLUMN IF NOT EXISTS redirect_status INTEGER NOT NULL DEFAULT 302;
ALTER TABLE raiwall_apps ADD COLUMN IF NOT EXISTS load_balancing TEXT NOT NULL DEFAULT 'round_robin';

CREATE TABLE IF NOT EXISTS raiwall_certificates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    domains TEXT NOT NULL DEFAULT '[]',
    source TEXT NOT NULL DEFAULT 'self_signed',
    cert_pem TEXT NOT NULL DEFAULT '',
    encrypted_key_pem TEXT NOT NULL DEFAULT '',
    fingerprint_sha256 TEXT NOT NULL DEFAULT '',
    issuer TEXT NOT NULL DEFAULT '',
    not_before TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    not_after TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    auto_renew INTEGER NOT NULL DEFAULT 1,
    acme_staging INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_raiwall_certificates_source ON raiwall_certificates(source);
