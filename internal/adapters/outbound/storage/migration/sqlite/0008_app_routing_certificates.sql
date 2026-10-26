-- Migration 0008: Application routing/TLS metadata and managed certificates.
-- Extends protected sites with listening-port metadata, TLS mode, and the
-- routing strategy (proxy / static / redirect), and introduces the managed
-- certificate store consumed by the dynamic SNI provider.

ALTER TABLE raiwall_apps ADD COLUMN description TEXT NOT NULL DEFAULT '';
ALTER TABLE raiwall_apps ADD COLUMN ports TEXT NOT NULL DEFAULT '[{"port":80,"scheme":"http"}]';
ALTER TABLE raiwall_apps ADD COLUMN ssl_mode TEXT NOT NULL DEFAULT 'none';
ALTER TABLE raiwall_apps ADD COLUMN certificate_id TEXT NOT NULL DEFAULT '';
ALTER TABLE raiwall_apps ADD COLUMN routing_type TEXT NOT NULL DEFAULT 'proxy';
ALTER TABLE raiwall_apps ADD COLUMN document_root TEXT NOT NULL DEFAULT '';
ALTER TABLE raiwall_apps ADD COLUMN redirect_url TEXT NOT NULL DEFAULT '';
ALTER TABLE raiwall_apps ADD COLUMN redirect_status INTEGER NOT NULL DEFAULT 302;
ALTER TABLE raiwall_apps ADD COLUMN load_balancing TEXT NOT NULL DEFAULT 'round_robin';

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
