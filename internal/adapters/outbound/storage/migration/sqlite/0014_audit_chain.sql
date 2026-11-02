-- Migration 0014: tamper-evident hash chain over the audit log.
-- Each audit event gets a chain row linking it to its predecessor; the head row
-- records the tail so truncation is detectable. Existing events stay unchained.

CREATE TABLE IF NOT EXISTS raiwall_admin_audit_chain (
    seq        INTEGER PRIMARY KEY,
    event_id   TEXT NOT NULL UNIQUE,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS raiwall_admin_audit_head (
    id   INTEGER PRIMARY KEY CHECK (id = 1),
    seq  INTEGER NOT NULL DEFAULT 0,
    hash TEXT NOT NULL DEFAULT ''
);

INSERT OR IGNORE INTO raiwall_admin_audit_head (id, seq, hash) VALUES (1, 0, '');
