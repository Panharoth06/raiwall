-- Migration 0015: audit retention floor and Ed25519 checkpoints.
-- The floor records the last chain entry removed by retention so the surviving
-- prefix can still be verified. Anchors are signed checkpoints over the head.

CREATE TABLE IF NOT EXISTS raiwall_admin_audit_floor (
    id   INTEGER PRIMARY KEY CHECK (id = 1),
    seq  BIGINT NOT NULL DEFAULT 0,
    hash TEXT NOT NULL DEFAULT ''
);
INSERT INTO raiwall_admin_audit_floor (id, seq, hash) VALUES (1, 0, '')
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS raiwall_admin_audit_anchors (
    seq        BIGINT PRIMARY KEY,
    hash       TEXT NOT NULL,
    signed_at  TIMESTAMPTZ NOT NULL,
    public_key TEXT NOT NULL,
    signature  TEXT NOT NULL
);
