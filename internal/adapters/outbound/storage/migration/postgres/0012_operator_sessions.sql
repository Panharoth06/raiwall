-- Migration 0012: opaque dashboard operator sessions.
-- Only the HMAC of the session token is stored; a database leak cannot replay
-- a cookie. Idle and absolute expiry are enforced on every request.

CREATE TABLE IF NOT EXISTS raiwall_sessions (
    id                  TEXT PRIMARY KEY,
    user_id             TEXT NOT NULL,
    token_hash          TEXT NOT NULL UNIQUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    idle_expires_at     TIMESTAMPTZ NOT NULL,
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,
    client_ip           TEXT NOT NULL DEFAULT '',
    user_agent          TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_raiwall_sessions_user ON raiwall_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_raiwall_sessions_idle ON raiwall_sessions(idle_expires_at);
