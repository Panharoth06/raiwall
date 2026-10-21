-- Raiwall Telemetry Initial Schema (PostgreSQL)

CREATE TABLE IF NOT EXISTS forensic_events (
    event_id VARCHAR(64) PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    host VARCHAR(255) NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    method VARCHAR(32) NOT NULL DEFAULT '',
    client_ip VARCHAR(64) NOT NULL DEFAULT '',
    ja4 VARCHAR(64) NOT NULL DEFAULT '',
    country VARCHAR(8) NOT NULL DEFAULT '',
    continent VARCHAR(8) NOT NULL DEFAULT '',
    city VARCHAR(128) NOT NULL DEFAULT '',
    asn INT NOT NULL DEFAULT 0,
    as_org VARCHAR(255) NOT NULL DEFAULT '',
    latitude DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    longitude DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    rule_id VARCHAR(64) NOT NULL DEFAULT '',
    action VARCHAR(32) NOT NULL DEFAULT '',
    severity VARCHAR(32) NOT NULL DEFAULT '',
    headers TEXT NOT NULL DEFAULT '',
    payload TEXT NOT NULL DEFAULT '',
    latency_us BIGINT NOT NULL DEFAULT 0,
    status_code INT NOT NULL DEFAULT 0,
    payload_location TEXT NOT NULL DEFAULT '',
    matched_token TEXT NOT NULL DEFAULT '',
    attack_category VARCHAR(64) NOT NULL DEFAULT '',
    response_headers TEXT NOT NULL DEFAULT '',
    response_body BYTEA
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON forensic_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_ip ON forensic_events(client_ip);
CREATE INDEX IF NOT EXISTS idx_events_action ON forensic_events(action);
CREATE INDEX IF NOT EXISTS idx_events_rule ON forensic_events(rule_id);
CREATE INDEX IF NOT EXISTS idx_events_country ON forensic_events(country);
CREATE INDEX IF NOT EXISTS idx_events_composite ON forensic_events(timestamp, action, rule_id, client_ip);
CREATE INDEX IF NOT EXISTS idx_events_ip_host_ts ON forensic_events(client_ip, host, timestamp);
