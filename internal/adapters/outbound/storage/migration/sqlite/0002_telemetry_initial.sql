-- Raiwall Telemetry Initial Schema (SQLite)

CREATE TABLE IF NOT EXISTS forensic_events (
    event_id TEXT PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    host TEXT,
    path TEXT,
    method TEXT,
    client_ip TEXT,
    ja4 TEXT,
    country TEXT,
    continent TEXT,
    city TEXT,
    asn INTEGER,
    as_org TEXT,
    latitude REAL,
    longitude REAL,
    rule_id TEXT,
    action TEXT,
    severity TEXT,
    headers TEXT,
    payload TEXT,
    latency_us INTEGER,
    status_code INTEGER,
    payload_location TEXT,
    matched_token TEXT,
    attack_category TEXT,
    response_headers TEXT,
    response_body BLOB
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON forensic_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_ip ON forensic_events(client_ip);
CREATE INDEX IF NOT EXISTS idx_events_action ON forensic_events(action);
CREATE INDEX IF NOT EXISTS idx_events_rule ON forensic_events(rule_id);
CREATE INDEX IF NOT EXISTS idx_events_country ON forensic_events(country);
CREATE INDEX IF NOT EXISTS idx_events_composite ON forensic_events(timestamp, action, rule_id, client_ip);
CREATE INDEX IF NOT EXISTS idx_events_ip_host_ts ON forensic_events(client_ip, host, timestamp);
