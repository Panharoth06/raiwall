-- CRS/engine metadata on forensic events (SQLite).

ALTER TABLE forensic_events ADD COLUMN engine TEXT;
ALTER TABLE forensic_events ADD COLUMN anomaly_score REAL;
ALTER TABLE forensic_events ADD COLUMN paranoia_level INTEGER;
ALTER TABLE forensic_events ADD COLUMN matched_rules TEXT;
