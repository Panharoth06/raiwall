-- Migration 0016: Response policy & DLP settings for WAF policies.
ALTER TABLE raiwall_waf_policies ADD COLUMN response_json TEXT NOT NULL DEFAULT '{}';
