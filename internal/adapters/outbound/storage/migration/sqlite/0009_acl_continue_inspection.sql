-- Migration: 0009_acl_continue_inspection.sql
-- Description: Add continue_inspection column to raiwall_acl_rules

ALTER TABLE raiwall_acl_rules ADD COLUMN continue_inspection INTEGER NOT NULL DEFAULT 0;
