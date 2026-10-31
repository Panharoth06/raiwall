package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/Panharoth06/raiwall/internal/core/control"
)

// WAF rule packs, per-rule overrides, and detection policies.

const rulePackColumns = `id, name, version, type, priority, enabled, replace_builtin,
	rules_json, directives, files_json, checksum, created_at, updated_at`

func scanRulePack(scanner interface{ Scan(...any) error }) (control.RulePackRecord, error) {
	var (
		rec     control.RulePackRecord
		enabled int
		replace int
	)
	err := scanner.Scan(
		&rec.ID, &rec.Name, &rec.Version, &rec.Type, &rec.Priority,
		&enabled, &replace, &rec.RulesJSON, &rec.Directives,
		&rec.FilesJSON, &rec.Checksum, &rec.CreatedAt, &rec.UpdatedAt,
	)
	rec.Enabled = enabled == 1
	rec.ReplaceBuiltin = replace == 1
	return rec, err
}

func (s *Store) ListRulePacks(ctx context.Context) ([]control.RulePackRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT "+rulePackColumns+" FROM raiwall_rule_packs ORDER BY priority ASC, name ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []control.RulePackRecord
	for rows.Next() {
		rec, err := scanRulePack(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, rec)
	}
	return result, rows.Err()
}

func (s *Store) GetRulePack(ctx context.Context, id string) (control.RulePackRecord, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT "+rulePackColumns+" FROM raiwall_rule_packs WHERE id = ?", id)
	return scanRulePack(row)
}

func (s *Store) UpsertRulePack(ctx context.Context, rec control.RulePackRecord) error {
	now := time.Now().UTC()
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = now
	}
	rec.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO raiwall_rule_packs (
			id, name, version, type, priority, enabled, replace_builtin,
			rules_json, directives, files_json, checksum, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			version = excluded.version,
			type = excluded.type,
			priority = excluded.priority,
			enabled = excluded.enabled,
			replace_builtin = excluded.replace_builtin,
			rules_json = excluded.rules_json,
			directives = excluded.directives,
			files_json = excluded.files_json,
			checksum = excluded.checksum,
			updated_at = excluded.updated_at`,
		rec.ID, rec.Name, rec.Version, rec.Type, rec.Priority,
		boolToInt(rec.Enabled), boolToInt(rec.ReplaceBuiltin),
		rec.RulesJSON, rec.Directives, rec.FilesJSON, rec.Checksum,
		rec.CreatedAt, rec.UpdatedAt,
	)
	return err
}

func (s *Store) DeleteRulePack(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM raiwall_rule_packs WHERE id = ?", id)
	return err
}

const ruleOverrideColumns = `canonical_id, enabled, severity, action, updated_by, updated_at`

func scanRuleOverride(scanner interface{ Scan(...any) error }) (control.RuleOverrideRecord, error) {
	var (
		rec     control.RuleOverrideRecord
		enabled sql.NullInt64
	)
	err := scanner.Scan(&rec.CanonicalID, &enabled, &rec.Severity, &rec.Action, &rec.UpdatedBy, &rec.UpdatedAt)
	if enabled.Valid {
		v := enabled.Int64 == 1
		rec.Enabled = &v
	}
	return rec, err
}

func (s *Store) ListRuleOverrides(ctx context.Context) ([]control.RuleOverrideRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT "+ruleOverrideColumns+" FROM raiwall_rule_overrides ORDER BY canonical_id ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []control.RuleOverrideRecord
	for rows.Next() {
		rec, err := scanRuleOverride(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, rec)
	}
	return result, rows.Err()
}

func (s *Store) GetRuleOverride(ctx context.Context, canonicalID string) (control.RuleOverrideRecord, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT "+ruleOverrideColumns+" FROM raiwall_rule_overrides WHERE canonical_id = ?", canonicalID)
	return scanRuleOverride(row)
}

func (s *Store) UpsertRuleOverride(ctx context.Context, rec control.RuleOverrideRecord) error {
	if rec.UpdatedAt.IsZero() {
		rec.UpdatedAt = time.Now().UTC()
	}
	var enabled any
	if rec.Enabled != nil {
		enabled = boolToInt(*rec.Enabled)
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO raiwall_rule_overrides (canonical_id, enabled, severity, action, updated_by, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(canonical_id) DO UPDATE SET
			enabled = excluded.enabled,
			severity = excluded.severity,
			action = excluded.action,
			updated_by = excluded.updated_by,
			updated_at = excluded.updated_at`,
		rec.CanonicalID, enabled, rec.Severity, rec.Action, rec.UpdatedBy, rec.UpdatedAt,
	)
	return err
}

func (s *Store) DeleteRuleOverride(ctx context.Context, canonicalID string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM raiwall_rule_overrides WHERE canonical_id = ?", canonicalID)
	return err
}

func (s *Store) ClearRuleOverrides(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM raiwall_rule_overrides")
	return err
}

const wafPolicyColumns = `id, scope, app_id, detection_mode, sensitivity, semantic_overrides,
	crs_enabled, crs_paranoia_level, crs_inbound_threshold, crs_outbound_threshold,
	disabled_pack_ids, updated_at`

func scanWAFPolicy(scanner interface{ Scan(...any) error }) (control.WAFPolicyRecord, error) {
	var (
		rec         control.WAFPolicyRecord
		crsOn       sql.NullInt64
		pl, in, out sql.NullInt64
	)
	err := scanner.Scan(
		&rec.ID, &rec.Scope, &rec.AppID, &rec.DetectionMode, &rec.Sensitivity,
		&rec.SemanticOverrides, &crsOn, &pl, &in, &out, &rec.DisabledPackIDs, &rec.UpdatedAt,
	)
	if crsOn.Valid {
		v := crsOn.Int64 == 1
		rec.CRSEnabled = &v
	}
	rec.CRSParanoiaLevel = nullIntPtr(pl)
	rec.CRSInboundThreshold = nullIntPtr(in)
	rec.CRSOutboundThreshold = nullIntPtr(out)
	return rec, err
}

func (s *Store) ListWAFPolicies(ctx context.Context) ([]control.WAFPolicyRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT "+wafPolicyColumns+" FROM raiwall_waf_policies ORDER BY scope ASC, app_id ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []control.WAFPolicyRecord
	for rows.Next() {
		rec, err := scanWAFPolicy(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, rec)
	}
	return result, rows.Err()
}

func (s *Store) GetWAFPolicy(ctx context.Context, scope, appID string) (control.WAFPolicyRecord, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT "+wafPolicyColumns+" FROM raiwall_waf_policies WHERE scope = ? AND app_id = ?",
		scope, appID)
	return scanWAFPolicy(row)
}

func (s *Store) UpsertWAFPolicy(ctx context.Context, rec control.WAFPolicyRecord) error {
	if rec.UpdatedAt.IsZero() {
		rec.UpdatedAt = time.Now().UTC()
	}
	var crsEnabled any
	if rec.CRSEnabled != nil {
		crsEnabled = boolToInt(*rec.CRSEnabled)
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO raiwall_waf_policies (
			id, scope, app_id, detection_mode, sensitivity, semantic_overrides,
			crs_enabled, crs_paranoia_level, crs_inbound_threshold, crs_outbound_threshold,
			disabled_pack_ids, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(scope, app_id) DO UPDATE SET
			detection_mode = excluded.detection_mode,
			sensitivity = excluded.sensitivity,
			semantic_overrides = excluded.semantic_overrides,
			crs_enabled = excluded.crs_enabled,
			crs_paranoia_level = excluded.crs_paranoia_level,
			crs_inbound_threshold = excluded.crs_inbound_threshold,
			crs_outbound_threshold = excluded.crs_outbound_threshold,
			disabled_pack_ids = excluded.disabled_pack_ids,
			updated_at = excluded.updated_at`,
		rec.ID, rec.Scope, rec.AppID, rec.DetectionMode, rec.Sensitivity, rec.SemanticOverrides,
		crsEnabled, intPtrValue(rec.CRSParanoiaLevel), intPtrValue(rec.CRSInboundThreshold),
		intPtrValue(rec.CRSOutboundThreshold), rec.DisabledPackIDs, rec.UpdatedAt,
	)
	return err
}

func (s *Store) DeleteWAFPolicy(ctx context.Context, scope, appID string) error {
	_, err := s.db.ExecContext(ctx,
		"DELETE FROM raiwall_waf_policies WHERE scope = ? AND app_id = ?", scope, appID)
	return err
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func nullIntPtr(v sql.NullInt64) *int {
	if !v.Valid {
		return nil
	}
	out := int(v.Int64)
	return &out
}

func intPtrValue(v *int) any {
	if v == nil {
		return nil
	}
	return *v
}
