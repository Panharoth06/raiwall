package postgres

import (
	"context"
	"database/sql"
	"fmt"
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

func (s *ControlStore) ListRulePacks(ctx context.Context) ([]control.RulePackRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT "+rulePackColumns+" FROM raiwall_rule_packs ORDER BY priority ASC, name ASC")
	if err != nil {
		return nil, fmt.Errorf("list rule packs: %w", err)
	}
	defer rows.Close()

	var result []control.RulePackRecord
	for rows.Next() {
		rec, err := scanRulePack(rows)
		if err != nil {
			return nil, fmt.Errorf("scan rule pack: %w", err)
		}
		result = append(result, rec)
	}
	return result, rows.Err()
}

func (s *ControlStore) GetRulePack(ctx context.Context, id string) (control.RulePackRecord, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT "+rulePackColumns+" FROM raiwall_rule_packs WHERE id = $1", id)
	rec, err := scanRulePack(row)
	if err != nil {
		return control.RulePackRecord{}, fmt.Errorf("get rule pack: %w", err)
	}
	return rec, nil
}

func (s *ControlStore) UpsertRulePack(ctx context.Context, rec control.RulePackRecord) error {
	now := time.Now().UTC()
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = now
	}
	rec.UpdatedAt = now
	query := `INSERT INTO raiwall_rule_packs (
			id, name, version, type, priority, enabled, replace_builtin,
			rules_json, directives, files_json, checksum, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT(id) DO UPDATE SET
			name = EXCLUDED.name,
			version = EXCLUDED.version,
			type = EXCLUDED.type,
			priority = EXCLUDED.priority,
			enabled = EXCLUDED.enabled,
			replace_builtin = EXCLUDED.replace_builtin,
			rules_json = EXCLUDED.rules_json,
			directives = EXCLUDED.directives,
			files_json = EXCLUDED.files_json,
			checksum = EXCLUDED.checksum,
			updated_at = EXCLUDED.updated_at`
	_, err := s.db.ExecContext(ctx, query,
		rec.ID, rec.Name, rec.Version, rec.Type, rec.Priority,
		boolToInt(rec.Enabled), boolToInt(rec.ReplaceBuiltin),
		rec.RulesJSON, rec.Directives, rec.FilesJSON, rec.Checksum,
		rec.CreatedAt, rec.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("upsert rule pack: %w", err)
	}
	return nil
}

func (s *ControlStore) DeleteRulePack(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM raiwall_rule_packs WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("delete rule pack: %w", err)
	}
	return nil
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

func (s *ControlStore) ListRuleOverrides(ctx context.Context) ([]control.RuleOverrideRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT "+ruleOverrideColumns+" FROM raiwall_rule_overrides ORDER BY canonical_id ASC")
	if err != nil {
		return nil, fmt.Errorf("list rule overrides: %w", err)
	}
	defer rows.Close()

	var result []control.RuleOverrideRecord
	for rows.Next() {
		rec, err := scanRuleOverride(rows)
		if err != nil {
			return nil, fmt.Errorf("scan rule override: %w", err)
		}
		result = append(result, rec)
	}
	return result, rows.Err()
}

func (s *ControlStore) GetRuleOverride(ctx context.Context, canonicalID string) (control.RuleOverrideRecord, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT "+ruleOverrideColumns+" FROM raiwall_rule_overrides WHERE canonical_id = $1", canonicalID)
	rec, err := scanRuleOverride(row)
	if err != nil {
		return control.RuleOverrideRecord{}, fmt.Errorf("get rule override: %w", err)
	}
	return rec, nil
}

func (s *ControlStore) UpsertRuleOverride(ctx context.Context, rec control.RuleOverrideRecord) error {
	if rec.UpdatedAt.IsZero() {
		rec.UpdatedAt = time.Now().UTC()
	}
	var enabled any
	if rec.Enabled != nil {
		enabled = boolToInt(*rec.Enabled)
	}
	query := `INSERT INTO raiwall_rule_overrides
			(canonical_id, enabled, severity, action, updated_by, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT(canonical_id) DO UPDATE SET
			enabled = EXCLUDED.enabled,
			severity = EXCLUDED.severity,
			action = EXCLUDED.action,
			updated_by = EXCLUDED.updated_by,
			updated_at = EXCLUDED.updated_at`
	if _, err := s.db.ExecContext(ctx, query,
		rec.CanonicalID, enabled, rec.Severity, rec.Action, rec.UpdatedBy, rec.UpdatedAt,
	); err != nil {
		return fmt.Errorf("upsert rule override: %w", err)
	}
	return nil
}

func (s *ControlStore) DeleteRuleOverride(ctx context.Context, canonicalID string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM raiwall_rule_overrides WHERE canonical_id = $1", canonicalID)
	if err != nil {
		return fmt.Errorf("delete rule override: %w", err)
	}
	return nil
}

func (s *ControlStore) ClearRuleOverrides(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, "DELETE FROM raiwall_rule_overrides"); err != nil {
		return fmt.Errorf("clear rule overrides: %w", err)
	}
	return nil
}

const wafPolicyColumns = `id, scope, app_id, detection_mode, sensitivity, semantic_overrides,
	crs_enabled, crs_paranoia_level, crs_inbound_threshold, crs_outbound_threshold,
	disabled_pack_ids, response_json, updated_at`

func scanWAFPolicy(scanner interface{ Scan(...any) error }) (control.WAFPolicyRecord, error) {
	var (
		rec         control.WAFPolicyRecord
		crsOn       sql.NullInt64
		pl, in, out sql.NullInt64
	)
	err := scanner.Scan(
		&rec.ID, &rec.Scope, &rec.AppID, &rec.DetectionMode, &rec.Sensitivity,
		&rec.SemanticOverrides, &crsOn, &pl, &in, &out, &rec.DisabledPackIDs,
		&rec.ResponseJSON, &rec.UpdatedAt,
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

func (s *ControlStore) ListWAFPolicies(ctx context.Context) ([]control.WAFPolicyRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT "+wafPolicyColumns+" FROM raiwall_waf_policies ORDER BY scope ASC, app_id ASC")
	if err != nil {
		return nil, fmt.Errorf("list waf policies: %w", err)
	}
	defer rows.Close()

	var result []control.WAFPolicyRecord
	for rows.Next() {
		rec, err := scanWAFPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("scan waf policy: %w", err)
		}
		result = append(result, rec)
	}
	return result, rows.Err()
}

func (s *ControlStore) GetWAFPolicy(ctx context.Context, scope, appID string) (control.WAFPolicyRecord, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT "+wafPolicyColumns+" FROM raiwall_waf_policies WHERE scope = $1 AND app_id = $2",
		scope, appID)
	rec, err := scanWAFPolicy(row)
	if err != nil {
		return control.WAFPolicyRecord{}, fmt.Errorf("get waf policy: %w", err)
	}
	return rec, nil
}

func (s *ControlStore) UpsertWAFPolicy(ctx context.Context, rec control.WAFPolicyRecord) error {
	if rec.UpdatedAt.IsZero() {
		rec.UpdatedAt = time.Now().UTC()
	}
	var crsEnabled any
	if rec.CRSEnabled != nil {
		crsEnabled = boolToInt(*rec.CRSEnabled)
	}
	query := `INSERT INTO raiwall_waf_policies (
			id, scope, app_id, detection_mode, sensitivity, semantic_overrides,
			crs_enabled, crs_paranoia_level, crs_inbound_threshold, crs_outbound_threshold,
			disabled_pack_ids, response_json, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT(scope, app_id) DO UPDATE SET
			detection_mode = EXCLUDED.detection_mode,
			sensitivity = EXCLUDED.sensitivity,
			semantic_overrides = EXCLUDED.semantic_overrides,
			crs_enabled = EXCLUDED.crs_enabled,
			crs_paranoia_level = EXCLUDED.crs_paranoia_level,
			crs_inbound_threshold = EXCLUDED.crs_inbound_threshold,
			crs_outbound_threshold = EXCLUDED.crs_outbound_threshold,
			disabled_pack_ids = EXCLUDED.disabled_pack_ids,
			response_json = EXCLUDED.response_json,
			updated_at = EXCLUDED.updated_at`
	_, err := s.db.ExecContext(ctx, query,
		rec.ID, rec.Scope, rec.AppID, rec.DetectionMode, rec.Sensitivity, rec.SemanticOverrides,
		crsEnabled, intPtrValue(rec.CRSParanoiaLevel), intPtrValue(rec.CRSInboundThreshold),
		intPtrValue(rec.CRSOutboundThreshold), rec.DisabledPackIDs, rec.ResponseJSON, rec.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("upsert waf policy: %w", err)
	}
	return nil
}

func (s *ControlStore) DeleteWAFPolicy(ctx context.Context, scope, appID string) error {
	_, err := s.db.ExecContext(ctx,
		"DELETE FROM raiwall_waf_policies WHERE scope = $1 AND app_id = $2", scope, appID)
	if err != nil {
		return fmt.Errorf("delete waf policy: %w", err)
	}
	return nil
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
