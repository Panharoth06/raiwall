-- name: ListApps :many
SELECT * FROM raiwall_apps ORDER BY name ASC;

-- name: GetApp :one
SELECT * FROM raiwall_apps WHERE id = ? LIMIT 1;

-- name: CreateApp :exec
INSERT INTO raiwall_apps (
    id, name, hostnames, mode, upstreams, block_status_code, block_response_body,
    offline_status_code, offline_response_body, custom_headers, proxy_settings,
    auth_enabled, auth_bypass_paths, description, ports, ssl_mode, certificate_id,
    routing_type, document_root, redirect_url, redirect_status, load_balancing,
    created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateApp :exec
UPDATE raiwall_apps SET
    name = ?, hostnames = ?, mode = ?, upstreams = ?, block_status_code = ?,
    block_response_body = ?, offline_status_code = ?, offline_response_body = ?,
    custom_headers = ?, proxy_settings = ?, auth_enabled = ?, auth_bypass_paths = ?,
    description = ?, ports = ?, ssl_mode = ?, certificate_id = ?, routing_type = ?,
    document_root = ?, redirect_url = ?, redirect_status = ?, load_balancing = ?,
    updated_at = ?
WHERE id = ?;

-- name: DeleteApp :exec
DELETE FROM raiwall_apps WHERE id = ?;

-- name: ListExceptions :many
SELECT * FROM raiwall_exceptions ORDER BY created_at DESC;

-- name: ListActiveExceptions :many
SELECT * FROM raiwall_exceptions WHERE is_active = 1 ORDER BY created_at DESC;

-- name: GetException :one
SELECT * FROM raiwall_exceptions WHERE id = ? LIMIT 1;

-- name: CreateException :exec
INSERT INTO raiwall_exceptions (
    id, description, host, path_regex, path_prefix, method, location,
    param_name, param_regex, rule_id, is_active, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateException :exec
UPDATE raiwall_exceptions SET
    description = ?, host = ?, path_regex = ?, path_prefix = ?, method = ?,
    location = ?, param_name = ?, param_regex = ?, rule_id = ?, is_active = ?,
    updated_at = ?
WHERE id = ?;

-- name: DeleteException :exec
DELETE FROM raiwall_exceptions WHERE id = ?;

-- name: ListACLRules :many
SELECT * FROM raiwall_acl_rules ORDER BY priority DESC, created_at ASC;

-- name: ListActiveACLRules :many
SELECT * FROM raiwall_acl_rules WHERE is_active = 1 ORDER BY priority DESC, created_at ASC;

-- name: GetACLRule :one
SELECT * FROM raiwall_acl_rules WHERE id = ? LIMIT 1;

-- name: CreateACLRule :exec
INSERT INTO raiwall_acl_rules (
    id, name, expression, action, priority, status_code, redirect_url, is_active, continue_inspection, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateACLRule :exec
UPDATE raiwall_acl_rules SET
    name = ?, expression = ?, action = ?, priority = ?, status_code = ?,
    redirect_url = ?, is_active = ?, continue_inspection = ?, updated_at = ?
WHERE id = ?;

-- name: DeleteACLRule :exec
DELETE FROM raiwall_acl_rules WHERE id = ?;

-- name: ListRatePolicies :many
SELECT * FROM raiwall_rate_policies ORDER BY created_at DESC;

-- name: ListActiveRatePolicies :many
SELECT * FROM raiwall_rate_policies WHERE is_active = 1 ORDER BY created_at DESC;

-- name: GetRatePolicy :one
SELECT * FROM raiwall_rate_policies WHERE id = ? LIMIT 1;

-- name: CreateRatePolicy :exec
INSERT INTO raiwall_rate_policies (
    id, name, host, tier1_rate, tier1_burst, tier1_period_sec,
    tier2_threshold, tier2_period_sec, tier2_ban_duration_sec,
    tier3_threshold, tier3_ban_duration_sec, waiting_room_enabled,
    waiting_room_capacity, waiting_room_paths, is_active, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateRatePolicy :exec
UPDATE raiwall_rate_policies SET
    name = ?, host = ?, tier1_rate = ?, tier1_burst = ?, tier1_period_sec = ?,
    tier2_threshold = ?, tier2_period_sec = ?, tier2_ban_duration_sec = ?,
    tier3_threshold = ?, tier3_ban_duration_sec = ?, waiting_room_enabled = ?,
    waiting_room_capacity = ?, waiting_room_paths = ?, is_active = ?, updated_at = ?
WHERE id = ?;

-- name: DeleteRatePolicy :exec
DELETE FROM raiwall_rate_policies WHERE id = ?;

-- name: ListBotConfigs :many
SELECT * FROM raiwall_bot_configs ORDER BY created_at DESC;

-- name: ListActiveBotConfigs :many
SELECT * FROM raiwall_bot_configs WHERE is_active = 1 ORDER BY created_at DESC;

-- name: GetBotConfig :one
SELECT * FROM raiwall_bot_configs WHERE id = ? LIMIT 1;

-- name: CreateBotConfig :exec
INSERT INTO raiwall_bot_configs (
    id, host, pow_enabled, pow_difficulty, trap_urls, is_active, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateBotConfig :exec
UPDATE raiwall_bot_configs SET
    host = ?, pow_enabled = ?, pow_difficulty = ?, trap_urls = ?,
    is_active = ?, updated_at = ?
WHERE id = ?;

-- name: DeleteBotConfig :exec
DELETE FROM raiwall_bot_configs WHERE id = ?;

-- name: CreateSnapshot :one
INSERT INTO raiwall_config_snapshots (
    snapshot_data, author, description, created_at
) VALUES (?, ?, ?, ?)
RETURNING version, snapshot_data, author, description, created_at;

-- name: GetSnapshotByVersion :one
SELECT * FROM raiwall_config_snapshots WHERE version = ? LIMIT 1;

-- name: GetLatestSnapshot :one
SELECT * FROM raiwall_config_snapshots ORDER BY version DESC LIMIT 1;

-- name: ListSnapshots :many
SELECT * FROM raiwall_config_snapshots ORDER BY version DESC;

-- name: ListUsers :many
SELECT * FROM raiwall_users ORDER BY username ASC;

-- name: GetUserByID :one
SELECT * FROM raiwall_users WHERE id = ? LIMIT 1;

-- name: GetUserByUsername :one
SELECT * FROM raiwall_users WHERE username = ? LIMIT 1;

-- name: CreateUser :exec
INSERT INTO raiwall_users (
    id, username, password_hash, role, is_active, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: UpdateUser :exec
UPDATE raiwall_users SET
    password_hash = ?, role = ?, is_active = ?, updated_at = ?
WHERE id = ?;

-- name: DeleteUser :exec
DELETE FROM raiwall_users WHERE id = ?;

-- name: ListAPIKeys :many
SELECT * FROM raiwall_api_keys ORDER BY created_at DESC;

-- name: GetAPIKeyByID :one
SELECT * FROM raiwall_api_keys WHERE id = ? LIMIT 1;

-- name: GetAPIKeyByHash :one
SELECT * FROM raiwall_api_keys WHERE key_hash = ? AND is_active = 1 LIMIT 1;

-- name: CreateAPIKey :exec
INSERT INTO raiwall_api_keys (
    id, name, key_hash, role, expires_at, is_active, created_at, last_used_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateAPIKeyLastUsed :exec
UPDATE raiwall_api_keys SET last_used_at = ? WHERE id = ?;

-- name: DeleteAPIKey :exec
DELETE FROM raiwall_api_keys WHERE id = ?;

-- name: ListForwardingRules :many
SELECT * FROM raiwall_forwarding_rules ORDER BY prefix ASC;

-- name: ListForwardingRulesByApp :many
SELECT * FROM raiwall_forwarding_rules WHERE app_id = ? ORDER BY prefix ASC;

-- name: ListActiveForwardingRulesByApp :many
SELECT * FROM raiwall_forwarding_rules WHERE app_id = ? AND is_active = 1 ORDER BY prefix ASC;

-- name: ListAllActiveForwardingRules :many
SELECT * FROM raiwall_forwarding_rules WHERE is_active = 1 ORDER BY prefix ASC;

-- name: GetForwardingRule :one
SELECT * FROM raiwall_forwarding_rules WHERE id = ? LIMIT 1;

-- name: CreateForwardingRule :exec
INSERT INTO raiwall_forwarding_rules (
    id, app_id, prefix, upstreams, strip_prefix, host_header_override, comment, is_active, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateForwardingRule :exec
UPDATE raiwall_forwarding_rules SET
    prefix = ?, upstreams = ?, strip_prefix = ?, host_header_override = ?, comment = ?, is_active = ?, updated_at = ?
WHERE id = ?;

-- name: DeleteForwardingRule :exec
DELETE FROM raiwall_forwarding_rules WHERE id = ?;

-- name: DeleteForwardingRulesByApp :exec
DELETE FROM raiwall_forwarding_rules WHERE app_id = ?;

-- name: ListAPIResourcesByApp :many
SELECT * FROM raiwall_api_resources WHERE app_id = ? ORDER BY hit_count DESC, last_seen DESC;

-- name: GetAPIResource :one
SELECT * FROM raiwall_api_resources WHERE id = ? LIMIT 1;

-- name: UpsertAPIResource :exec
INSERT INTO raiwall_api_resources (
    id, app_id, method, path_pattern, content_type, hit_count, last_seen, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(app_id, method, path_pattern) DO UPDATE SET
    hit_count = raiwall_api_resources.hit_count + excluded.hit_count,
    content_type = CASE WHEN excluded.content_type != '' THEN excluded.content_type ELSE raiwall_api_resources.content_type END,
    last_seen = excluded.last_seen;

-- name: DeleteAPIResource :exec
DELETE FROM raiwall_api_resources WHERE id = ?;

-- name: DeleteAPIResourcesByApp :exec
DELETE FROM raiwall_api_resources WHERE app_id = ?;


-- name: FetchCertificates :many
SELECT * FROM raiwall_certificates ORDER BY name ASC;

-- name: FetchCertificate :one
SELECT * FROM raiwall_certificates WHERE id = ? LIMIT 1;

-- name: InsertCertificate :exec
INSERT INTO raiwall_certificates (
    id, name, domains, source, cert_pem, encrypted_key_pem, fingerprint_sha256,
    issuer, not_before, not_after, auto_renew, acme_staging, last_error,
    created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ModifyCertificate :exec
UPDATE raiwall_certificates SET
    name = ?, domains = ?, source = ?, cert_pem = ?, encrypted_key_pem = ?,
    fingerprint_sha256 = ?, issuer = ?, not_before = ?, not_after = ?,
    auto_renew = ?, acme_staging = ?, last_error = ?, updated_at = ?
WHERE id = ?;

-- name: RemoveCertificate :exec
DELETE FROM raiwall_certificates WHERE id = ?;
