import type { ForensicEvent, AggregateStats } from '@/types/telemetry';
import type { RuleTestRequest, RuleTestResult } from '@/types/rules';

export interface Site {
  id: string;
  name: string;
  description?: string;
  hostnames: string[];
  mode: 'defense' | 'audit' | 'offline';
  ports: ListeningPort[];
  ssl_mode: 'none' | 'auto' | 'manual';
  certificate_id?: string;
  routing_type: 'proxy' | 'static' | 'redirect';
  document_root?: string;
  redirect_url?: string;
  redirect_status?: number;
  load_balancing: 'round_robin' | 'least_conn' | 'ip_hash' | 'primary_backup';
  upstreams: Upstream[];
  block_status_code: number;
  block_response_body?: string;
  offline_status_code: number;
  offline_response_body?: string;
  custom_headers?: Record<string, string>;
  // Zero-trust HTTP 467 gate (unified SSO clearance)
  auth_enabled?: boolean;
  auth_bypass_paths?: string[];
  proxy_settings?: ProxySettings;
  forwarding_rules?: ForwardingRule[];
  created_at?: string;
  updated_at?: string;
}

// Listening ports are declarative metadata: the data plane binds fixed shared
// listeners (:8080 / :8443) and uses these for validation and reporting.
export interface ListeningPort {
  port: number;
  scheme: 'http' | 'https';
}

export type CertificateSource = 'upload' | 'self_signed' | 'acme';
export type CertificateStatus = 'valid' | 'expiring' | 'expired' | 'pending';

export interface ManagedCertificate {
  id: string;
  name: string;
  domains: string[];
  source: CertificateSource;
  cert_pem?: string;
  fingerprint_sha256?: string;
  issuer?: string;
  not_before?: string;
  not_after?: string;
  auto_renew: boolean;
  last_error?: string;
  status: CertificateStatus;
  created_at: string;
  updated_at: string;
}

export interface CertificatePayload {
  name?: string;
  domains: string[];
  source: CertificateSource;
  cert_pem?: string;
  key_pem?: string;
  auto_renew?: boolean;
}

export interface Upstream {
  dial: string;
  weight: number;
  health_check_path?: string;
  interval?: string;
  fail_timeout?: string;
}

export interface ForwardingRule {
  id: string;
  app_id: string;
  prefix: string;
  upstreams: Upstream[];
  strip_prefix: boolean;
  host_header_override: string;
  comment: string;
  is_active: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface APIResource {
  id: string;
  app_id: string;
  method: string;
  path_pattern: string;
  content_type: string;
  hit_count: number;
  last_seen?: string;
  created_at?: string;
}

export interface ProxySettings {
  client_ip_source?: string;
  rewrite_xff?: boolean;
  hsts?: boolean;
  enable_sse?: boolean;
  enable_compression?: boolean;
  enable_ipv6?: boolean;
  redirect_http?: boolean;
}

export interface ExceptionRule {
  id: string;
  app_id?: string;
  host: string;
  path: string;
  method: string;
  location: string;
  param_name: string;
  reason: string;
  rule_id: string;
  created_at?: string;
}

export interface ACLRule {
  id: string;
  name: string;
  expression: string;
  action: 'block' | 'allow' | 'redirect';
  redirect_url?: string;
  priority: number;
  enabled: boolean;
  is_active?: boolean;
  continue_inspection?: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface BanEntry {
  key: string;
  client_ip?: string;
  ja4?: string;
  reason: string;
  site_id?: string;
  duration?: number;
  remaining_seconds: number;
  banned_at: string;
  expires_at: string;
}

export interface WaitingRoomMetrics {
  active_in_flight: number;
  total_waiting: number;
  peak_queue_depth: number;
  avg_wait_seconds: number;
  bounce_rate: number;
  total_admitted: number;
  total_enqueued: number;
  total_abandoned: number;
}

export interface PolicySettings {
  tier1_rate: number;
  tier1_burst: number;
  tier2_threshold: number;
  tier2_ban_seconds: number;
  tier3_threshold: number;
  tier3_ban_seconds: number;
  bot_defense_mode: 'off' | 'audit' | 'challenge' | 'defense';
  pow_difficulty: number;
  honeypot_enabled: boolean;
  waiting_room_enabled: boolean;
  waiting_room_max_concurrent: number;
  waiting_room_paths?: string[];
}

export interface ApiKeyItem {
  id: string;
  name: string;
  prefix: string;
  role: 'admin' | 'viewer';
  created_at: string;
  expires_at?: string;
}

export interface AdminUser {
  id: string;
  username: string;
  role: 'admin' | 'viewer';
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface AdminUserResponse {
  user: AdminUser;
  password?: string;
}

export interface AuditEvent {
  id: string;
  occurred_at: string;
  actor_type: string;
  actor_id?: string;
  actor_name?: string;
  role?: string;
  action: string;
  target_type?: string;
  target_id?: string;
  method?: string;
  path?: string;
  status_code?: number;
  request_id?: string;
  client_ip?: string;
  user_agent?: string;
  snapshot_version?: number;
  detail?: string;
}

export interface AuditQuery {
  from?: string;
  to?: string;
  actor?: string;
  action?: string;
  limit?: number;
  offset?: number;
}

export interface ConfigDiffItem {
  type: 'site' | 'exception' | 'acl' | 'policy';
  action: 'added' | 'modified' | 'deleted';
  name: string;
  details: string;
}

export interface ConfigHistoryItem {
  version: number;
  author: string;
  description: string;
  applied_at: string;
  hash: string;
}

export interface SystemStatus {
  status: string;
  active_version: number;
  mode: string;
  auto_apply: boolean;
  timestamp: string;
}

export interface UserSession {
  username: string;
  role: 'admin' | 'viewer';
}

export interface EventQueryParams {
  limit?: number;
  offset?: number;
  client_ip?: string;
  action?: string;
  rule_id?: string;
  country?: string;
  min_severity?: string;
  start_time?: string;
  end_time?: string;
}

export interface EventsQueryResult {
  events: ForensicEvent[];
  total: number;
  limit: number;
  offset: number;
}

const API_BASE = '/.raiwall/api/v1';

export async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers || {});
  if (!headers.has('Content-Type') && options.body && typeof options.body === 'string') {
    headers.set('Content-Type', 'application/json');
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
    credentials: 'include',
  });

  const contentType = response.headers.get('content-type') || '';
  const isJson = contentType.includes('application/json');

  if (!response.ok) {
    let errorDetail = response.statusText;
    if (isJson) {
      try {
        const errorJson = await response.json();
        errorDetail = errorJson.message || errorJson.error || JSON.stringify(errorJson);
      } catch {
        // ignore
      }
    } else {
      const text = await response.text();
      if (text.includes('<!doctype') || text.includes('<html')) {
        errorDetail = 'Backend server returned HTML. Ensure Raiwall backend is running on :8080.';
      } else if (text) {
        errorDetail = text.slice(0, 150);
      }
    }
    throw new Error(`API error (${response.status}): ${errorDetail}`);
  }

  if (response.status === 204) {
    return {} as T;
  }

  if (!isJson) {
    const text = await response.text();
    if (text.includes('<!doctype') || text.includes('<html')) {
      throw new Error(
        'Backend server unavailable: received HTML response instead of JSON. Ensure the Raiwall backend server is running on :8080 ("go run ./cmd/raiwall" or "make run").'
      );
    }
    throw new Error(`Unexpected non-JSON content-type received from backend (${contentType || 'unknown'})`);
  }

  return response.json();
}

// requestBlob downloads a non-JSON payload (certificate PEM) while reusing the
// same auth/credential handling as request().
export async function requestBlob(endpoint: string, options: RequestInit = {}): Promise<Blob> {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    credentials: 'include',
  });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = body.message || body.error || JSON.stringify(body);
    } catch {
      // ignore non-JSON error bodies
    }
    throw new Error(`API error (${response.status}): ${detail}`);
  }
  return response.blob();
}

export const api = {
  // Auth
  getMe: () => request<UserSession>('/auth/me'),
  login: (credentials: { username: string; password: string }) =>
    request<UserSession>('/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    }),
  logout: () =>
    request<{ success: boolean }>('/auth/logout', {
      method: 'POST',
    }),

  // Sites
  listSites: () => request<Site[]>('/sites'),
  createSite: (site: Partial<Site>) =>
    request<Site>('/sites', {
      method: 'POST',
      body: JSON.stringify(site),
    }),
  updateSite: (id: string, site: Partial<Site>) =>
    request<Site>(`/sites/${id}`, {
      method: 'PUT',
      body: JSON.stringify(site),
    }),
  deleteSite: (id: string) =>
    request<void>(`/sites/${id}`, {
      method: 'DELETE',
    }),

  // TLS certificates (private keys are never returned by the API)
  listCertificates: () => request<ManagedCertificate[]>('/certificates'),
  getCertificate: (id: string) => request<ManagedCertificate>(`/certificates/${id}`),
  createCertificate: (payload: CertificatePayload) =>
    request<ManagedCertificate>('/certificates', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  updateCertificate: (id: string, payload: Partial<CertificatePayload>) =>
    request<ManagedCertificate>(`/certificates/${id}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),
  deleteCertificate: (id: string) =>
    request<void>(`/certificates/${id}`, {
      method: 'DELETE',
    }),
  renewCertificate: (id: string) =>
    request<ManagedCertificate>(`/certificates/${id}/renew`, {
      method: 'POST',
    }),
  downloadCertificate: (id: string) => requestBlob(`/certificates/${id}/download`),

  // Forwarding rules (path-prefix routing)
  listForwardingRules: (siteId: string) => request<ForwardingRule[]>(`/sites/${siteId}/forwarding-rules`),
  createForwardingRule: (siteId: string, rule: Partial<ForwardingRule>) =>
    request<ForwardingRule>(`/sites/${siteId}/forwarding-rules`, {
      method: 'POST',
      body: JSON.stringify(rule),
    }),
  updateForwardingRule: (siteId: string, ruleId: string, rule: Partial<ForwardingRule>) =>
    request<ForwardingRule>(`/sites/${siteId}/forwarding-rules/${ruleId}`, {
      method: 'PUT',
      body: JSON.stringify(rule),
    }),
  deleteForwardingRule: (siteId: string, ruleId: string) =>
    request<{ status: string }>(`/sites/${siteId}/forwarding-rules/${ruleId}`, {
      method: 'DELETE',
    }),

  // Auto-discovered API inventory
  listAPIResources: (siteId: string) => request<APIResource[]>(`/sites/${siteId}/resources`),
  deleteAPIResource: (siteId: string, resourceId: string) =>
    request<{ status: string }>(`/sites/${siteId}/resources/${resourceId}`, {
      method: 'DELETE',
    }),

  // Exceptions
  listExceptions: () => request<ExceptionRule[]>('/exceptions'),
  createException: (rule: Partial<ExceptionRule>) =>
    request<ExceptionRule>('/exceptions', {
      method: 'POST',
      body: JSON.stringify(rule),
    }),
  deleteException: (id: string) =>
    request<void>(`/exceptions/${id}`, {
      method: 'DELETE',
    }),
  dryRunException: (payload: { rule: Partial<ExceptionRule>; request: { host: string; path: string; method: string; params: Record<string, string> } }) =>
    request<{
      matched: boolean;
      reason: string;
      effects?: { engine: string; directive?: string; detail: string }[];
    }>('/exceptions/dry-run', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  // ACLs
  listACLs: () => request<ACLRule[]>('/acls'),
  createACL: (rule: Partial<ACLRule>) =>
    request<ACLRule>('/acls', {
      method: 'POST',
      body: JSON.stringify(rule),
    }),
  updateACL: (id: string, rule: Partial<ACLRule>) =>
    request<ACLRule>(`/acls/${id}`, {
      method: 'PUT',
      body: JSON.stringify(rule),
    }),
  deleteACL: (id: string) =>
    request<void>(`/acls/${id}`, {
      method: 'DELETE',
    }),
  dryRunACL: (payload: { expression: string; request: Record<string, unknown> }) =>
    request<{ valid: boolean; error?: string; matched?: boolean }>('/acls/dry-run', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  // Policies
  getPolicies: () => request<PolicySettings>('/policies'),
  updatePolicies: (policies: Partial<PolicySettings>) =>
    request<PolicySettings>('/policies', {
      method: 'PUT',
      body: JSON.stringify(policies),
    }),

  // Bans & Active Volumetric Defense
  listBans: () => request<BanEntry[]>('/rate/bans'),
  releaseBan: (payload: { key?: string; ip?: string }) =>
    request<{ status: string; target: string; released: boolean }>('/rate/bans/release', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  releaseAllBans: () =>
    request<{ status: string; cleared: number }>('/rate/bans/release-all', {
      method: 'POST',
    }),
  getWaitingRoomMetrics: () => request<WaitingRoomMetrics>('/waiting-room/metrics'),

  // API Keys
  listApiKeys: () => request<ApiKeyItem[]>('/apikeys'),
  createApiKey: (key: { name: string; role: 'admin' | 'viewer'; expires_in_days?: number }) =>
    request<{ id: string; name: string; token: string }>('/apikeys', {
      method: 'POST',
      body: JSON.stringify(key),
    }),
  deleteApiKey: (id: string) =>
    request<void>(`/apikeys/${id}`, {
      method: 'DELETE',
    }),

  // Operators (dashboard users)
  listAdminUsers: () => request<AdminUser[]>('/users'),
  createAdminUser: (payload: { username: string; password?: string; role: 'admin' | 'viewer' }) =>
    request<AdminUserResponse>('/users', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  updateAdminUser: (id: string, payload: { role?: 'admin' | 'viewer'; is_active?: boolean }) =>
    request<AdminUserResponse>(`/users/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),
  resetAdminUserPassword: (id: string, password?: string) =>
    request<AdminUserResponse>(`/users/${id}/password`, {
      method: 'POST',
      body: JSON.stringify({ password: password ?? '' }),
    }),
  revokeAdminUserSessions: (id: string) =>
    request<{ status: string }>(`/users/${id}/sessions/revoke`, {
      method: 'POST',
    }),
  deactivateAdminUser: (id: string) =>
    request<AdminUserResponse>(`/users/${id}`, {
      method: 'DELETE',
    }),

  // Audit log
  listAuditEvents: (query: AuditQuery = {}) => {
    const params = new URLSearchParams();
    if (query.from) params.set('from', query.from);
    if (query.to) params.set('to', query.to);
    if (query.actor) params.set('actor', query.actor);
    if (query.action) params.set('action', query.action);
    if (query.limit) params.set('limit', String(query.limit));
    if (query.offset) params.set('offset', String(query.offset));
    const suffix = params.toString();
    return request<{ events: AuditEvent[]; limit: number; offset: number }>(
      `/audit${suffix ? `?${suffix}` : ''}`
    );
  },

  // Deployments & Config
  getDraftDiff: () => request<{ has_changes: boolean; diffs: ConfigDiffItem[] }>('/config/draft/diff'),
  applyConfig: (payload: { author: string; description: string }) =>
    request<{ version: number; hash: string }>('/config/apply', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  rollbackConfig: (version: number) =>
    request<{ success: boolean; version: number }>(`/config/rollback/${version}`, {
      method: 'POST',
    }),
  getConfigHistory: () => request<ConfigHistoryItem[]>('/config/history'),

  // Rule testing
  testRule: (payload: RuleTestRequest) =>
    request<RuleTestResult>('/rules/test', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  getClusterStatus: () =>
    request<{
      mode: string;
      redis_connected: boolean;
      active_version: number;
      channel: string;
      applied_version?: number;
      applied_hash?: string;
      last_apply_error?: string;
      ban_count?: number;
    }>('/cluster/status'),
  getStatus: () => request<SystemStatus>('/status'),
  setAutoApply: (enabled: boolean) =>
    request<{ success: boolean; auto_apply: boolean }>('/system/auto-apply', {
      method: 'PUT',
      body: JSON.stringify({ auto_apply: enabled }),
    }),

  // Telemetry
  listEvents: (params?: EventQueryParams) => {
    const q = new URLSearchParams();
    if (params?.limit != null) q.set('limit', params.limit.toString());
    if (params?.offset != null) q.set('offset', params.offset.toString());
    if (params?.client_ip) q.set('client_ip', params.client_ip);
    if (params?.action) q.set('action', params.action);
    if (params?.rule_id) q.set('rule_id', params.rule_id);
    if (params?.country) q.set('country', params.country);
    if (params?.min_severity) q.set('min_severity', params.min_severity);
    if (params?.start_time) q.set('start_time', params.start_time);
    if (params?.end_time) q.set('end_time', params.end_time);
    const qs = q.toString();
    return request<EventsQueryResult>(`/telemetry/events${qs ? '?' + qs : ''}`);
  },
  getStats: (startTime?: string, endTime?: string) => {
    const q = new URLSearchParams();
    if (startTime) q.set('start_time', startTime);
    if (endTime) q.set('end_time', endTime);
    const qs = q.toString();
    return request<AggregateStats>(`/telemetry/events/stats${qs ? '?' + qs : ''}`);
  },
};
