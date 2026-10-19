export interface Site {
  id: string;
  name: string;
  hostnames: string[];
  mode: 'defense' | 'audit' | 'offline';
  upstreams: Upstream[];
  block_status_code: number;
  block_response_body?: string;
  offline_status_code: number;
  offline_response_body?: string;
  custom_headers?: Record<string, string>;
}

export interface Upstream {
  dial: string;
  weight: number;
  health_check_path?: string;
  interval?: string;
  fail_timeout?: string;
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
}

export interface ApiKeyItem {
  id: string;
  name: string;
  prefix: string;
  role: 'admin' | 'viewer';
  created_at: string;
  expires_at?: string;
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

export interface UserSession {
  username: string;
  role: 'admin' | 'viewer';
}

const API_BASE = '/.raiwall/api/v1';

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers || {});
  if (!headers.has('Content-Type') && options.body && typeof options.body === 'string') {
    headers.set('Content-Type', 'application/json');
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
    credentials: 'include',
  });

  if (!response.ok) {
    let errorDetail = response.statusText;
    try {
      const errorJson = await response.json();
      errorDetail = errorJson.message || errorJson.error || JSON.stringify(errorJson);
    } catch {
      // ignore
    }
    throw new Error(`API error (${response.status}): ${errorDetail}`);
  }

  if (response.status === 204) {
    return {} as T;
  }

  return response.json();
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
    request<{ matched: boolean; reason: string }>('/exceptions/dry-run', {
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
  getClusterStatus: () =>
    request<{ mode: string; redis_connected: boolean; active_version: number; channel: string }>('/cluster/status'),
};
