// Detection workspace API: status, global/per-site policy, and presets.

export type DetectionMode = 'inherit' | 'off' | 'alert' | 'block';
export type Sensitivity = 'inherit' | 'low' | 'medium' | 'high';
export type ModuleMode = 'disabled' | 'audit' | 'balance' | 'strict';

export interface CRSPolicy {
  enabled?: boolean;
  paranoia_level?: number;
  inbound_threshold?: number;
  outbound_threshold?: number;
}

export interface WAFPolicy {
  detection_mode: DetectionMode;
  sensitivity: Sensitivity;
  semantic_overrides?: Record<string, ModuleMode>;
  crs?: CRSPolicy;
  disabled_packs?: string[];
}

export interface DetectionStatus {
  snapshot_version: number;
  detection_mode: string;
  sensitivity: string;
  crs_enabled: boolean;
  crs_engine_available: boolean;
  rule_packs: number;
  rule_overrides: number;
  exceptions: number;
  disabled_rules: number;
  sources: string[];
}

export interface AppDetectionPolicy {
  app_id: string;
  name: string;
  policy: WAFPolicy;
  raw: WAFPolicy;
  overridden: boolean;
}

export interface PolicyResponse {
  policy: WAFPolicy;
  resolved: WAFPolicy;
}

export interface DetectionPreset {
  id: Sensitivity;
  description: string;
  modules: Record<string, ModuleMode>;
  crs: {
    paranoia_level: number;
    inbound_threshold: number;
    outbound_threshold: number;
  };
}

export interface DetectionRule {
  id: string;
  source: string;
  pack_id?: string;
  pack_name?: string;
  name: string;
  category: string;
  severity: string;
  default_severity: string;
  action: string;
  default_action: string;
  enabled: boolean;
  overridden: boolean;
  phase?: number;
  methods?: string[];
  prefix?: string;
  description?: string;
}

export interface RuleFacet {
  value: string;
  count: number;
}

export interface RuleFacets {
  sources: RuleFacet[];
  categories: RuleFacet[];
  severities: RuleFacet[];
  packs: RuleFacet[];
}

export interface RuleCatalogResponse {
  rules: DetectionRule[];
  total: number;
  offset: number;
  limit: number;
  facets: RuleFacets;
}

export interface RuleFilters {
  q: string;
  source: string;
  category: string;
  severity: string;
  enabled: string;
}

export interface RuleOverride {
  enabled?: boolean;
  action?: string;
  severity?: string;
}

export interface DetectionRulePack {
  id: string;
  name: string;
  version: string;
  type: string;
  relation: string;
  enabled: boolean;
  priority: number;
  rules_count: number;
  status: string;
  builtin?: boolean;
  updated_at: string;
}

export interface RulePackValidation {
  valid: boolean;
  rules_parsed: number;
  errors?: string[];
  warnings?: string[];
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
    const text = await response.text();
    let message = `HTTP ${response.status}: ${response.statusText}`;
    try {
      const err = JSON.parse(text);
      if (err.error) message = err.error;
    } catch {
      if (text) message = text.slice(0, 200);
    }
    throw new Error(message);
  }
  return response.json();
}

export const detectionApi = {
  getStatus: () => request<DetectionStatus>('/detection/status'),
  getPolicy: () => request<PolicyResponse>('/detection/policy'),
  setPolicy: (policy: WAFPolicy) =>
    request<{ success: boolean; policy: WAFPolicy }>('/detection/policy', {
      method: 'PUT',
      body: JSON.stringify(policy),
    }),
  listPresets: () => request<{ presets: DetectionPreset[] }>('/detection/presets'),
  listAppPolicies: () => request<{ policies: AppDetectionPolicy[] }>('/detection/policies/apps'),
  getAppPolicy: (appID: string) =>
    request<PolicyResponse & { app_id: string; name: string }>(
      `/detection/policies/apps/${encodeURIComponent(appID)}`
    ),
  setAppPolicy: (appID: string, policy: WAFPolicy) =>
    request<{ success: boolean; policy: WAFPolicy }>(
      `/detection/policies/apps/${encodeURIComponent(appID)}`,
      { method: 'PUT', body: JSON.stringify(policy) }
    ),
  resetAppPolicy: (appID: string) =>
    request<{ success: boolean; app_id: string }>(
      `/detection/policies/apps/${encodeURIComponent(appID)}`,
      { method: 'DELETE' }
    ),

  // Unified rule catalog.
  listRules: (params: RuleFilters & { offset?: number; limit?: number }) => {
    const query = new URLSearchParams();
    if (params.q) query.set('q', params.q);
    if (params.source) query.set('source', params.source);
    if (params.category) query.set('category', params.category);
    if (params.severity) query.set('severity', params.severity);
    if (params.enabled) query.set('enabled', params.enabled);
    if (params.offset !== undefined) query.set('offset', String(params.offset));
    if (params.limit !== undefined) query.set('limit', String(params.limit));
    return request<RuleCatalogResponse>(`/detection/rules?${query.toString()}`);
  },
  getRule: (canonicalID: string) =>
    request<DetectionRule>(`/detection/rules/${encodeURIComponent(canonicalID)}`),
  updateRule: (canonicalID: string, override: RuleOverride) =>
    request<{ success: boolean; id: string }>(
      `/detection/rules/${encodeURIComponent(canonicalID)}`,
      { method: 'PATCH', body: JSON.stringify(override) }
    ),
  resetRule: (canonicalID: string) =>
    request<{ success: boolean; id: string }>(
      `/detection/rules/${encodeURIComponent(canonicalID)}/override`,
      { method: 'DELETE' }
    ),
  bulkRules: (ids: string[], override: RuleOverride) =>
    request<{ success: boolean; updated: number }>('/detection/rules/bulk', {
      method: 'POST',
      body: JSON.stringify({ ids, ...override }),
    }),

  // Imported native rule packs.
  listPacks: () => request<{ packs: DetectionRulePack[] }>('/detection/packs'),
  validatePack: (payload: Record<string, unknown>) =>
    request<RulePackValidation>('/detection/packs/validate', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  createPack: (payload: Record<string, unknown>) =>
    request<{ success: boolean; pack: DetectionRulePack }>('/detection/packs', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  updatePack: (packID: string, patch: { enabled?: boolean; priority?: number }) =>
    request<{ success: boolean; pack: DetectionRulePack }>(
      `/detection/packs/${encodeURIComponent(packID)}`,
      { method: 'PUT', body: JSON.stringify(patch) }
    ),
  deletePack: (packID: string) =>
    request<{ success: boolean; id: string }>(
      `/detection/packs/${encodeURIComponent(packID)}`,
      { method: 'DELETE' }
    ),
};
