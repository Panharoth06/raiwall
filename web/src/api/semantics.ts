// Semantic detection matrix and inner rules (CVE virtual patches) API.

export type ModuleMode = 'disabled' | 'audit' | 'balance' | 'strict';

export interface DetectorModule {
  module: string;
  name: string;
  category: string;
  description: string;
  mode: ModuleMode;
}

export interface DetectorAppPolicy {
  app_id: string;
  overrides: Record<string, ModuleMode>;
}

export interface DetectorMatrix {
  modules: DetectorModule[];
  apps: DetectorAppPolicy[];
  updated_at?: string;
}

export interface InnerRule {
  id: string;
  name: string;
  category: string;
  enabled: boolean;
}

export interface InnerRuleCategory {
  category: string;
  count: number;
  disabled: number;
}

export interface InnerRulesLibrary {
  rules: InnerRule[];
  categories: InnerRuleCategory[];
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

export const semanticsApi = {
  // Semantic detection matrix (14 modules, 4-way modes)
  getMatrix: () => request<DetectorMatrix>('/detector'),
  setModuleMode: (module: string, mode: ModuleMode) =>
    request<{ success: boolean }>(`/detector/modules/${module}`, {
      method: 'PUT',
      body: JSON.stringify({ mode }),
    }),
  getAppPolicy: (appID: string) =>
    request<DetectorAppPolicy & { updated_at?: string }>(`/detector/apps/${appID}`),
  setAppPolicy: (appID: string, overrides: Record<string, ModuleMode>) =>
    request<{ success: boolean }>(`/detector/apps/${appID}`, {
      method: 'PUT',
      body: JSON.stringify({ overrides }),
    }),

  // CVE virtual patches (inner rules)
  listInnerRules: () => request<InnerRulesLibrary>('/inner-rules'),
  setInnerRuleEnabled: (ruleID: string, enabled: boolean) =>
    request<{ success: boolean }>(`/inner-rules/${ruleID}`, {
      method: 'PUT',
      body: JSON.stringify({ enabled }),
    }),
  setInnerRuleCategoryEnabled: (category: string, enabled: boolean) =>
    request<{ success: boolean; count: number }>(`/inner-rules/categories/${category}`, {
      method: 'PUT',
      body: JSON.stringify({ enabled }),
    }),
};
