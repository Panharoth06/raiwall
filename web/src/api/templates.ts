export interface ResponseTemplate {
  id: string;
  status_code: number;
  title: string;
  content_html: string;
  custom_css: string;
  brand_name: string;
  logo_url: string;
  is_custom: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface PreviewPayload {
  content_html?: string;
  custom_css?: string;
  brand_name?: string;
  logo_url?: string;
}

export interface StatusCodeOption {
  code: number;
  name: string;
  category: string;
  description: string;
}

export const TEMPLATE_STATUS_CODES: StatusCodeOption[] = [
  { code: 403, name: 'Forbidden (WAF Block)', category: 'Security', description: 'Triggered upon semantic threat detection or ACL block rule match' },
  { code: 404, name: 'Not Found', category: 'Standard', description: 'Triggered when requested resource path does not exist on upstream' },
  { code: 429, name: 'Too Many Requests', category: 'Rate Limit', description: 'Triggered when access rate exceeds Tier 1 velocity threshold' },
  { code: 465, name: 'Virtual Waiting Room', category: 'Waiting Room', description: 'Triggered when traffic volume exceeds queue admission threshold' },
  { code: 466, name: 'Maintenance Mode', category: 'Offline', description: 'Triggered when site is set to offline or undergoing scheduled maintenance' },
  { code: 467, name: 'Identity Gateway Auth', category: 'Identity', description: 'Triggered when unauthenticated client requests protected route' },
  { code: 468, name: 'PoW Bot Challenge', category: 'Bot Defense', description: 'Triggered when browser client requires Proof-of-Work clearance' },
  { code: 502, name: 'Bad Gateway', category: 'Upstream', description: 'Triggered when all upstream backends fail active health checks' },
  { code: 504, name: 'Gateway Timeout', category: 'Upstream', description: 'Triggered when upstream response time exceeds timeout threshold' },
];

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
    const errorText = await response.text();
    let errorMessage = `HTTP ${response.status}: ${response.statusText}`;
    try {
      const errorJson = JSON.parse(errorText);
      if (errorJson.error) errorMessage = errorJson.error;
    } catch {
      if (errorText) errorMessage = errorText;
    }
    throw new Error(errorMessage);
  }

  return response.json();
}

export const templatesApi = {
  listTemplates: () => request<ResponseTemplate[]>('/templates'),
  getTemplate: (code: number) => request<ResponseTemplate>(`/templates/${code}`),
  updateTemplate: (code: number, data: Partial<ResponseTemplate>) =>
    request<ResponseTemplate>(`/templates/${code}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),
  resetTemplate: (code: number) =>
    request<ResponseTemplate>(`/templates/${code}/reset`, {
      method: 'POST',
    }),
  previewTemplate: (code: number, payload: PreviewPayload) =>
    request<{ html: string }>(`/templates/${code}/preview`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
};
