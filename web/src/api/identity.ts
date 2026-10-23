// Auth gateway console API: user directory, IdP connectors, audit log.

export interface IdentityUser {
  id: string;
  username: string;
  email: string;
  display_name: string;
  totp_enrolled: boolean;
  app_ids: string[];
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface IdentityUserEnrollment extends IdentityUser {
  totp_secret?: string;
  totp_provisioning_uri?: string;
}

export interface IdentityProvider {
  id: string;
  type: 'oidc' | 'ldap' | 'github' | 'simple';
  name: string;
  config: Record<string, string | boolean | string[]>;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface IdentityAuthEvent {
  created_at?: string;
  id?: string;
  username: string;
  app_id: string;
  host: string;
  method: string;
  result: string;
  client_ip: string;
  country: string;
  detail: string;
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

export const identityApi = {
  // Directory user management
  listUsers: () => request<IdentityUser[]>('/identity/users'),
  createUser: (payload: { username: string; password: string; email?: string; display_name?: string; app_ids?: string[] }) =>
    request<IdentityUserEnrollment>('/identity/users', { method: 'POST', body: JSON.stringify(payload) }),
  updateUser: (id: string, patch: Partial<Pick<IdentityUser, 'email' | 'display_name' | 'app_ids' | 'enabled'>>) =>
    request<IdentityUser>(`/identity/users/${id}`, { method: 'PUT', body: JSON.stringify(patch) }),
  deleteUser: (id: string) => request<{ status: string }>(`/identity/users/${id}`, { method: 'DELETE' }),
  resetUserPassword: (id: string, newPassword: string) =>
    request<IdentityUser>(`/identity/users/${id}/password-reset`, {
      method: 'POST',
      body: JSON.stringify({ new_password: newPassword }),
    }),
  resetUserTOTP: (id: string, enroll: boolean) =>
    request<IdentityUserEnrollment>(`/identity/users/${id}/totp-reset`, {
      method: 'POST',
      body: JSON.stringify({ enroll }),
    }),

  // External IdP connectors
  listProviders: () => request<IdentityProvider[]>('/identity/providers'),
  createProvider: (payload: { type: IdentityProvider['type']; name: string; config: Record<string, string | boolean | string[]> }) =>
    request<IdentityProvider>('/identity/providers', { method: 'POST', body: JSON.stringify(payload) }),
  updateProvider: (id: string, patch: { name?: string; config?: IdentityProvider['config']; enabled?: boolean }) =>
    request<IdentityProvider>(`/identity/providers/${id}`, { method: 'PUT', body: JSON.stringify(patch) }),
  deleteProvider: (id: string) => request<{ status: string }>(`/identity/providers/${id}`, { method: 'DELETE' }),

  // Authentication audit log
  listAuthEvents: (limit = 200) => request<IdentityAuthEvent[]>(`/identity/auth-events?limit=${limit}`),
};
