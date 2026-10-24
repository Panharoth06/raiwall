import { request } from './client';

/** Per-host bot-defense override. The wildcard host "*" holds the global policy. */
export interface BotConfig {
  id: string;
  host: string;
  pow_enabled: boolean;
  pow_difficulty: number;
  trap_urls: string[];
  is_active: boolean;
  created_at?: string;
  updated_at?: string;
}

export type BotConfigDraft = Pick<
  BotConfig,
  'host' | 'pow_enabled' | 'pow_difficulty' | 'trap_urls' | 'is_active'
>;

export const botApi = {
  list: () => request<BotConfig[]>('/policies/bot'),
  create: (config: BotConfigDraft) =>
    request<BotConfig>('/policies/bot', {
      method: 'POST',
      body: JSON.stringify(config),
    }),
  update: (id: string, config: Partial<BotConfigDraft>) =>
    request<BotConfig>(`/policies/bot/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(config),
    }),
  remove: (id: string) =>
    request<{ status: string; id: string }>(`/policies/bot/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),
};
