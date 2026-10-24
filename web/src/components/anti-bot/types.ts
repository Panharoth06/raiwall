import type { BotConfig } from '@/api/bot';

export type BotAppStatus = 'on' | 'off' | 'inherit' | 'partial' | 'paused' | 'unconfigured';

/** One row in the application-scoped BOT Protect table. */
export interface BotAppRow {
  id: string;
  name: string;
  hostnames: string[];
  global: boolean;
  status: BotAppStatus;
  /** Effective policy used to prefill the editor. */
  config: BotConfig | null;
  /** No application records exist; the global policy applies. */
  inherited: boolean;
  /** At least one hostname has an application-specific record. */
  custom: boolean;
  difficulty: number | null;
  traps: number;
  coverage?: { custom: number; total: number };
}
