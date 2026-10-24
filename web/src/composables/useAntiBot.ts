import { computed, ref } from 'vue';
import { api, type Site } from '@/api/client';
import { botApi, type BotConfig, type BotConfigDraft } from '@/api/bot';
import type { BotAppRow, BotAppStatus } from '@/components/anti-bot/types';
import type { ForensicEvent } from '@/types/telemetry';

const ACTIVITY_WINDOW_MS = 24 * 60 * 60 * 1000;
const ACTIVITY_SAMPLE_LIMIT = 100;

export interface BotPolicyDraft {
  pow_enabled: boolean;
  pow_difficulty: number;
  trap_urls: string[];
  is_active: boolean;
}

export interface BotPolicyTarget {
  /** Application name, or "Global default" for the wildcard policy. */
  name: string;
  /** Exact Host headers covered by this application. Empty for the global policy. */
  hostnames: string[];
  global?: boolean;
}

export interface ResolvedBotPolicy {
  /** Effective policy used to prefill the editor. */
  config: BotConfig | null;
  /** True when the application has no override and inherits the global policy. */
  inherited: boolean;
  /** True when at least one hostname has an application-specific record. */
  custom: boolean;
  /** Records that belong to the application. */
  records: BotConfig[];
}

const errorMessage = (err: unknown, fallback: string) =>
  err instanceof Error && err.message ? err.message : fallback;

/**
 * Loads application-scoped bot policies and 24h challenge telemetry.
 * Bot records are keyed by exact Host header; an application may cover several hostnames.
 */
export function useAntiBot() {
  const configs = ref<BotConfig[]>([]);
  const configsLoading = ref(false);
  const configsError = ref('');

  const recentChallenges = ref<ForensicEvent[]>([]);
  const challengeTotal = ref(0);
  const trapTotal = ref(0);
  const spoofTotal = ref(0);
  const activityLoading = ref(false);
  const activityError = ref('');

  const globalConfig = computed(() => configs.value.find((c) => c.host === '*') ?? null);

  const uniqueJA4 = computed(
    () => new Set(recentChallenges.value.map((e) => e.ja4).filter(Boolean)).size
  );

  function recordsForHosts(hostnames: string[]): BotConfig[] {
    const wanted = new Set(hostnames.filter(Boolean));
    if (wanted.size === 0) return [];
    return configs.value.filter((c) => c.host !== '*' && wanted.has(c.host));
  }

  function resolvePolicy(hostnames: string[]): ResolvedBotPolicy {
    const records = recordsForHosts(hostnames);
    if (records.length > 0) {
      const primary =
        records.find((c) => c.host === hostnames[0]) ?? records[0];
      return { config: primary, inherited: false, custom: true, records };
    }
    return {
      config: globalConfig.value,
      inherited: true,
      custom: false,
      records: [],
    };
  }

  function appRow(site: Site): BotAppRow {
    const hostnames = (site.hostnames ?? []).filter(Boolean);
    const resolved = resolvePolicy(hostnames);
    const records = resolved.records;
    const active = records.filter((record) => record.is_active);
    const total = hostnames.length;

    let status: BotAppStatus = 'inherit';
    if (records.length > 0) {
      if (active.length === 0) {
        status = 'paused';
      } else if (records.length < total || active.length < records.length) {
        status = 'partial';
      } else if (active.every((record) => record.pow_enabled)) {
        status = 'on';
      } else if (active.every((record) => !record.pow_enabled)) {
        status = 'off';
      } else {
        status = 'partial';
      }
    }

    const effective = resolved.config;
    const traps = records.length
      ? new Set(records.flatMap((record) => record.trap_urls ?? [])).size
      : (globalConfig.value?.trap_urls?.length ?? 0);

    return {
      id: site.id,
      name: site.name,
      hostnames,
      global: false,
      status,
      config: effective,
      inherited: resolved.inherited,
      custom: resolved.custom,
      difficulty: effective?.pow_difficulty ?? null,
      traps,
      coverage: { custom: records.length, total },
    };
  }

  /** Builds the application table rows, with the wildcard policy first. */
  function buildRows(sites: Site[]): BotAppRow[] {
    const global = globalConfig.value;
    const globalStatus: BotAppStatus = !global
      ? 'unconfigured'
      : !global.is_active
        ? 'paused'
        : global.pow_enabled
          ? 'on'
          : 'off';

    return [
      {
        id: 'global',
        name: 'Global default',
        hostnames: [],
        global: true,
        status: globalStatus,
        config: global,
        inherited: false,
        custom: false,
        difficulty: global?.pow_difficulty ?? null,
        traps: global?.trap_urls?.length ?? 0,
      },
      ...sites.map(appRow),
    ];
  }

  async function loadConfigs() {
    configsLoading.value = true;
    configsError.value = '';
    try {
      configs.value = await botApi.list();
    } catch (err) {
      configsError.value = errorMessage(err, 'Could not load bot policies.');
    } finally {
      configsLoading.value = false;
    }
  }

  async function loadActivity() {    activityLoading.value = true;
    activityError.value = '';
    const startTime = new Date(Date.now() - ACTIVITY_WINDOW_MS).toISOString();
    try {
      const [challenges, traps, spoofs] = await Promise.all([
        api.listEvents({
          action: 'challenge',
          start_time: startTime,
          limit: ACTIVITY_SAMPLE_LIMIT,
        }),
        api.listEvents({ rule_id: 'honeypot_trap', start_time: startTime, limit: 1 }),
        api.listEvents({ rule_id: 'bot_spoof', start_time: startTime, limit: 1 }),
      ]);
      recentChallenges.value = challenges.events ?? [];
      challengeTotal.value = challenges.total ?? recentChallenges.value.length;
      trapTotal.value = traps.total ?? 0;
      spoofTotal.value = spoofs.total ?? 0;
    } catch (err) {
      activityError.value = errorMessage(err, 'Could not load challenge activity.');
    } finally {
      activityLoading.value = false;
    }
  }

  async function upsertHost(host: string, draft: BotPolicyDraft) {
    const existing = configs.value.find((c) => c.host === host);
    const payload: BotConfigDraft = { host, ...draft };
    if (existing) {
      await botApi.update(existing.id, payload);
    } else {
      await botApi.create(payload);
    }
  }

  /** Persists the same policy for every hostname in the application. */
  async function savePolicy(target: BotPolicyTarget, draft: BotPolicyDraft) {
    const hosts = target.global ? ['*'] : [...new Set(target.hostnames.filter(Boolean))];
    for (const host of hosts) {
      await upsertHost(host, draft);
    }
    await loadConfigs();
  }

  /** Removes application overrides so the global default applies again. */
  async function resetPolicy(hostnames: string[]) {
    const records = recordsForHosts(hostnames);
    for (const record of records) {
      await botApi.remove(record.id);
    }
    await loadConfigs();
  }

  return {
    globalConfig,
    configsLoading,
    configsError,
    recentChallenges,
    challengeTotal,
    trapTotal,
    spoofTotal,
    uniqueJA4,
    activityLoading,
    activityError,
    resolvePolicy,
    buildRows,
    loadConfigs,
    loadActivity,
    savePolicy,
    resetPolicy,
  };
}
