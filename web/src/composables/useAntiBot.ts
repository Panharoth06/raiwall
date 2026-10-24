import { computed, ref } from 'vue';
import { api } from '@/api/client';
import { botApi, type BotConfig, type BotConfigDraft } from '@/api/bot';
import type { ForensicEvent } from '@/types/telemetry';

const ACTIVITY_WINDOW_MS = 24 * 60 * 60 * 1000;
const ACTIVITY_SAMPLE_LIMIT = 100;

const errorMessage = (err: unknown, fallback: string) =>
  err instanceof Error && err.message ? err.message : fallback;

/**
 * Loads per-host bot overrides and 24h challenge telemetry.
 * Counts come from the server-side filtered totals; the recent list is a bounded sample.
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

  const hostOverrides = computed(() => configs.value.filter((c) => c.host !== '*'));
  const uniqueJA4 = computed(
    () => new Set(recentChallenges.value.map((e) => e.ja4).filter(Boolean)).size
  );
  const uniqueClients = computed(
    () => new Set(recentChallenges.value.map((e) => e.client_ip)).size
  );

  async function loadConfigs() {
    configsLoading.value = true;
    configsError.value = '';
    try {
      configs.value = await botApi.list();
    } catch (err) {
      configsError.value = errorMessage(err, 'Could not load bot overrides.');
    } finally {
      configsLoading.value = false;
    }
  }

  async function loadActivity() {
    activityLoading.value = true;
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

  async function createConfig(draft: BotConfigDraft) {
    await botApi.create(draft);
    await loadConfigs();
  }

  async function updateConfig(id: string, draft: Partial<BotConfigDraft>) {
    await botApi.update(id, draft);
    await loadConfigs();
  }

  async function removeConfig(id: string) {
    await botApi.remove(id);
    await loadConfigs();
  }

  async function toggleConfig(config: BotConfig) {
    // The API replaces the full record; send every field so a toggle cannot wipe host/policy data.
    await botApi.update(config.id, {
      host: config.host,
      pow_enabled: config.pow_enabled,
      pow_difficulty: config.pow_difficulty,
      trap_urls: config.trap_urls,
      is_active: !config.is_active,
    });
    await loadConfigs();
  }

  function load() {
    void loadConfigs();
    void loadActivity();
  }

  return {
    configs,
    hostOverrides,
    configsLoading,
    configsError,
    recentChallenges,
    challengeTotal,
    trapTotal,
    spoofTotal,
    uniqueJA4,
    uniqueClients,
    activityLoading,
    activityError,
    loadConfigs,
    loadActivity,
    createConfig,
    updateConfig,
    removeConfig,
    toggleConfig,
    load,
  };
}
