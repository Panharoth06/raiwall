<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue';
import { useConfigStore } from '@/stores/config';
import type { PolicySettings } from '@/api/client';
import type { BotConfig, BotConfigDraft } from '@/api/bot';
import { useAntiBot } from '@/composables/useAntiBot';
import BotPolicyCard from '@/components/anti-bot/BotPolicyCard.vue';
import BotHostTable from '@/components/anti-bot/BotHostTable.vue';
import BotHostDialog from '@/components/anti-bot/BotHostDialog.vue';
import ChallengeActivity from '@/components/anti-bot/ChallengeActivity.vue';
import { Badge } from '@/components/ui/badge';
import { Bot, CheckCircle2, AlertTriangle } from 'lucide-vue-next';

/** Fallback used only when the policy store has not loaded yet. Mirrors server defaults. */
const FALLBACK_POLICY: PolicySettings = {
  tier1_rate: 100,
  tier1_burst: 200,
  tier2_threshold: 10,
  tier2_ban_seconds: 3600,
  tier3_threshold: 25,
  tier3_ban_seconds: 7200,
  bot_defense_mode: 'defense',
  pow_difficulty: 50_000,
  honeypot_enabled: true,
  waiting_room_enabled: false,
  waiting_room_max_concurrent: 1000,
  waiting_room_paths: [],
};

const configStore = useConfigStore();
const {
  hostOverrides,
  configsLoading,
  configsError,
  recentChallenges,
  challengeTotal,
  trapTotal,
  spoofTotal,
  uniqueJA4,
  activityLoading,
  activityError,
  load,
  loadConfigs,
  loadActivity,
  createConfig,
  updateConfig,
  removeConfig,
  toggleConfig,
} = useAntiBot();

const form = reactive({
  powEnabled: true,
  difficulty: 50_000,
  honeypot: true,
});

const savingPolicy = ref(false);
const notice = ref<{ kind: 'success' | 'error'; text: string } | null>(null);
let noticeTimer: ReturnType<typeof setTimeout> | undefined;

function pushNotice(kind: 'success' | 'error', text: string) {
  notice.value = { kind, text };
  clearTimeout(noticeTimer);
  if (kind === 'success') {
    noticeTimer = setTimeout(() => (notice.value = null), 4000);
  }
}

function errorText(err: unknown) {
  return err instanceof Error && err.message ? err.message : 'Unexpected request failure.';
}

function syncPolicy(policies: PolicySettings | null) {
  if (!policies) return;
  form.powEnabled =
    policies.bot_defense_mode === 'defense' || policies.bot_defense_mode === 'challenge';
  form.difficulty = policies.pow_difficulty || FALLBACK_POLICY.pow_difficulty;
  form.honeypot = policies.honeypot_enabled;
}

watch(() => configStore.policies, syncPolicy, { immediate: true, deep: true });

async function savePolicy() {
  savingPolicy.value = true;
  try {
    const base = configStore.policies ?? FALLBACK_POLICY;
    await configStore.savePolicies({
      ...base,
      bot_defense_mode: form.powEnabled ? 'defense' : 'audit',
      pow_difficulty: form.difficulty,
      honeypot_enabled: form.honeypot,
    });
    pushNotice('success', 'Bot policy staged to the config draft. Deploy to activate.');
  } catch (err) {
    pushNotice('error', `Policy save failed: ${errorText(err)}`);
  } finally {
    savingPolicy.value = false;
  }
}

// Per-host override dialog
const dialogOpen = ref(false);
const editingConfig = ref<BotConfig | null>(null);
const dialogSaving = ref(false);
const dialogError = ref('');

const hostSuggestions = computed(() =>
  (configStore.sites ?? []).flatMap((site) => site.hostnames ?? []).filter((host) => host !== '*')
);

function openAddOverride() {
  editingConfig.value = null;
  dialogError.value = '';
  dialogOpen.value = true;
}

function openEditOverride(config: BotConfig) {
  editingConfig.value = config;
  dialogError.value = '';
  dialogOpen.value = true;
}

async function saveOverride(draft: BotConfigDraft) {
  dialogSaving.value = true;
  dialogError.value = '';
  try {
    if (editingConfig.value) {
      await updateConfig(editingConfig.value.id, draft);
    } else {
      await createConfig(draft);
    }
    dialogOpen.value = false;
    pushNotice('success', `Override saved for ${draft.host}.`);
  } catch (err) {
    dialogError.value = errorText(err);
  } finally {
    dialogSaving.value = false;
  }
}

async function deleteOverride(config: BotConfig) {
  if (!confirm(`Delete the bot override for ${config.host}?`)) return;
  try {
    await removeConfig(config.id);
    pushNotice('success', `Override removed for ${config.host}.`);
  } catch (err) {
    pushNotice('error', `Delete failed: ${errorText(err)}`);
  }
}

async function toggleOverride(config: BotConfig) {
  try {
    await toggleConfig(config);
  } catch (err) {
    pushNotice('error', `Update failed: ${errorText(err)}`);
  }
}

onMounted(load);
</script>

<template>
  <div class="h-full flex flex-col space-y-4 p-6 bg-card text-card-foreground rounded-xl border border-border shadow-none font-sans overflow-hidden">
    <div class="flex flex-wrap items-start justify-between gap-3 shrink-0">
      <div class="min-w-0">
        <h1 class="text-sm font-semibold uppercase tracking-wider text-foreground flex items-center gap-2">
          <Bot class="w-4 h-4 text-muted-foreground" />
          <span>Anti-Bot Defense</span>
        </h1>
        <p class="text-sm text-muted-foreground mt-1 leading-relaxed">
          JA4 fingerprint verification, stateless SHA-256 proof-of-work, and crawler traps for
          browser routes.
        </p>
      </div>
      <Badge variant="outline" class="font-mono text-[10px] uppercase">JA4 · SHA-256 PoW</Badge>
    </div>

    <div
      v-if="notice"
      class="shrink-0 flex items-center gap-2 rounded-md border px-3 py-2 text-xs"
      :class="
        notice.kind === 'success'
          ? 'border-success/30 bg-success/10 text-success'
          : 'border-threat/30 bg-threat/10 text-threat'
      "
      role="status"
      data-testid="bot-notice"
    >
      <CheckCircle2 v-if="notice.kind === 'success'" class="w-4 h-4 shrink-0" />
      <AlertTriangle v-else class="w-4 h-4 shrink-0" />
      <span class="min-w-0 break-words">{{ notice.text }}</span>
    </div>

    <div class="flex-1 min-h-0 overflow-y-auto space-y-4 pr-1">
      <BotPolicyCard
        :pow-enabled="form.powEnabled"
        :difficulty="form.difficulty"
        :honeypot="form.honeypot"
        :saving="savingPolicy"
        @update:pow-enabled="form.powEnabled = $event"
        @update:difficulty="form.difficulty = $event"
        @update:honeypot="form.honeypot = $event"
        @save="savePolicy"
      />

      <div class="grid grid-cols-1 xl:grid-cols-3 gap-4 items-start">
        <div class="xl:col-span-2 min-w-0">
          <BotHostTable
            :configs="hostOverrides"
            :loading="configsLoading"
            :error="configsError"
            @add="openAddOverride"
            @edit="openEditOverride"
            @remove="deleteOverride"
            @toggle="toggleOverride"
            @retry="loadConfigs"
          />
        </div>

        <div class="min-w-0">
          <ChallengeActivity
            :events="recentChallenges"
            :challenge-total="challengeTotal"
            :trap-total="trapTotal"
            :spoof-total="spoofTotal"
            :unique-ja4="uniqueJA4"
            :loading="activityLoading"
            :error="activityError"
            @refresh="loadActivity"
          />
        </div>
      </div>
    </div>

    <BotHostDialog
      :open="dialogOpen"
      :config="editingConfig"
      :suggestions="hostSuggestions"
      :saving="dialogSaving"
      :error="dialogError"
      @close="dialogOpen = false"
      @save="saveOverride"
    />
  </div>
</template>
