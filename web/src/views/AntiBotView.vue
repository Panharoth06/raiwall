<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { useRoute } from '@/router';
import { useConfigStore } from '@/stores/config';
import type { BotConfig } from '@/api/bot';
import type { BotPolicyDraft, BotPolicyTarget } from '@/composables/useAntiBot';
import { useAntiBot } from '@/composables/useAntiBot';
import BotAppTable from '@/components/anti-bot/BotAppTable.vue';
import BotProtectDialog from '@/components/anti-bot/BotProtectDialog.vue';
import ChallengeActivity from '@/components/anti-bot/ChallengeActivity.vue';
import type { BotAppRow } from '@/components/anti-bot/types';
import { Badge } from '@/components/ui/badge';
import { Bot, CheckCircle2, AlertTriangle } from 'lucide-vue-next';

const route = useRoute();
const configStore = useConfigStore();
const {
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
} = useAntiBot();

const rows = computed<BotAppRow[]>(() => buildRows(configStore.sites ?? []));

const dialogOpen = ref(false);
const dialogTarget = ref<BotPolicyTarget | null>(null);
const dialogConfig = ref<BotConfig | null>(null);
const dialogInherited = ref(false);
const dialogCustom = ref(false);
const dialogSaving = ref(false);
const dialogError = ref('');

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

function openProtect(row: BotAppRow) {
  if (!row.global && row.hostnames.length === 0) {
    pushNotice('error', 'Add a hostname to this application before configuring BOT Protect.');
    return;
  }

  dialogError.value = '';
  dialogTarget.value = {
    name: row.name,
    hostnames: row.hostnames,
    global: row.global,
  };

  if (row.global) {
    dialogConfig.value = globalConfig.value;
    dialogInherited.value = false;
    dialogCustom.value = false;
  } else {
    const resolved = resolvePolicy(row.hostnames);
    dialogConfig.value = resolved.config;
    dialogInherited.value = resolved.inherited;
    dialogCustom.value = resolved.custom;
  }

  dialogOpen.value = true;
}

async function handleSave(draft: BotPolicyDraft) {
  if (!dialogTarget.value) return;
  const target = dialogTarget.value;
  dialogSaving.value = true;
  dialogError.value = '';
  try {
    await savePolicy(target, draft);
    dialogOpen.value = false;
    const scope = target.global
      ? 'all unconfigured hosts'
      : `${target.name} (${target.hostnames.length} hostname${target.hostnames.length === 1 ? '' : 's'})`;
    pushNotice('success', `BOT Protect saved for ${scope}. Compile the draft to activate.`);
  } catch (err) {
    dialogError.value = errorText(err);
  } finally {
    dialogSaving.value = false;
  }
}

async function handleReset() {
  if (!dialogTarget.value) return;
  const target = dialogTarget.value;
  dialogSaving.value = true;
  dialogError.value = '';
  try {
    await resetPolicy(target.hostnames);
    dialogOpen.value = false;
    pushNotice('success', `BOT Protect override removed for ${target.name}.`);
  } catch (err) {
    dialogError.value = errorText(err);
  } finally {
    dialogSaving.value = false;
  }
}

function openFromQuery() {
  const siteId = route.value?.query?.app;
  if (!siteId) return;
  const row = rows.value.find((item) => item.id === siteId);
  if (row) openProtect(row);
  // Consume the deep-link parameter without triggering another hash navigation.
  if (typeof window !== 'undefined' && window.location.hash.includes('?')) {
    window.history.replaceState(null, '', '#/anti-bot');
  }
}

onMounted(async () => {
  void loadActivity();
  await loadConfigs();
  openFromQuery();
});
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
          Configure BOT Protect per application: proof-of-work challenges, crawler traps, and 24h
          challenge telemetry.
        </p>
      </div>
      <Badge variant="outline" class="font-mono text-[10px] uppercase">
        Application-scoped · PoW · JA4
      </Badge>
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

    <div class="flex-1 min-h-0 overflow-y-auto pr-1">
      <div class="grid grid-cols-1 xl:grid-cols-3 gap-4 items-start">
        <div class="xl:col-span-2 min-w-0">
          <BotAppTable
            :rows="rows"
            :loading="configsLoading"
            :error="configsError"
            @configure="openProtect"
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

    <BotProtectDialog
      :open="dialogOpen"
      :target="dialogTarget"
      :config="dialogConfig"
      :inherited="dialogInherited"
      :custom="dialogCustom"
      :saving="dialogSaving"
      :error="dialogError"
      @close="dialogOpen = false"
      @save="handleSave"
      @reset="handleReset"
    />
  </div>
</template>
