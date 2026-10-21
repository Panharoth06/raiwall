<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue';
import { useRoute, useRouter } from '@/router';
import { useConfigStore } from '@/stores/config';
import type { PolicySettings } from '@/api/client';
import RateLimitingTable from '@/components/http-flood/RateLimitingTable.vue';
import RateLimitingSettings from '@/components/http-flood/RateLimitingSettings.vue';
import WaitingRoomDashboard from '@/components/WaitingRoomDashboard.vue';
import { Tabs, type Tab } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { ShieldAlert, Flame, Users, Save, CheckCircle2 } from 'lucide-vue-next';

const route = useRoute();
const router = useRouter();
const configStore = useConfigStore();

type FloodSubTab = 'bans' | 'limits' | 'waiting-room';
const activeTab = ref<FloodSubTab>('bans');

const tabs: (Tab & { id: FloodSubTab })[] = [
  { id: 'bans', label: 'Active Blocked Clients', icon: ShieldAlert },
  { id: 'limits', label: '3-Tier Limits Configuration', icon: Flame },
  { id: 'waiting-room', label: 'Waiting Room Dashboard', icon: Users },
];

const form = ref<PolicySettings>({
  tier1_rate: 100,
  tier1_burst: 200,
  tier2_threshold: 10,
  tier2_ban_seconds: 3600,
  tier3_threshold: 25,
  tier3_ban_seconds: 7200,
  bot_defense_mode: 'defense',
  pow_difficulty: 20000,
  honeypot_enabled: true,
  waiting_room_enabled: false,
  waiting_room_max_concurrent: 1000,
  waiting_room_paths: [],
});

const savedNotification = ref(false);

const syncFromRoute = (path: string) => {
  if (path.includes('waiting-room')) {
    activeTab.value = 'waiting-room';
  } else if (path.includes('settings')) {
    activeTab.value = 'limits';
  } else {
    activeTab.value = 'bans';
  }
};

onMounted(() => {
  if (configStore.policies) {
    form.value = { ...configStore.policies };
  }
  syncFromRoute(route.value.path || '');
});

watch(
  () => route.value.path,
  (newPath) => {
    if (newPath) {
      syncFromRoute(newPath);
    }
  }
);

watch(
  () => configStore.policies,
  (val) => {
    if (val) {
      form.value = { ...val };
    }
  }
);

const handleTabChange = (tabId: string) => {
  activeTab.value = tabId as FloodSubTab;
  if (tabId === 'waiting-room') {
    router.push('/http-flood/waiting-room');
  } else if (tabId === 'limits') {
    router.push('/http-flood/limits/settings');
  } else {
    router.push('/http-flood/limits');
  }
};

const handleSave = async () => {
  await configStore.savePolicies(form.value);
  savedNotification.value = true;
  setTimeout(() => {
    savedNotification.value = false;
  }, 3000);
};
</script>

<template>
  <div class="h-full flex flex-col space-y-4 p-6 bg-background text-foreground rounded-xl border border-border shadow-xs font-sans overflow-hidden">
    <!-- Top Header Strip -->
    <div class="flex items-center justify-between shrink-0">
      <div>
        <h1 class="text-sm font-semibold uppercase tracking-wider text-foreground flex items-center gap-2">
          <span>HTTP Flood & Volumetric Defense</span>
        </h1>
        <p class="text-xs text-muted-foreground mt-0.5 leading-relaxed">
          SafeLine-style volumetric rate limiting, 3-tier defense policies, and virtual waiting room buffering.
        </p>
      </div>

      <Button size="sm" class="gap-1.5 h-8 text-xs font-semibold" @click="handleSave">
        <Save class="w-3.5 h-3.5" />
        <span>Save to Draft</span>
      </Button>
    </div>

    <!-- Notification Banner -->
    <div
      v-if="savedNotification"
      class="p-2.5 bg-primary/10 border border-primary/30 rounded-md flex items-center gap-2 text-primary text-xs shrink-0"
    >
      <CheckCircle2 class="w-4 h-4 text-primary" />
      <span>Volumetric defense policies saved to draft. Deploy via Deployments console to activate on gateway.</span>
    </div>

    <!-- Sub-tab switcher -->
    <div class="border-b border-border pb-1.5 shrink-0">
      <Tabs
        :tabs="tabs"
        :active-tab="activeTab"
        @tab-change="handleTabChange"
      />
    </div>

    <!-- Main Content Area -->
    <div class="flex-1 min-h-0 overflow-y-auto pr-1">
      <!-- 1. SafeLine Rate Limiting Records Table -->
      <div v-if="activeTab === 'bans'">
        <RateLimitingTable />
      </div>

      <!-- 2. SafeLine 3-Tier Limiting Settings -->
      <div v-else-if="activeTab === 'limits'">
        <RateLimitingSettings />
      </div>

      <!-- 3. Virtual Waiting Room Dashboard -->
      <div v-else-if="activeTab === 'waiting-room'">
        <WaitingRoomDashboard v-model:policy="form" />
      </div>
    </div>
  </div>
</template>
