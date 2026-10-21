<script setup lang="ts">
import { ref, onMounted, watch } from 'vue';
import { useConfigStore } from '@/stores/config';
import type { PolicySettings } from '@/api/client';
import ActiveBansTable from '@/components/ActiveBansTable.vue';
import WaitingRoomDashboard from '@/components/WaitingRoomDashboard.vue';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from '@/components/ui/card';
import {
  Activity,
  ShieldAlert,
  Flame,
  Users,
  Save,
  CheckCircle2,
} from 'lucide-vue-next';
import { Tabs, type Tab } from '@/components/ui/tabs';

const configStore = useConfigStore();
type FloodSubTab = 'bans' | 'limits' | 'waiting-room';
const activeTab = ref<FloodSubTab>('bans');

const tabs: (Tab & { id: FloodSubTab })[] = [
  { id: 'bans', label: 'Active Blocked Clients', icon: ShieldAlert },
  { id: 'limits', label: '3-Tier Limits Configuration', icon: Flame },
  { id: 'waiting-room', label: 'Waiting Room Dashboard', icon: Users },
];

const handleTabChange = (tabId: string) => {
  activeTab.value = tabId as FloodSubTab;
};

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

onMounted(() => {
  if (configStore.policies) {
    form.value = { ...configStore.policies };
  }
});

watch(
  () => configStore.policies,
  (val) => {
    if (val) {
      form.value = { ...val };
    }
  }
);

const handleSave = async () => {
  await configStore.savePolicies(form.value);
  savedNotification.value = true;
  setTimeout(() => {
    savedNotification.value = false;
  }, 3000);
};
</script>

<template>
  <div class="h-full flex flex-col space-y-4 p-6 bg-background text-foreground rounded-xl border border-border shadow-sm font-sans overflow-hidden">
    <!-- Header -->
    <div class="flex items-center justify-between shrink-0">
      <div>
        <h1 class="text-sm font-semibold uppercase tracking-wider text-foreground flex items-center gap-2">
          <Activity class="w-4 h-4 text-primary" />
          <span>Volumetric Defense & Virtual Waiting Room</span>
        </h1>
        <p class="text-sm text-muted-foreground mt-1 leading-relaxed">
          Real-time active ban registry, 3-tier composite rate limits, and HTTP 465 queue buffering.
        </p>
      </div>

      <Button size="sm" class="gap-1.5 h-8 text-xs font-semibold" @click="handleSave">
        <Save class="w-3.5 h-3.5" />
        <span>Save to Draft</span>
      </Button>
    </div>

    <!-- Saved Confirmation Banner -->
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

    <!-- Tab Content -->
    <div class="flex-1 min-h-0 overflow-y-auto pr-1">
      <!-- 1. Active Blocked Clients -->
      <div v-if="activeTab === 'bans'">
        <ActiveBansTable />
      </div>

      <!-- 2. 3-Tier Limits Configuration -->
      <div v-else-if="activeTab === 'limits'" class="space-y-4 max-w-4xl">
        <!-- Tier 1: Access Velocity -->
        <Card class="bg-card border-border">
          <CardHeader class="pb-2">
            <CardTitle class="text-xs uppercase tracking-wider text-foreground">
              Tier 1: Access Velocity Limiting (Token Bucket)
            </CardTitle>
            <CardDescription class="text-sm text-muted-foreground mt-1 leading-relaxed">
              Evaluates GCRA token bucket across composite key (IP + JA4 + Cookie) to protect against CGNAT collateral damage.
            </CardDescription>
          </CardHeader>
          <CardContent class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label class="text-xs font-medium text-foreground block mb-1">Permitted Rate (req/min)</label>
              <Input v-model.number="form.tier1_rate" type="number" class="h-8 text-xs font-mono" />
            </div>
            <div>
              <label class="text-xs font-medium text-foreground block mb-1">Burst Tolerance (requests)</label>
              <Input v-model.number="form.tier1_burst" type="number" class="h-8 text-xs font-mono" />
            </div>
          </CardContent>
        </Card>

        <!-- Tier 2: Attack Frequency Ban -->
        <Card class="bg-card border-border">
          <CardHeader class="pb-2">
            <CardTitle class="text-xs uppercase tracking-wider text-foreground">
              Tier 2: Attack Frequency Auto-Ban
            </CardTitle>
            <CardDescription class="text-sm text-muted-foreground mt-1 leading-relaxed">
              Automatically escalates repeated malicious WAF payload violations into an immediate temporary ban.
            </CardDescription>
          </CardHeader>
          <CardContent class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label class="text-xs font-medium text-foreground block mb-1">Attack Threshold (violations/min)</label>
              <Input v-model.number="form.tier2_threshold" type="number" class="h-8 text-xs font-mono" />
            </div>
            <div>
              <label class="text-xs font-medium text-foreground block mb-1">Ban Duration (seconds)</label>
              <Input v-model.number="form.tier2_ban_seconds" type="number" class="h-8 text-xs font-mono" />
            </div>
          </CardContent>
        </Card>

        <!-- Tier 3: Scanner Trap -->
        <Card class="bg-card border-border">
          <CardHeader class="pb-2">
            <CardTitle class="text-xs uppercase tracking-wider text-foreground">
              Tier 3: Upstream Scanner Trap (403/404 Brute-force)
            </CardTitle>
            <CardDescription class="text-sm text-muted-foreground mt-1 leading-relaxed">
              Traps aggressive directory enumeration and reconnaissance scanners returning repeated 403/404 errors.
            </CardDescription>
          </CardHeader>
          <CardContent class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label class="text-xs font-medium text-foreground block mb-1">403/404 Threshold (errors/30s)</label>
              <Input v-model.number="form.tier3_threshold" type="number" class="h-8 text-xs font-mono" />
            </div>
            <div>
              <label class="text-xs font-medium text-foreground block mb-1">Ban Duration (seconds)</label>
              <Input v-model.number="form.tier3_ban_seconds" type="number" class="h-8 text-xs font-mono" />
            </div>
          </CardContent>
        </Card>
      </div>

      <!-- 3. Waiting Room Dashboard -->
      <div v-else-if="activeTab === 'waiting-room'">
        <WaitingRoomDashboard v-model:policy="form" />
      </div>
    </div>
  </div>
</template>
