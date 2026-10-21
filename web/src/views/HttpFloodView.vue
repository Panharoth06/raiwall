<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue';
import { useRoute } from '@/router';
import { useConfigStore } from '@/stores/config';
import type { PolicySettings } from '@/api/client';
import RateLimitingTable from '@/components/http-flood/RateLimitingTable.vue';
import RateLimitingSettings from '@/components/http-flood/RateLimitingSettings.vue';
import WaitingRoomDashboard from '@/components/WaitingRoomDashboard.vue';

const route = useRoute();
const configStore = useConfigStore();

const policy = ref<PolicySettings>({
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

onMounted(() => {
  if (configStore.policies) {
    policy.value = { ...configStore.policies };
  }
});

watch(
  () => configStore.policies,
  (val) => {
    if (val) {
      policy.value = { ...val };
    }
  }
);

const activeView = computed(() => {
  const p = route.value.path || '';
  if (p.includes('waiting-room')) return 'waiting-room';
  if (p.includes('settings')) return 'settings';
  return 'limits';
});
</script>

<template>
  <div class="h-full flex flex-col p-6 font-sans overflow-hidden">
    <div class="flex-1 min-h-0 overflow-y-auto">
      <RateLimitingSettings v-if="activeView === 'settings'" />
      <WaitingRoomDashboard v-else-if="activeView === 'waiting-room'" v-model:policy="policy" />
      <RateLimitingTable v-else />
    </div>
  </div>
</template>
