<script setup lang="ts">
import { ref, onMounted, watch } from 'vue';
import { useConfigStore } from '@/stores/config';
import type { PolicySettings } from '@/api/client';
import { Sliders, Shield, Bot, Flame, Save, CheckCircle2 } from 'lucide-vue-next';

const configStore = useConfigStore();

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
  <div class="space-y-6 max-w-4xl">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-xl font-bold text-white tracking-tight flex items-center space-x-2.5">
          <Sliders class="w-6 h-6 text-emerald-400" />
          <span>Security & DDoS Defense Policies</span>
        </h1>
        <p class="text-xs text-slate-400 mt-1">
          Configure three-tiered rate limiting, stateless Proof-of-Work bot challenges, and virtual waiting room thresholds.
        </p>
      </div>

      <button
        @click="handleSave"
        class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-medium transition-colors flex items-center space-x-2 shadow-lg"
      >
        <Save class="w-4 h-4" />
        <span>Save Policies to Draft</span>
      </button>
    </div>

    <div v-if="savedNotification" class="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg flex items-center space-x-2 text-emerald-400 text-xs">
      <CheckCircle2 class="w-4 h-4" />
      <span>Security policies saved to draft configuration. Review and deploy in Deployments view.</span>
    </div>

    <!-- 3-Tier Rate Limiting -->
    <div class="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
      <h2 class="text-sm font-semibold text-white flex items-center space-x-2">
        <Flame class="w-4 h-4 text-amber-400" />
        <span>Three-Tiered Composite Rate Limiting</span>
      </h2>
      <p class="text-xs text-slate-400">
        Multi-layered threshold defense protecting against high-velocity floods, repeated exploit attacks, and vulnerability scanners.
      </p>

      <div class="grid grid-cols-2 gap-6 pt-2">
        <!-- Tier 1 -->
        <div class="p-4 bg-slate-800/50 border border-slate-800 rounded-lg space-y-3">
          <span class="text-xs font-semibold text-slate-200 block">Tier 1: Velocity Rate Limit (PoW Trigger)</span>
          <div>
            <label class="block text-[11px] text-slate-400 mb-1">Max Requests / Sec</label>
            <input
              v-model.number="form.tier1_rate"
              type="number"
              class="w-full px-3 py-1.5 bg-slate-800 border border-slate-700 rounded text-slate-200 text-xs focus:outline-none focus:border-emerald-500"
            />
          </div>
          <div>
            <label class="block text-[11px] text-slate-400 mb-1">Burst Capacity</label>
            <input
              v-model.number="form.tier1_burst"
              type="number"
              class="w-full px-3 py-1.5 bg-slate-800 border border-slate-700 rounded text-slate-200 text-xs focus:outline-none focus:border-emerald-500"
            />
          </div>
        </div>

        <!-- Tier 2 -->
        <div class="p-4 bg-slate-800/50 border border-slate-800 rounded-lg space-y-3">
          <span class="text-xs font-semibold text-slate-200 block">Tier 2: Attack Frequency Auto-Ban</span>
          <div>
            <label class="block text-[11px] text-slate-400 mb-1">Threat Threshold (Violations in 10s)</label>
            <input
              v-model.number="form.tier2_threshold"
              type="number"
              class="w-full px-3 py-1.5 bg-slate-800 border border-slate-700 rounded text-slate-200 text-xs focus:outline-none focus:border-emerald-500"
            />
          </div>
          <div>
            <label class="block text-[11px] text-slate-400 mb-1">Ban Duration (Seconds)</label>
            <input
              v-model.number="form.tier2_ban_seconds"
              type="number"
              class="w-full px-3 py-1.5 bg-slate-800 border border-slate-700 rounded text-slate-200 text-xs focus:outline-none focus:border-emerald-500"
            />
          </div>
        </div>
      </div>

      <!-- Tier 3 -->
      <div class="p-4 bg-slate-800/50 border border-slate-800 rounded-lg space-y-3">
        <span class="text-xs font-semibold text-slate-200 block">Tier 3: Upstream Scanner Trap (403/404 Abuse)</span>
        <div class="grid grid-cols-2 gap-4">
          <div>
            <label class="block text-[11px] text-slate-400 mb-1">Scanner 403/404 Threshold</label>
            <input
              v-model.number="form.tier3_threshold"
              type="number"
              class="w-full px-3 py-1.5 bg-slate-800 border border-slate-700 rounded text-slate-200 text-xs focus:outline-none focus:border-emerald-500"
            />
          </div>
          <div>
            <label class="block text-[11px] text-slate-400 mb-1">Scanner Ban Duration (Seconds)</label>
            <input
              v-model.number="form.tier3_ban_seconds"
              type="number"
              class="w-full px-3 py-1.5 bg-slate-800 border border-slate-700 rounded text-slate-200 text-xs focus:outline-none focus:border-emerald-500"
            />
          </div>
        </div>
      </div>
    </div>

    <!-- Active Bot Defense -->
    <div class="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
      <h2 class="text-sm font-semibold text-white flex items-center space-x-2">
        <Bot class="w-4 h-4 text-emerald-400" />
        <span>Active Bot Defense & Proof-of-Work</span>
      </h2>

      <div class="grid grid-cols-2 gap-6">
        <div>
          <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Challenge Mode</label>
          <select
            v-model="form.bot_defense_mode"
            class="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-200 text-xs focus:outline-none focus:border-emerald-500"
          >
            <option value="defense">Defense (Issue HTTP 468 PoW Challenge)</option>
            <option value="challenge">Interactive Challenge Always</option>
            <option value="audit">Audit Only (Fingerprint without challenge)</option>
            <option value="off">Disabled</option>
          </select>
        </div>

        <div>
          <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
            PoW SHA-256 Difficulty: {{ form.pow_difficulty }}
          </label>
          <input
            v-model.number="form.pow_difficulty"
            type="range"
            min="5000"
            max="100000"
            step="5000"
            class="w-full accent-emerald-500"
          />
        </div>
      </div>

      <div class="pt-2 flex items-center space-x-3">
        <input
          id="honeypot"
          v-model="form.honeypot_enabled"
          type="checkbox"
          class="h-4 w-4 rounded bg-slate-800 border-slate-700 text-emerald-600 focus:ring-emerald-500"
        />
        <label for="honeypot" class="text-xs text-slate-300">
          Inject invisible honeypot trap hyperlinks into HTML responses to trap headless crawlers
        </label>
      </div>
    </div>
  </div>
</template>
