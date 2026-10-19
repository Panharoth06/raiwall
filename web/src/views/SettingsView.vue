<script setup lang="ts">
import { useConfigStore } from '@/stores/config';
import ApiKeysManager from '@/components/ApiKeysManager.vue';
import { Settings, Server, Network, ShieldCheck } from 'lucide-vue-next';

const configStore = useConfigStore();
</script>

<template>
  <div class="space-y-6 max-w-4xl">
    <!-- Header -->
    <div>
      <h1 class="text-xl font-bold text-white tracking-tight flex items-center space-x-2.5">
        <Settings class="w-6 h-6 text-emerald-400" />
        <span>System Settings & Cluster Integration</span>
      </h1>
      <p class="text-xs text-slate-400 mt-1">
        Inspect distributed cluster topology and manage programmatic API access tokens.
      </p>
    </div>

    <!-- Cluster Status Card -->
    <div class="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
      <h2 class="text-sm font-semibold text-white flex items-center space-x-2">
        <Network class="w-4 h-4 text-emerald-400" />
        <span>Cluster Node & Redis Pub/Sub Synchronization</span>
      </h2>

      <div class="grid grid-cols-3 gap-4 pt-2">
        <div class="p-4 bg-slate-800/40 border border-slate-800 rounded-lg">
          <span class="text-[11px] text-slate-400 block mb-1">Operating Mode</span>
          <span class="text-sm font-semibold text-white capitalize">
            {{ configStore.cluster?.mode || 'Standalone' }}
          </span>
        </div>

        <div class="p-4 bg-slate-800/40 border border-slate-800 rounded-lg">
          <span class="text-[11px] text-slate-400 block mb-1">Redis Sync Status</span>
          <span
            class="text-sm font-semibold flex items-center space-x-1.5"
            :class="configStore.cluster?.redis_connected ? 'text-emerald-400' : 'text-slate-400'"
          >
            <span
              class="h-2 w-2 rounded-full"
              :class="configStore.cluster?.redis_connected ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'"
            ></span>
            <span>{{ configStore.cluster?.redis_connected ? 'Connected' : 'Standalone / Local DB' }}</span>
          </span>
        </div>

        <div class="p-4 bg-slate-800/40 border border-slate-800 rounded-lg">
          <span class="text-[11px] text-slate-400 block mb-1">Active Snapshot Version</span>
          <span class="text-sm font-semibold text-emerald-400 font-mono">
            v{{ configStore.activeVersion }}
          </span>
        </div>
      </div>
    </div>

    <!-- API Keys Manager -->
    <div class="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
      <ApiKeysManager />
    </div>
  </div>
</template>
