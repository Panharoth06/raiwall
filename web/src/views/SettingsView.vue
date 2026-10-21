<script setup lang="ts">
import { ref } from 'vue';
import { useConfigStore } from '@/stores/config';
import ApiKeysManager from '@/components/ApiKeysManager.vue';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Settings, Network, Key } from 'lucide-vue-next';
import { Tabs, type Tab } from '@/components/ui/tabs';

const configStore = useConfigStore();

type SettingsSubTab = 'cluster' | 'apikeys';
const activeTab = ref<SettingsSubTab>('cluster');

const tabs: (Tab & { id: SettingsSubTab })[] = [
  { id: 'cluster', label: 'Cluster Synchronization', icon: Network },
  { id: 'apikeys', label: 'API Keys & Access', icon: Key },
];

const handleTabChange = (tabId: string) => {
  activeTab.value = tabId as SettingsSubTab;
};
</script>

<template>
  <div class="h-full flex flex-col space-y-4 p-6 bg-card text-card-foreground rounded-xl border border-border shadow-2xl font-sans overflow-hidden">
    <!-- Header -->
    <div class="shrink-0">
      <h1 class="text-sm font-semibold uppercase tracking-wider text-foreground flex items-center gap-2">
        <Settings class="w-4 h-4 text-muted-foreground" />
        <span>System Settings & Cluster Integration</span>
      </h1>
      <p class="text-sm text-muted-foreground mt-1 leading-relaxed">
        Distributed cluster topology, Redis state sync, and programmatic API access credentials.
      </p>
    </div>

    <!-- Sub-tab switcher -->
    <div class="border-b border-border pb-1.5 shrink-0">
      <Tabs
        :tabs="tabs"
        :active-tab="activeTab"
        @tab-change="handleTabChange"
      />
    </div>

    <!-- Scrollable Content -->
    <div class="flex-1 min-h-0 overflow-y-auto space-y-4 pr-1">
      <!-- Cluster Status Card -->
      <Card v-if="activeTab === 'cluster'">
        <CardHeader class="pb-2">
          <div class="flex items-center gap-2">
            <Network class="w-4 h-4 text-muted-foreground" />
            <CardTitle class="text-xs uppercase tracking-wider text-foreground">
              Cluster Node & State Synchronization
            </CardTitle>
          </div>
        </CardHeader>

        <CardContent class="pt-2">
          <div class="grid grid-cols-3 gap-3">
            <div class="p-3 bg-muted/50 border border-border rounded-md">
              <span class="text-[10px] uppercase font-mono text-muted-foreground block mb-1">Operating Mode</span>
              <span class="text-xs font-semibold text-foreground capitalize">
                {{ configStore.cluster?.mode || 'Standalone' }}
              </span>
            </div>

            <div class="p-3 bg-muted/50 border border-border rounded-md">
              <span class="text-[10px] uppercase font-mono text-muted-foreground block mb-1">Redis Sync Status</span>
              <span
                class="text-xs font-semibold flex items-center gap-1.5"
                :class="configStore.cluster?.redis_connected ? 'text-success' : 'text-muted-foreground'"
              >
                <span
                  class="h-1.5 w-1.5 rounded-full"
                  :class="configStore.cluster?.redis_connected ? 'bg-success' : 'bg-muted-foreground/60'"
                ></span>
                <span>{{ configStore.cluster?.redis_connected ? 'Connected' : 'Standalone / Local DB' }}</span>
              </span>
            </div>

            <div class="p-3 bg-muted/50 border border-border rounded-md">
              <span class="text-[10px] uppercase font-mono text-muted-foreground block mb-1">Active Snapshot Version</span>
              <span class="text-xs font-semibold text-primary font-mono">
                v{{ configStore.activeVersion }}
              </span>
            </div>
          </div>
        </CardContent>
      </Card>

      <!-- API Keys Manager -->
      <Card v-else-if="activeTab === 'apikeys'" class="p-4">
        <ApiKeysManager />
      </Card>
    </div>
  </div>
</template>
