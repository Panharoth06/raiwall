<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRouter } from '@/router';
import { useConfigStore } from '@/stores/config';
import { useTheme } from '@/composables/useTheme';
import { api } from '@/api/client';
import ApiKeysManager from '@/components/ApiKeysManager.vue';
import UsersPanel from '@/components/settings/UsersPanel.vue';
import CertificatesPanel from '@/components/certificates/CertificatesPanel.vue';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Settings,
  Network,
  Key,
  Users,
  Palette,
  Moon,
  Sun,
  Monitor,
  Lock,
  History,
  Rocket,
  Zap,
  GitCommit,
  Check,
} from 'lucide-vue-next';
import { Tabs, type Tab } from '@/components/ui/tabs';

const router = useRouter();
const configStore = useConfigStore();
const { theme, setTheme } = useTheme();

type SettingsSubTab = 'cluster' | 'certificates' | 'apikeys' | 'users';
const activeTab = ref<SettingsSubTab>('cluster');

const tabs: (Tab & { id: SettingsSubTab })[] = [
  { id: 'cluster', label: 'Cluster Synchronization', icon: Network },
  { id: 'certificates', label: 'TLS Certificates', icon: Lock },
  { id: 'apikeys', label: 'API Keys & Access', icon: Key },
  { id: 'users', label: 'Operators', icon: Users },
];

const handleTabChange = (tabId: string) => {
  activeTab.value = tabId as SettingsSubTab;
};

const autoApply = ref(true);
const autoApplyLoading = ref(false);
const autoApplyError = ref('');

const loadAutoApply = async () => {
  try {
    const status = await api.getStatus();
    autoApply.value = status.auto_apply;
  } catch {
    // Default to true
  }
};

const setAutoApplyMode = async (enabled: boolean) => {
  if (autoApply.value === enabled && !autoApplyError.value) return;
  autoApplyLoading.value = true;
  autoApplyError.value = '';
  try {
    const res = await api.setAutoApply(enabled);
    autoApply.value = res.auto_apply;
  } catch (e) {
    autoApplyError.value = e instanceof Error ? e.message : 'Failed to update auto-apply';
  } finally {
    autoApplyLoading.value = false;
  }
};

onMounted(() => {
  void loadAutoApply();
});
</script>

<template>
  <div class="space-y-6 font-sans">
    <!-- Header -->
    <div class="border-b border-border pb-4">
      <h1 class="text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
        <Settings class="w-5 h-5 text-muted-foreground" />
        <span>System Settings & Cluster Integration</span>
      </h1>
      <p class="text-sm text-muted-foreground mt-1 leading-relaxed">
        Distributed cluster topology, deployment promotion policy, and programmatic API access credentials.
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
      <template v-if="activeTab === 'cluster'">
        <!-- Deployment & Promotion Policy Card -->
        <Card data-testid="settings-deployment-policy-card">
          <CardHeader class="pb-2">
            <div class="flex items-center justify-between">
              <div class="flex items-center gap-2">
                <Rocket class="w-4 h-4 text-primary" />
                <CardTitle class="text-base font-semibold text-foreground">
                  Deployment & Promotion Policy
                </CardTitle>
              </div>
              <Badge
                variant="outline"
                class="font-mono text-xs uppercase"
                :class="autoApply ? 'border-primary/40 text-primary bg-primary/10' : 'border-warning/40 text-warning bg-warning/10'"
                data-testid="auto-apply-badge"
              >
                {{ autoApply ? 'Auto-Apply Live' : 'Manual Staging' }}
              </Badge>
            </div>
          </CardHeader>

          <CardContent class="pt-2 space-y-4">
            <p class="text-xs text-muted-foreground leading-relaxed">
              Choose how configuration changes (sites, ACL rules, bot mitigations, semantic modes) are committed to the data plane.
            </p>

            <p v-if="autoApplyError" class="text-xs text-destructive" data-testid="auto-apply-error">
              {{ autoApplyError }}
            </p>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
              <!-- Auto Apply Option Card -->
              <div
                class="p-4 rounded-lg border text-left transition-all cursor-pointer relative"
                :class="autoApply ? 'border-primary bg-primary/5 ring-1 ring-primary' : 'border-border bg-card hover:bg-muted/50 text-muted-foreground'"
                data-testid="option-auto-apply"
                @click="setAutoApplyMode(true)"
              >
                <div class="flex items-center justify-between mb-2">
                  <div class="flex items-center gap-2">
                    <Zap class="w-4 h-4" :class="autoApply ? 'text-primary' : 'text-muted-foreground'" />
                    <span class="text-xs font-semibold text-foreground">Automatic Live Apply</span>
                  </div>
                  <Check v-if="autoApply" class="w-4 h-4 text-primary" />
                </div>
                <p class="text-xs text-muted-foreground leading-relaxed">
                  Every change is compiled and hot-swapped into the running Caddy data plane immediately. Zero manual deploy steps; roll back anytime via snapshot history.
                </p>
              </div>

              <!-- Manual Staging Option Card -->
              <div
                class="p-4 rounded-lg border text-left transition-all cursor-pointer relative"
                :class="!autoApply ? 'border-warning bg-warning/5 ring-1 ring-warning' : 'border-border bg-card hover:bg-muted/50 text-muted-foreground'"
                data-testid="option-manual-staging"
                @click="setAutoApplyMode(false)"
              >
                <div class="flex items-center justify-between mb-2">
                  <div class="flex items-center gap-2">
                    <GitCommit class="w-4 h-4" :class="!autoApply ? 'text-warning' : 'text-muted-foreground'" />
                    <span class="text-xs font-semibold text-foreground">Manual Staged Promotion</span>
                  </div>
                  <Check v-if="!autoApply" class="w-4 h-4 text-warning" />
                </div>
                <p class="text-xs text-muted-foreground leading-relaxed">
                  Changes accumulate in the draft workspace without affecting live traffic. An operator must review unified diffs and manually trigger promotion in Deployments.
                </p>
              </div>
            </div>

            <div class="pt-2 border-t border-border flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
              <span class="text-xs font-mono text-muted-foreground">
                Current engine mode: {{ autoApply ? 'Continuous Live Reload' : 'Staged Gate Promotion' }}
              </span>
              <Button
                variant="outline"
                size="sm"
                class="gap-1.5 text-xs h-8"
                @click="router.push('/deployments')"
              >
                <span>View Staged Diffs & History</span>
                <History class="w-3.5 h-3.5" />
              </Button>
            </div>
          </CardContent>
        </Card>

        <!-- Cluster Status Card -->
        <Card>
          <CardHeader class="pb-2">
            <div class="flex items-center gap-2">
              <Network class="w-4 h-4 text-muted-foreground" />
              <CardTitle class="text-base font-semibold text-foreground">
                Cluster Node & State Synchronization
              </CardTitle>
            </div>
          </CardHeader>

          <CardContent class="pt-2">
            <div class="grid grid-cols-3 gap-3">
              <div class="p-3 bg-muted/50 border border-border rounded-md">
                <span class="text-xs uppercase font-mono text-muted-foreground block mb-1">Operating Mode</span>
                <span class="text-xs font-semibold text-foreground capitalize">
                  {{ configStore.cluster?.mode || 'Standalone' }}
                </span>
              </div>

              <div class="p-3 bg-muted/50 border border-border rounded-md">
                <span class="text-xs uppercase font-mono text-muted-foreground block mb-1">Redis Sync Status</span>
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
                <span class="text-xs uppercase font-mono text-muted-foreground block mb-1">Active Snapshot Version</span>
                <span class="text-xs font-semibold text-primary font-mono">
                  v{{ configStore.activeVersion }}
                </span>
              </div>
            </div>

            <div class="mt-3 pt-3 border-t border-border flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
              <p class="text-xs text-muted-foreground">
                Deploy staged changes and roll the data plane back to any historical snapshot.
              </p>
              <Button
                variant="outline"
                size="sm"
                data-testid="settings-deployment-history"
                class="gap-1.5"
                @click="router.push('/deployments')"
              >
                <History class="w-3.5 h-3.5" />
                <span>Deployment History</span>
              </Button>
            </div>
          </CardContent>
        </Card>

        <!-- Appearance & Theme Card -->
        <Card>
          <CardHeader class="pb-2">
            <div class="flex items-center gap-2">
              <Palette class="w-4 h-4 text-muted-foreground" />
              <CardTitle class="text-base font-semibold text-foreground">
                Interface Theme & Color Mode
              </CardTitle>
            </div>
          </CardHeader>

          <CardContent class="pt-2 space-y-4">
            <p class="text-xs text-muted-foreground">
              Choose your preferred color theme for the Raiwall WAF management console.
            </p>

            <div class="grid grid-cols-3 gap-3">
              <button
                type="button"
                data-testid="theme-select-dark"
                @click="setTheme('dark')"
                class="flex flex-col items-start p-4 rounded-lg border text-left transition-all cursor-pointer"
                :class="theme === 'dark' ? 'border-primary bg-primary/10 text-foreground ring-1 ring-primary' : 'border-border bg-card hover:bg-muted text-muted-foreground'"
              >
                <div class="flex items-center gap-2 mb-2">
                  <Moon class="w-4 h-4" :class="theme === 'dark' ? 'text-primary' : 'text-muted-foreground'" />
                  <span class="text-xs font-semibold text-foreground">Dark Mode</span>
                </div>
                <span class="text-xs text-muted-foreground">Default high-contrast dark theme optimized for SOC operations.</span>
              </button>

              <button
                type="button"
                data-testid="theme-select-light"
                @click="setTheme('light')"
                class="flex flex-col items-start p-4 rounded-lg border text-left transition-all cursor-pointer"
                :class="theme === 'light' ? 'border-primary bg-primary/10 text-foreground ring-1 ring-primary' : 'border-border bg-card hover:bg-muted text-muted-foreground'"
              >
                <div class="flex items-center gap-2 mb-2">
                  <Sun class="w-4 h-4" :class="theme === 'light' ? 'text-warning' : 'text-muted-foreground'" />
                  <span class="text-xs font-semibold text-foreground">Light Mode</span>
                </div>
                <span class="text-xs text-muted-foreground">Clean, high-legibility light theme for daytime administrative review.</span>
              </button>

              <button
                type="button"
                data-testid="theme-select-system"
                @click="setTheme('system')"
                class="flex flex-col items-start p-4 rounded-lg border text-left transition-all cursor-pointer"
                :class="theme === 'system' ? 'border-primary bg-primary/10 text-foreground ring-1 ring-primary' : 'border-border bg-card hover:bg-muted text-muted-foreground'"
              >
                <div class="flex items-center gap-2 mb-2">
                  <Monitor class="w-4 h-4" :class="theme === 'system' ? 'text-primary' : 'text-muted-foreground'" />
                  <span class="text-xs font-semibold text-foreground">System Match</span>
                </div>
                <span class="text-xs text-muted-foreground">Automatically synchronizes with your OS color scheme preference.</span>
              </button>
            </div>
          </CardContent>
        </Card>
      </template>

      <!-- TLS Certificates -->
      <Card v-else-if="activeTab === 'certificates'" class="p-4">
        <CertificatesPanel />
      </Card>

      <!-- API Keys Manager -->
      <Card v-else-if="activeTab === 'apikeys'" class="p-4">
        <ApiKeysManager />
      </Card>

      <!-- Operator accounts -->
      <Card v-else-if="activeTab === 'users'" class="p-4">
        <UsersPanel />
      </Card>
    </div>
  </div>
</template>
