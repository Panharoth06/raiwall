<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue';
import { useRoute, useRouter } from '@/router';
import { api, type Site } from '@/api/client';
import ForwardingRulesEditor from '@/components/site-detail/ForwardingRulesEditor.vue';
import ProxyConfigEditor from '@/components/site-detail/ProxyConfigEditor.vue';
import ApiInventoryTable from '@/components/site-detail/ApiInventoryTable.vue';
import { Tabs, type Tab } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { ArrowLeft, Boxes, MonitorDot, Route, Sliders } from 'lucide-vue-next';

type SiteTab = 'basic' | 'rules' | 'proxy' | 'inventory';

const route = useRoute();
const router = useRouter();

const site = ref<Site | null>(null);
const loading = ref(true);
const error = ref('');

const siteId = computed(() => route.value.params?.id || '');

const activeTab = computed<SiteTab>(() => {
  const path = route.value.path || '';
  if (path.includes('rules')) return 'rules';
  if (path.includes('proxy')) return 'proxy';
  if (path.includes('inventory')) return 'inventory';
  return 'basic';
});

const loadSite = async () => {
  loading.value = true;
  error.value = '';
  site.value = null;
  try {
    const sites = await api.listSites();
    site.value = sites.find((s) => s.id === siteId.value) || null;
    if (!site.value) {
      error.value = 'Site not found — it may have been deleted.';
    }
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to load site';
  } finally {
    loading.value = false;
  }
};

onMounted(loadSite);
watch(siteId, loadSite);

const tabs: (Tab & { id: SiteTab })[] = [
  {
    id: 'basic',
    label: 'Basic Information',
    icon: Boxes,
    description: 'Metadata, bound hostnames, upstreams, and operational mode',
    testId: 'tab-site-basic',
  },
  {
    id: 'rules',
    label: 'Forwarding Rules',
    icon: Route,
    description: 'Path-prefix routing into dedicated upstream pools',
    testId: 'tab-site-rules',
  },
  {
    id: 'proxy',
    label: 'Advanced Settings',
    icon: Sliders,
    description: 'XFF, HSTS, SSE, compression, IPv6, and redirect matrix',
    testId: 'tab-site-proxy',
  },
  {
    id: 'inventory',
    label: 'Routings / API Inventory',
    icon: MonitorDot,
    description: 'Auto-discovered endpoint catalog from live traffic',
    testId: 'tab-site-inventory',
  },
];

// Local alias keeps the lucide import list stable with the template icons.
// Local alias keeps the lucide import list stable with the template icons.
const handleTabChange = (tabId: string) => {
  const map: Record<SiteTab, string> = {
    basic: `/sites/${siteId.value}`,
    rules: `/sites/${siteId.value}/rules`,
    proxy: `/sites/${siteId.value}/proxy`,
    inventory: `/sites/${siteId.value}/inventory`,
  };
  router.push(map[tabId as SiteTab] ?? `/sites/${siteId.value}`);
};

const modeVariant = (mode?: string): 'default' | 'destructive' | 'secondary' => {
  if (mode === 'defense') return 'default';
  if (mode === 'offline') return 'destructive';
  return 'secondary';
};
</script>

<template>
  <div class="h-full flex flex-col space-y-4 p-6 bg-card text-card-foreground rounded-xl border border-border shadow-none font-sans overflow-hidden">
    <div class="shrink-0">
      <button class="text-[10px] uppercase tracking-wider text-muted-foreground hover:text-foreground flex items-center gap-1 mb-2" data-testid="site-back" @click="router.push('/sites')">
        <ArrowLeft class="w-3 h-3" />
        All Sites
      </button>
      <h1 class="text-sm font-semibold uppercase tracking-wider text-foreground flex items-center gap-2">
        <Boxes class="w-4 h-4 text-muted-foreground" />
        <span data-testid="site-name">{{ site?.name || (loading ? 'Loading…' : 'Site Detail') }}</span>
        <Badge v-if="site" :variant="modeVariant(site.mode)" class="text-[10px] uppercase" data-testid="site-mode-badge">
          {{ site.mode }}
        </Badge>
      </h1>
      <p class="text-xs font-mono text-muted-foreground mt-1" data-testid="site-hostnames">{{ site?.hostnames.join(' · ') || '—' }}</p>
    </div>

    <div class="border-b border-border pb-1.5 shrink-0">
      <Tabs :tabs="tabs" :active-tab="activeTab" @tab-change="handleTabChange" />
    </div>

    <div class="flex-1 min-h-0 overflow-y-auto pr-1">
      <p v-if="error" class="text-sm text-destructive" data-testid="site-error">{{ error }}</p>
      <div v-else-if="loading" class="flex items-center justify-center py-16 text-xs text-muted-foreground" data-testid="site-loading">
        Loading site configuration…
      </div>

      <template v-else-if="site">
        <!-- 1. Basic Information -->
        <div v-if="activeTab === 'basic'" class="space-y-3" data-testid="site-panel-basic">
          <div class="border border-border rounded-lg divide-y divide-border bg-background">
            <div class="px-3 py-2.5 flex items-center justify-between" data-testid="site-basic-mode">
              <span class="text-xs text-muted-foreground">Operational Mode</span>
              <Badge :variant="modeVariant(site.mode)" class="text-[10px] uppercase font-mono">{{ site.mode }}</Badge>
            </div>
            <div class="px-3 py-2.5" data-testid="site-basic-upstreams">
              <span class="text-xs text-muted-foreground">Default Upstream Pool</span>
              <p class="text-xs font-mono mt-0.5">
                {{ site.upstreams.map((u) => `${u.dial} (w${u.weight})`).join(', ') || '— none —' }}
              </p>
            </div>
            <div class="px-3 py-2.5 flex items-center justify-between" data-testid="site-basic-status-codes">
              <span class="text-xs text-muted-foreground">Block / Offline Status</span>
              <span class="text-xs font-mono tabular-nums">{{ site.block_status_code }} / {{ site.offline_status_code }}</span>
            </div>
            <div class="px-3 py-2.5" data-testid="site-basic-headers">
              <span class="text-xs text-muted-foreground">Custom Response Headers</span>
              <p class="text-xs font-mono mt-0.5 truncate" :title="Object.keys(site.custom_headers || {}).join(', ')">
                {{ Object.keys(site.custom_headers || {}).length || '0' }} configured
              </p>
            </div>
          </div>
        </div>

        <!-- 2. Forwarding Rules -->
        <ForwardingRulesEditor v-else-if="activeTab === 'rules'" :site="site" />

        <!-- 3. Advanced Settings -->
        <ProxyConfigEditor v-else-if="activeTab === 'proxy'" :site="site" />

        <!-- 4. Routings / API Inventory -->
        <ApiInventoryTable v-else :site-id="site.id" class="block" />
      </template>
    </div>
  </div>
</template>
