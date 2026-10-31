<script setup lang="ts">
import { ref, computed, onMounted, onBeforeUnmount, nextTick } from 'vue';
import { useRouter } from '@/router';
import { useConfigStore } from '@/stores/config';
import { useAuthStore } from '@/stores/auth';
import { useTheme } from '@/composables/useTheme';
import {
  Search,
  X,
  TrendingUp,
  Globe,
  ShieldAlert,
  ShieldCheck,
  Activity,
  Bot,
  Braces,
  Lock,
  Settings,
  Rocket,
  FileCode,
  Users,
  Sun,
  Moon,
  LogOut,
  Sliders,
  Radio,
  ScrollText,
  ListChecks,
  Package,
} from 'lucide-vue-next';

interface SearchItem {
  id: string;
  title: string;
  category: 'Navigation' | 'Sites' | 'Actions';
  icon: any;
  path?: string;
  action?: () => void;
  description?: string;
}

const router = useRouter();
const configStore = useConfigStore();
const authStore = useAuthStore();
const { isDark, toggleTheme } = useTheme();

const props = withDefaults(
  defineProps<{
    collapsed?: boolean;
  }>(),
  {
    collapsed: false,
  }
);

const isOpen = ref(false);
const searchQuery = ref('');
const selectedIndex = ref(0);
const searchInputRef = ref<HTMLInputElement | null>(null);
const resultsListRef = ref<HTMLElement | null>(null);

const staticNavItems: SearchItem[] = [
  { id: 'nav-stats', title: 'Statistics & Threat Radar', category: 'Navigation', icon: TrendingUp, path: '/statistics', description: 'Real-time telemetry, QPS, and threat distribution' },
  { id: 'nav-sites', title: 'Protected Applications', category: 'Navigation', icon: Globe, path: '/sites', description: 'Application upstreams, hostnames, and routing' },
  { id: 'nav-attacks', title: 'Live Telemetry & Attacks', category: 'Navigation', icon: ShieldAlert, path: '/attacks', description: 'Streaming forensics, inspection, and incidents' },
  { id: 'nav-incidents', title: 'Incident Radar & Clusters', category: 'Navigation', icon: Radio, path: '/attacks?view=incidents', description: 'Correlated multi-vector security incidents' },
  { id: 'nav-logs', title: 'Security Forensic Logs', category: 'Navigation', icon: ScrollText, path: '/attacks?tab=logs', description: 'Historical SQLite/ClickHouse security audit records' },
  { id: 'nav-acls', title: 'Allow & Deny ACL Rules', category: 'Navigation', icon: ShieldCheck, path: '/allow-deny', description: 'Sub-15ns compiled bytecode access control' },
  { id: 'nav-detection', title: 'Detection Overview & Policy', category: 'Navigation', icon: Sliders, path: '/detection', description: 'Detection mode, sensitivity preset, and per-site policies' },
  { id: 'nav-exceptions', title: 'Exceptions Gate', category: 'Navigation', icon: ShieldCheck, path: '/detection/exceptions', description: 'Parameter-level false-positive bypass rules' },
  { id: 'nav-rules', title: 'Rule Tester', category: 'Navigation', icon: Sliders, path: '/detection/tester', description: 'Test and inspect live WAF rule evaluation' },
  { id: 'nav-flood', title: 'HTTP Flood & Rate Limiting', category: 'Navigation', icon: Activity, path: '/http-flood/limits', description: 'Tiered velocity limits, active bans, and unblock' },
  { id: 'nav-waiting-room', title: 'Waiting Room Queue Buffer', category: 'Navigation', icon: Users, path: '/http-flood/waiting-room', description: 'Stateless concurrency buffer and token queue' },
  { id: 'nav-bot', title: 'Anti-Bot Mitigation', category: 'Navigation', icon: Bot, path: '/anti-bot', description: 'JA4 TLS fingerprinting, PoW challenges, and honeypots' },
  { id: 'nav-rule-catalog', title: 'Rule Catalog', category: 'Navigation', icon: ListChecks, path: '/detection/rules', description: 'Semantic modules, CVE patches, and imported pack rules' },
  { id: 'nav-rule-packs', title: 'Rule Packs & Imports', category: 'Navigation', icon: Package, path: '/detection/packs', description: 'Install, enable, and remove external signature packs' },
  { id: 'nav-semantics', title: 'Semantic Detection Matrix', category: 'Navigation', icon: Braces, path: '/detection/modules', description: 'libinjection lexical triage and bounded AST verification' },
  { id: 'nav-block-pages', title: 'Block Pages & Templates', category: 'Navigation', icon: FileCode, path: '/block-pages', description: 'Custom challenge and interstitial HTML block pages' },
  { id: 'nav-auth-logs', title: 'Auth Gateway — Logs', category: 'Navigation', icon: ScrollText, path: '/auth-gateway/logs', description: 'Directory login attempts and clearance audits' },
  { id: 'nav-auth-users', title: 'Auth Gateway — Users', category: 'Navigation', icon: Users, path: '/auth-gateway/users', description: 'Pre-app identity accounts, passwords, and 2FA' },
  { id: 'nav-auth-sso', title: 'Auth Gateway — Single Sign-On', category: 'Navigation', icon: Radio, path: '/auth-gateway/sso', description: 'HTTP 467 portal and per-site clearance binding' },
  { id: 'nav-auth-idp', title: 'Auth Gateway — IdP Config', category: 'Navigation', icon: Lock, path: '/auth-gateway/idp', description: 'OIDC, LDAP, and OAuth2 identity connectors' },
  { id: 'nav-deployments', title: 'Deployments & Rollback History', category: 'Navigation', icon: Rocket, path: '/deployments', description: 'Atomic snapshot swaps and version rollbacks' },
  { id: 'nav-settings', title: 'System Settings & Cluster', category: 'Navigation', icon: Settings, path: '/system', description: 'Cluster topology, Redis sync, and TLS certs' },
];

const allSearchItems = computed<SearchItem[]>(() => {
  const items: SearchItem[] = [...staticNavItems];

  // Dynamically include user sites
  if (configStore.sites?.length) {
    for (const site of configStore.sites) {
      const primaryHost = site.hostnames?.[0] || 'localhost';
      items.push({
        id: `site-${site.id}`,
        title: site.name || primaryHost,
        category: 'Sites',
        icon: Globe,
        path: `/sites/${site.id}`,
        description: `Upstreams: ${site.upstreams?.map((u) => u.dial).join(', ') || 'direct'}`,
      });
    }
  }

  // Quick actions
  items.push({
    id: 'act-theme',
    title: isDark.value ? 'Switch to Light Mode' : 'Switch to Dark Mode',
    category: 'Actions',
    icon: isDark.value ? Sun : Moon,
    action: () => toggleTheme(),
    description: 'Toggle interface visual theme appearance',
  });

  if (configStore.hasDraftChanges) {
    items.push({
      id: 'act-deploy',
      title: 'Review Staged Deployments',
      category: 'Actions',
      icon: Rocket,
      path: '/deployments',
      description: `${configStore.diffs.length} pending changes ready for rollout`,
    });
  }

  items.push({
    id: 'act-logout',
    title: 'Sign Out Operator Session',
    category: 'Actions',
    icon: LogOut,
    action: async () => {
      await authStore.logout();
      router.push('/login');
    },
    description: `Signed in as ${authStore.user?.username || 'admin'}`,
  });

  return items;
});

const filteredItems = computed<SearchItem[]>(() => {
  const q = searchQuery.value.trim().toLowerCase();
  if (!q) {
    return allSearchItems.value;
  }
  return allSearchItems.value.filter((item) => {
    return (
      item.title.toLowerCase().includes(q) ||
      item.category.toLowerCase().includes(q) ||
      (item.description && item.description.toLowerCase().includes(q))
    );
  });
});

const scrollToSelected = () => {
  nextTick(() => {
    const container = resultsListRef.value;
    if (!container) return;
    const items = container.querySelectorAll<HTMLElement>('[role="option"]');
    const target = items[selectedIndex.value];
    if (!target) return;

    const containerTop = container.scrollTop;
    const containerBottom = containerTop + container.clientHeight;
    const targetTop = target.offsetTop;
    const targetBottom = targetTop + target.offsetHeight;

    if (targetTop < containerTop) {
      container.scrollTop = targetTop;
    } else if (targetBottom > containerBottom) {
      container.scrollTop = targetBottom - container.clientHeight;
    }
  });
};

const navigateDown = () => {
  if (filteredItems.value.length === 0) return;
  selectedIndex.value = (selectedIndex.value + 1) % filteredItems.value.length;
  scrollToSelected();
};

const navigateUp = () => {
  if (filteredItems.value.length === 0) return;
  selectedIndex.value = (selectedIndex.value - 1 + filteredItems.value.length) % filteredItems.value.length;
  scrollToSelected();
};

const selectCurrent = () => {
  const item = filteredItems.value[selectedIndex.value];
  if (item) {
    executeItem(item);
  }
};

const onInput = () => {
  selectedIndex.value = 0;
  nextTick(() => {
    if (resultsListRef.value) {
      resultsListRef.value.scrollTop = 0;
    }
  });
};

const openSearch = () => {
  isOpen.value = true;
  searchQuery.value = '';
  selectedIndex.value = 0;
  nextTick(() => {
    searchInputRef.value?.focus();
    if (resultsListRef.value) {
      resultsListRef.value.scrollTop = 0;
    }
  });
};

const closeSearch = () => {
  isOpen.value = false;
  searchQuery.value = '';
};

const executeItem = (item: SearchItem) => {
  closeSearch();
  if (item.action) {
    item.action();
  } else if (item.path) {
    router.push(item.path);
  }
};

const handleKeydown = (e: KeyboardEvent) => {
  // Global ⌘K / Ctrl+K / '/' handler
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    if (isOpen.value) {
      closeSearch();
    } else {
      openSearch();
    }
    return;
  }

  // Open search on forward slash when not in an editable field
  if (
    !isOpen.value &&
    e.key === '/' &&
    !(e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement || (e.target as HTMLElement)?.isContentEditable)
  ) {
    e.preventDefault();
    openSearch();
    return;
  }

  if (isOpen.value) {
    if (e.key === 'Escape') {
      e.preventDefault();
      closeSearch();
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      navigateDown();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      navigateUp();
    } else if (e.key === 'PageDown') {
      e.preventDefault();
      if (filteredItems.value.length > 0) {
        selectedIndex.value = Math.min(filteredItems.value.length - 1, selectedIndex.value + 5);
        scrollToSelected();
      }
    } else if (e.key === 'PageUp') {
      e.preventDefault();
      if (filteredItems.value.length > 0) {
        selectedIndex.value = Math.max(0, selectedIndex.value - 5);
        scrollToSelected();
      }
    } else if (e.key === 'Home' && document.activeElement !== searchInputRef.value) {
      e.preventDefault();
      selectedIndex.value = 0;
      scrollToSelected();
    } else if (e.key === 'End' && document.activeElement !== searchInputRef.value) {
      e.preventDefault();
      selectedIndex.value = filteredItems.value.length - 1;
      scrollToSelected();
    } else if (e.key === 'Enter') {
      e.preventDefault();
      selectCurrent();
    }
  }
};

onMounted(() => {
  window.addEventListener('keydown', handleKeydown);
});

onBeforeUnmount(() => {
  window.removeEventListener('keydown', handleKeydown);
});
</script>

<template>
  <div data-testid="navbar-search-menu" class="w-full flex items-center justify-center">
    <!-- Collapsed Trigger Button -->
    <button
      v-if="collapsed"
      type="button"
      data-testid="navbar-search-trigger"
      @click="openSearch"
      class="w-10 h-10 flex items-center justify-center rounded-lg border border-border bg-muted/40 hover:bg-muted text-muted-foreground hover:text-foreground transition-colors cursor-pointer select-none"
      title="Search routes, sites, actions (⌘K)"
      aria-label="Search routes, sites, actions"
    >
      <Search class="w-4 h-4 shrink-0 text-muted-foreground" />
    </button>

    <!-- Expanded Trigger Button -->
    <button
      v-else
      type="button"
      data-testid="navbar-search-trigger"
      @click="openSearch"
      class="w-full flex items-center justify-between gap-2 px-3 py-1.5 rounded-lg border border-border bg-muted/40 hover:bg-muted text-muted-foreground hover:text-foreground text-xs font-medium transition-colors cursor-pointer select-none"
    >
      <div class="flex items-center gap-2 min-w-0">
        <Search class="w-3.5 h-3.5 shrink-0 text-muted-foreground" />
        <span class="truncate text-muted-foreground">Search routes, sites, actions...</span>
      </div>
      <kbd class="inline-flex items-center gap-0.5 rounded border border-border bg-card px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
        <span>⌘</span>K
      </kbd>
    </button>

    <!-- Modal Dialog / Command Palette Overlay -->
    <Teleport to="body">
      <div
        v-if="isOpen"
        class="fixed inset-0 z-50 flex items-start justify-center pt-16 sm:pt-24 px-4 bg-black/60 backdrop-blur-sm animate-in fade-in-0 duration-150"
        @click.self="closeSearch"
      >
        <div
          data-testid="navbar-search-dialog"
          role="dialog"
          aria-modal="true"
          aria-label="Command search palette"
          class="w-full max-w-xl bg-card border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden animate-in zoom-in-95 duration-150"
        >
          <!-- Input Bar -->
          <div class="flex items-center gap-3 px-4 py-3 border-b border-border bg-card">
            <Search class="w-4 h-4 text-muted-foreground shrink-0" />
            <input
              ref="searchInputRef"
              v-model="searchQuery"
              data-testid="navbar-search-input"
              type="text"
              aria-label="Search routes, sites, or actions"
              aria-autocomplete="list"
              placeholder="Type a command, route, or site name..."
              class="flex-1 bg-transparent border-0 outline-none text-foreground text-sm placeholder:text-muted-foreground"
              @input="onInput"
              @keydown.down.prevent="navigateDown"
              @keydown.up.prevent="navigateUp"
              @keydown.enter.prevent="selectCurrent"
              @keydown.esc.prevent="closeSearch"
            />
            <button
              type="button"
              data-testid="navbar-search-close"
              aria-label="Close search"
              class="p-1 rounded-md text-muted-foreground hover:text-foreground hover:bg-muted transition-colors cursor-pointer"
              @click="closeSearch"
            >
              <X class="w-4 h-4" />
            </button>
          </div>

          <!-- Result Items List -->
          <div
            ref="resultsListRef"
            role="listbox"
            aria-label="Search results"
            class="max-h-[380px] overflow-y-auto p-2 space-y-1"
          >
            <div
              v-if="filteredItems.length === 0"
              class="py-8 text-center text-sm text-muted-foreground"
            >
              No matching routes, sites, or actions found for "{{ searchQuery }}".
            </div>

            <button
              v-for="(item, idx) in filteredItems"
              :key="item.id"
              :data-testid="'search-result-' + item.id"
              type="button"
              role="option"
              :aria-selected="selectedIndex === idx"
              @click="executeItem(item)"
              @mouseenter="selectedIndex = idx"
              :class="[
                'w-full flex items-center justify-between gap-3 px-3 py-2 rounded-lg text-left text-sm transition-colors cursor-pointer',
                selectedIndex === idx
                  ? 'bg-primary/10 text-primary'
                  : 'text-foreground hover:bg-muted'
              ]"
            >
              <div class="flex items-center gap-2.5 min-w-0">
                <component
                  :is="item.icon"
                  class="w-4 h-4 shrink-0"
                  :class="selectedIndex === idx ? 'text-primary' : 'text-muted-foreground'"
                />
                <div class="min-w-0">
                  <div class="font-medium truncate text-foreground">{{ item.title }}</div>
                  <div v-if="item.description" class="text-xs text-muted-foreground truncate">
                    {{ item.description }}
                  </div>
                </div>
              </div>
              <span
                class="text-xs font-mono uppercase px-1.5 py-0.5 rounded border shrink-0"
                :class="
                  item.category === 'Sites'
                    ? 'border-info/30 bg-info/10 text-info'
                    : item.category === 'Actions'
                    ? 'border-warning/30 bg-warning/10 text-warning'
                    : 'border-border bg-muted/60 text-muted-foreground'
                "
              >
                {{ item.category }}
              </span>
            </button>
          </div>

          <!-- Footer Shortcut Hints -->
          <div class="px-4 py-2 border-t border-border bg-muted/30 flex items-center justify-between text-xs text-muted-foreground">
            <div class="flex items-center gap-3">
              <span><kbd class="font-mono">↑</kbd><kbd class="font-mono">↓</kbd> Navigate</span>
              <span><kbd class="font-mono">↵</kbd> Select</span>
              <span><kbd class="font-mono">Esc</kbd> Close</span>
            </div>
            <span>{{ filteredItems.length }} results</span>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>
