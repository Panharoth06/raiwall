<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { useRouter, useRoute } from '@/router';
import { useAuthStore } from '@/stores/auth';
import { useConfigStore } from '@/stores/config';
import {
  TrendingUp,
  Globe,
  ShieldAlert,
  ShieldCheck,
  Activity,
  Bot,
  Lock,
  Settings,
  Gauge,
  LogOut,
  AlertTriangle,
  Building2,
} from 'lucide-vue-next';
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';

const router = useRouter();
const route = useRoute();
const authStore = useAuthStore();
const configStore = useConfigStore();

const selectedTenant = ref('default');

onMounted(async () => {
  await authStore.fetchCurrentUser();
  if (!authStore.isAuthenticated) {
    router.push('/login');
    return;
  }
  configStore.loadAll();
});

const currentPath = computed(() => route.value.path || '/');

export interface NavChildItem {
  name: string;
  path: string;
  testId: string;
}

export interface NavItem {
  name: string;
  path: string;
  icon: any;
  testId: string;
  children?: NavChildItem[];
}

const navItems: NavItem[] = [
  { name: 'Statistics', path: '/statistics', icon: TrendingUp, testId: 'nav-statistics' },
  { name: 'Applications', path: '/sites', icon: Globe, testId: 'nav-applications' },
  { name: 'Attacks', path: '/attacks', icon: ShieldAlert, testId: 'nav-attacks' },
  { name: 'Allow & Deny', path: '/allow-deny', icon: ShieldCheck, testId: 'nav-allow-deny' },
  {
    name: 'HTTP Flood',
    path: '/http-flood',
    icon: Activity,
    testId: 'nav-http-flood',
    children: [
      { name: 'Rate Limiting', path: '/http-flood/limits', testId: 'nav-http-flood-limits' },
      { name: 'Waiting Room', path: '/http-flood/waiting-room', testId: 'nav-http-flood-waiting-room' },
    ],
  },
  { name: 'Anti-Bot', path: '/anti-bot', icon: Bot, testId: 'nav-anti-bot' },
  { name: 'Auth', path: '/auth', icon: Lock, testId: 'nav-auth' },
  { name: 'Settings', path: '/system', icon: Settings, testId: 'nav-settings' },
];

const isItemActive = (path: string): boolean => {
  if (path === '/statistics') {
    return currentPath.value === '/' || currentPath.value.startsWith('/statistics');
  }
  if (path === '/allow-deny') {
    return currentPath.value.startsWith('/allow-deny') || currentPath.value.startsWith('/acls');
  }
  if (path === '/system') {
    return currentPath.value.startsWith('/system') || currentPath.value.startsWith('/settings');
  }
  return currentPath.value.startsWith(path);
};

const isChildActive = (childPath: string): boolean => {
  if (childPath === '/http-flood/limits') {
    return (
      currentPath.value === '/http-flood' ||
      currentPath.value.startsWith('/http-flood/limits')
    );
  }
  return currentPath.value.startsWith(childPath);
};

const isTopologyActive = computed(() => currentPath.value.startsWith('/topology') || currentPath.value.startsWith('/command-center'));

const navigateTo = (path: string) => {
  router.push(path);
};

const handleLogout = async () => {
  await authStore.logout();
  router.push('/login');
};
</script>

<template>
  <div class="h-full w-full overflow-hidden bg-background text-foreground flex font-sans">
    <!-- Persistent Left Sidebar with Command Center Theme -->
    <aside
      data-testid="nav-rail"
      class="w-60 h-full bg-card border-r border-border flex flex-col flex-shrink-0 select-none overflow-hidden"
    >
      <!-- Brand Header with Crisp High-Resolution PNG Logo -->
      <div class="h-14 px-4 border-b border-border flex items-center justify-between flex-shrink-0">
        <div data-testid="brand-logo" class="flex items-center gap-2.5">
          <img
            src="/logo.png"
            alt="Raiwall"
            class="w-8 h-8 object-contain flex-shrink-0"
            style="image-rendering: -webkit-optimize-contrast;"
          />
          <span class="font-bold text-foreground text-base tracking-tight block">Raiwall</span>
        </div>
      </div>

      <!-- Operations / Command Center Quick Access -->
      <div class="p-3 pb-1 border-b border-border/50 flex-shrink-0">
        <button
          data-testid="nav-topology"
          @click="navigateTo('/topology')"
          :class="[
            'relative w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-[15px] font-medium transition-colors text-left cursor-pointer overflow-hidden',
            isTopologyActive
              ? 'bg-primary/10 text-primary border-l-[3px] border-primary rounded-l-none font-semibold'
              : 'text-muted-foreground hover:text-foreground hover:bg-muted'
          ]"
        >
          <div v-if="isTopologyActive" class="absolute left-0 top-0 bottom-0 w-[3px] bg-primary"></div>
          <Gauge class="w-[18px] h-[18px] flex-shrink-0" :class="isTopologyActive ? 'text-primary' : 'text-muted-foreground'" />
          <span class="truncate font-semibold" :class="isTopologyActive ? 'text-foreground' : 'text-muted-foreground'">Command Center</span>
        </button>
      </div>

      <!-- SafeLine 8-Domain Navigation Links with Vertical Auto-Scroll -->
      <nav class="flex-1 min-h-0 px-3 py-2 space-y-1 overflow-y-auto">
        <div v-for="item in navItems" :key="item.path" class="space-y-0.5">
          <button
            :data-testid="item.testId"
            @click="navigateTo(item.path)"
            :class="[
              'relative w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-[15px] font-medium transition-colors text-left cursor-pointer overflow-hidden',
              isItemActive(item.path)
                ? 'bg-primary/10 text-primary border-l-[3px] border-primary rounded-l-none font-semibold'
                : 'text-muted-foreground hover:text-foreground hover:bg-muted'
            ]"
          >
            <div
              v-if="isItemActive(item.path)"
              class="absolute left-0 top-0 bottom-0 w-[3px] bg-primary"
            />
            <component
              :is="item.icon"
              class="w-[18px] h-[18px] flex-shrink-0"
              :class="isItemActive(item.path) ? 'text-primary' : 'text-muted-foreground'"
            />
            <span class="truncate" :class="isItemActive(item.path) ? 'text-foreground' : 'text-muted-foreground'">{{ item.name }}</span>
          </button>

          <!-- SafeLine Expandable Sub-Menu for HTTP Flood -->
          <div
            v-if="item.children && isItemActive(item.path)"
            class="ml-6 pl-2.5 border-l border-border/80 space-y-0.5 py-1"
          >
            <button
              v-for="child in item.children"
              :key="child.path"
              :data-testid="child.testId"
              @click="navigateTo(child.path)"
              :class="[
                'w-full flex items-center gap-2 px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors text-left cursor-pointer',
                isChildActive(child.path)
                  ? 'text-primary font-semibold bg-primary/10'
                  : 'text-muted-foreground hover:text-foreground hover:bg-muted/60'
              ]"
            >
              <span
                class="w-1.5 h-1.5 rounded-full shrink-0"
                :class="isChildActive(child.path) ? 'bg-primary' : 'bg-muted-foreground/40'"
              />
              <span class="truncate">{{ child.name }}</span>
            </button>
          </div>
        </div>
      </nav>

      <!-- Bottom User Profile & Session Controls with Pinned mt-auto -->
      <div class="p-3 border-t border-border bg-card flex flex-col gap-2.5 mt-auto flex-shrink-0">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-2.5 min-w-0">
            <div class="h-8 w-8 rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center text-xs font-bold text-primary flex-shrink-0">
              {{ authStore.user?.username?.slice(0, 2).toUpperCase() || 'AD' }}
            </div>
            <div class="min-w-0">
              <span class="text-[13px] font-medium text-foreground block truncate">
                {{ authStore.user?.username || 'Operator' }}
              </span>
              <span class="text-[11px] text-primary uppercase tracking-wider block font-semibold font-mono">
                {{ authStore.user?.role || 'admin' }}
              </span>
            </div>
          </div>
          <button
            data-testid="logout-btn"
            @click="handleLogout"
            title="Sign out"
            class="p-1.5 text-muted-foreground hover:text-threat hover:bg-muted rounded-md transition-colors cursor-pointer"
          >
            <LogOut class="w-4 h-4" />
          </button>
        </div>

        <!-- Node Mode / Cluster Status Indicator (Moved from Top Navbar) -->
        <div class="pt-2 border-t border-border/70 flex items-center justify-between text-xs text-muted-foreground">
          <span class="text-[11px] uppercase font-mono tracking-wider text-muted-foreground">Mode</span>
          <span
            v-if="configStore.cluster?.redis_connected"
            data-testid="cluster-status"
            class="inline-flex items-center gap-1.5 text-success font-medium font-mono text-xs"
          >
            <span class="h-1.5 w-1.5 rounded-full bg-success animate-pulse"></span>
            <span>Cluster Synced</span>
          </span>
          <span
            v-else
            data-testid="cluster-status"
            class="inline-flex items-center gap-1.5 text-muted-foreground font-mono text-xs"
          >
            <span class="h-1.5 w-1.5 rounded-full bg-muted-foreground/60"></span>
            <span>Standalone Mode</span>
          </span>
        </div>
      </div>
    </aside>

    <!-- Main Content Canvas Area -->
    <div class="flex-1 h-full flex flex-col min-w-0 min-h-0 bg-background overflow-hidden">
      <!-- Top Action Bar -->
      <header class="h-14 bg-card border-b border-border px-5 flex items-center justify-between flex-shrink-0">
        <div class="flex items-center gap-3">
          <!-- Tenant / Workspace Selector Component Dropdown -->
          <div class="flex items-center gap-2">
            <Building2 class="w-3.5 h-3.5 text-muted-foreground" />
            <Select v-model="selectedTenant">
              <SelectTrigger
                data-testid="tenant-selector"
                class="h-8 w-56 border-input bg-background text-xs text-foreground"
              >
                <SelectValue />
              </SelectTrigger>
              <SelectContent class="border-border bg-popover text-popover-foreground">
                <SelectItem value="default">Default Tenant (Production)</SelectItem>
                <SelectItem value="staging">Staging Gateway</SelectItem>
                <SelectItem value="dmz">External DMZ Edge</SelectItem>
              </SelectContent>
            </Select>
            <select
              v-model="selectedTenant"
              class="sr-only"
              tabindex="-1"
              aria-hidden="true"
            >
              <option value="default">Default Tenant (Production)</option>
              <option value="staging">Staging Gateway</option>
              <option value="dmz">External DMZ Edge</option>
            </select>
          </div>

          <!-- Staged Deployment Alert Banner -->
          <button
            v-if="configStore.hasDraftChanges"
            data-testid="staged-changes-banner"
            @click="navigateTo('/deployments')"
            class="flex items-center gap-1.5 px-2.5 py-1 bg-warning/10 border border-warning/30 rounded-md text-xs text-warning hover:bg-warning/20 transition-colors cursor-pointer font-medium"
          >
            <AlertTriangle class="w-3.5 h-3.5 text-warning" />
            <span>{{ configStore.diffs.length }} staged changes ready to deploy</span>
          </button>
        </div>

        <!-- Right Side Gateway State / Controls (Cleaned) -->
        <div class="flex items-center gap-3 text-xs text-muted-foreground">
        </div>
      </header>

      <!-- View Slot Content -->
      <main class="flex-1 min-h-0 overflow-y-auto p-4 bg-background flex flex-col">
        <slot />
      </main>
    </div>
  </div>
</template>
