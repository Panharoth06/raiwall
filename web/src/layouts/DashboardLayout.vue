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
  Braces,
  Lock,
  Settings,
  Gauge,
  LogOut,
  AlertTriangle,
  Sun,
  Moon,
  ChevronRight,
  FileCode,
  Menu,
  X,
} from 'lucide-vue-next';
import { useTheme } from '@/composables/useTheme';

const router = useRouter();
const route = useRoute();
const authStore = useAuthStore();
const configStore = useConfigStore();
const { isDark, toggleTheme } = useTheme();

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
  {
    name: 'Detection',
    path: '/semantics',
    icon: Braces,
    testId: 'nav-detection',
    children: [
      { name: 'Semantic Matrix', path: '/semantics', testId: 'nav-semantic-matrix' },
      { name: 'Inner Rules', path: '/inner-rules', testId: 'nav-inner-rules' },
    ],
  },
  { name: 'Block Pages', path: '/block-pages', icon: FileCode, testId: 'nav-block-pages' },
  {
    name: 'Auth Gateway',
    path: '/auth-gateway',
    icon: Lock,
    testId: 'nav-auth-gateway',
    children: [
      { name: 'Authentication Logs', path: '/auth-gateway/logs', testId: 'nav-auth-logs' },
      { name: 'User Management', path: '/auth-gateway/users', testId: 'nav-auth-users' },
      { name: 'Single Sign-On', path: '/auth-gateway/sso', testId: 'nav-auth-sso' },
      { name: 'Login Configuration', path: '/auth-gateway/idp', testId: 'nav-auth-idp' },
    ],
  },
  { name: 'Settings', path: '/system', icon: Settings, testId: 'nav-settings' },
];

const expandedMenus = ref<Record<string, boolean>>({});
const mobileNavOpen = ref(false);

const isExpanded = (path: string): boolean => {
  if (expandedMenus.value[path] !== undefined) {
    return expandedMenus.value[path];
  }
  return isItemActive(path);
};

const toggleMenu = (path: string) => {
  const current = isExpanded(path);
  expandedMenus.value[path] = !current;
};

const handleParentNavClick = (item: NavItem) => {
  if (isItemActive(item.path) && isExpanded(item.path)) {
    toggleMenu(item.path);
  } else {
    expandedMenus.value[item.path] = true;
    navigateTo(item.children?.[0]?.path || item.path);
  }
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

const isTopologyActive = computed(() => currentPath.value.startsWith('/topology') || currentPath.value.startsWith('/command-center'));

const navigateTo = (path: string) => {
  mobileNavOpen.value = false;
  router.push(path);
};

const handleLogout = async () => {
  mobileNavOpen.value = false;
  await authStore.logout();
  router.push('/login');
};
</script>

<template>
  <div class="h-full w-full overflow-hidden bg-background text-foreground flex font-sans">
    <!-- Mobile sidebar backdrop -->
    <div
      v-if="mobileNavOpen"
      class="fixed inset-0 z-30 bg-black/50 lg:hidden"
      aria-hidden="true"
      @click="mobileNavOpen = false"
    />

    <!-- Persistent Left Sidebar with Command Center Theme -->
    <aside
      data-testid="nav-rail"
      class="fixed inset-y-0 left-0 z-40 w-60 h-full bg-card border-r border-border flex flex-col flex-shrink-0 select-none overflow-hidden transition-transform duration-150 lg:static lg:translate-x-0"
      :class="mobileNavOpen ? 'translate-x-0' : '-translate-x-full'"
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
        <button
          type="button"
          data-testid="nav-mobile-close"
          class="lg:hidden flex items-center justify-center w-7 h-7 rounded-md text-muted-foreground hover:text-foreground hover:bg-muted transition-colors cursor-pointer"
          aria-label="Close navigation"
          @click="mobileNavOpen = false"
        >
          <X class="w-4 h-4" />
        </button>
      </div>

      <!-- Operations / Command Center Quick Access -->
      <div class="p-3 pb-1 border-b border-border/50 flex-shrink-0">
        <button
          data-testid="nav-topology"
          @click="navigateTo('/topology')"
          :class="[
            'w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-[15px] font-medium transition-colors text-left cursor-pointer',
            isTopologyActive
              ? 'bg-primary/10 text-primary font-semibold'
              : 'text-muted-foreground hover:text-foreground hover:bg-muted'
          ]"
        >
          <Gauge class="w-[18px] h-[18px] flex-shrink-0" :class="isTopologyActive ? 'text-primary' : 'text-muted-foreground'" />
          <span class="truncate" :class="isTopologyActive ? 'text-foreground font-semibold' : 'text-muted-foreground'">Command Center</span>
        </button>
      </div>

      <!-- SafeLine 8-Domain Navigation Links with Vertical Auto-Scroll -->
      <nav class="flex-1 min-h-0 px-3 py-2 space-y-1 overflow-y-auto">
        <div v-for="item in navItems" :key="item.path" class="space-y-0.5">
          <!-- Standard Nav Item (without children) -->
          <button
            v-if="!item.children"
            :data-testid="item.testId"
            type="button"
            @click="navigateTo(item.path)"
            :class="[
              'w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-[15px] font-medium transition-colors text-left cursor-pointer',
              isItemActive(item.path)
                ? 'bg-primary/10 text-primary font-semibold'
                : 'text-muted-foreground hover:text-foreground hover:bg-muted'
            ]"
          >
            <component
              :is="item.icon"
              class="w-[18px] h-[18px] flex-shrink-0"
              :class="isItemActive(item.path) ? 'text-primary' : 'text-muted-foreground'"
            />
            <span class="truncate" :class="isItemActive(item.path) ? 'text-foreground font-semibold' : 'text-muted-foreground'">{{ item.name }}</span>
          </button>

          <!-- Nav Item with Nested Children (dropdown with arrow toggle) -->
          <div
            v-else
            :class="[
              'w-full flex items-center justify-between rounded-lg text-[15px] font-medium transition-colors',
              isItemActive(item.path)
                ? 'bg-primary/10 text-primary font-semibold'
                : 'text-muted-foreground hover:text-foreground hover:bg-muted'
            ]"
          >
            <button
              :data-testid="item.testId"
              type="button"
              @click="handleParentNavClick(item)"
              class="flex-1 flex items-center gap-3 px-3 py-2.5 text-left cursor-pointer min-w-0"
            >
              <component
                :is="item.icon"
                class="w-[18px] h-[18px] flex-shrink-0"
                :class="isItemActive(item.path) ? 'text-primary' : 'text-muted-foreground'"
              />
              <span class="truncate" :class="isItemActive(item.path) ? 'text-foreground font-semibold' : 'text-muted-foreground'">
                {{ item.name }}
              </span>
            </button>

            <button
              :data-testid="item.testId + '-chevron'"
              type="button"
              @click.stop="toggleMenu(item.path)"
              class="p-2 mr-1 rounded-md text-muted-foreground hover:text-foreground hover:bg-muted/60 transition-colors cursor-pointer flex items-center justify-center shrink-0"
              :title="isExpanded(item.path) ? 'Collapse ' + item.name : 'Drop ' + item.name"
              :aria-label="isExpanded(item.path) ? 'Collapse ' + item.name : 'Drop ' + item.name"
              :aria-expanded="isExpanded(item.path)"
            >
              <ChevronRight
                class="w-4 h-4 transition-transform duration-200"
                :class="{ 'rotate-90': isExpanded(item.path) }"
              />
            </button>
          </div>

          <!-- Dropped Nested Sub-Menu with Animation -->
          <Transition
            enter-active-class="transition-all duration-200 ease-out overflow-hidden"
            enter-from-class="opacity-0 max-h-0"
            enter-to-class="opacity-100 max-h-40"
            leave-active-class="transition-all duration-150 ease-in overflow-hidden"
            leave-from-class="opacity-100 max-h-40"
            leave-to-class="opacity-0 max-h-0"
          >
            <div
              v-if="item.children && isExpanded(item.path)"
              class="ml-6 pl-2.5 border-l border-border/80 space-y-0.5 py-1"
            >
              <button
                v-for="child in item.children"
                :key="child.path"
                :data-testid="child.testId"
                type="button"
                @click="navigateTo(child.path)"
                :class="[
                  'w-full flex items-center px-3 py-2 rounded-md text-sm font-medium transition-colors text-left cursor-pointer',
                  isChildActive(child.path)
                    ? 'text-primary font-semibold bg-primary/10'
                    : 'text-muted-foreground hover:text-foreground hover:bg-muted/60'
                ]"
              >
                <span class="truncate">{{ child.name }}</span>
              </button>
            </div>
          </Transition>
        </div>
      </nav>

      <!-- Bottom User Profile & Session Controls with Pinned mt-auto -->
      <div class="p-3 border-t border-border bg-card flex items-center justify-between mt-auto flex-shrink-0">
        <div class="flex items-center gap-2.5 min-w-0">
          <div class="h-8 w-8 rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center text-xs font-bold text-primary flex-shrink-0">
            {{ authStore.user?.username?.slice(0, 2).toUpperCase() || 'AD' }}
          </div>
          <div class="min-w-0">
            <span class="text-sm font-medium text-foreground block truncate">
              {{ authStore.user?.username || 'Operator' }}
            </span>
            <span class="text-xs text-primary uppercase tracking-wider block font-semibold font-mono">
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
    </aside>

    <!-- Main Content Canvas Area -->
    <div class="flex-1 h-full flex flex-col min-w-0 min-h-0 bg-background overflow-hidden">
      <!-- Top Action Bar -->
      <header class="h-14 bg-card border-b border-border px-5 flex items-center justify-between flex-shrink-0">
        <div class="flex items-center gap-3">
          <button
            type="button"
            data-testid="nav-mobile-toggle"
            class="lg:hidden flex items-center justify-center w-8 h-8 rounded-md border border-border bg-card text-muted-foreground hover:text-foreground hover:bg-muted transition-colors cursor-pointer"
            :aria-label="mobileNavOpen ? 'Close navigation' : 'Open navigation'"
            :aria-expanded="mobileNavOpen"
            @click="mobileNavOpen = !mobileNavOpen"
          >
            <X v-if="mobileNavOpen" class="w-4 h-4" />
            <Menu v-else class="w-4 h-4" />
          </button>
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

        <!-- Right Side Controls (Circular Theme Toggle) -->
        <div class="flex items-center gap-3">
          <button
            data-testid="theme-toggle-btn"
            type="button"
            @click="toggleTheme"
            class="flex items-center justify-center w-8 h-8 rounded-full border border-border bg-card text-foreground hover:bg-muted transition-colors cursor-pointer"
            :title="isDark ? 'Switch to Light Mode' : 'Switch to Dark Mode'"
            :aria-label="isDark ? 'Switch to Light Mode' : 'Switch to Dark Mode'"
          >
            <Sun v-if="isDark" class="w-4 h-4 text-warning" />
            <Moon v-else class="w-4 h-4 text-primary" />
          </button>
        </div>
      </header>

      <!-- View Slot Content -->
      <main class="flex-1 min-h-0 overflow-y-auto p-4 bg-background flex flex-col">
        <slot />
      </main>
    </div>
  </div>
</template>
