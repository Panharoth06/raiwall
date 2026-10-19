<script setup lang="ts">
import { computed, onMounted } from 'vue';
import { useRouter, useRoute } from '@/router';
import { useAuthStore } from '@/stores/auth';
import { useConfigStore } from '@/stores/config';
import {
  LayoutDashboard,
  Globe,
  Sliders,
  Shield,
  FileCode,
  Rocket,
  Settings,
  LogOut,
  Layers,
  AlertTriangle,
} from 'lucide-vue-next';

const router = useRouter();
const route = useRoute();
const authStore = useAuthStore();
const configStore = useConfigStore();

onMounted(() => {
  configStore.loadAll();
  authStore.fetchCurrentUser();
});

const currentPath = computed(() => route.value.path);

const navItems = [
  { name: 'Command Center', path: '/', icon: LayoutDashboard },
  { name: 'Sites & Upstreams', path: '/sites', icon: Globe },
  { name: 'Exceptions', path: '/exceptions', icon: Shield },
  { name: 'ACL Rules', path: '/acls', icon: FileCode },
  { name: 'Security Policies', path: '/policies', icon: Sliders },
  { name: 'Deployments', path: '/deployments', icon: Rocket },
  { name: 'Cluster & Keys', path: '/settings', icon: Settings },
];

const navigateTo = (path: string) => {
  router.push(path);
};

const handleLogout = async () => {
  await authStore.logout();
  router.push('/login');
};
</script>

<template>
  <div class="min-h-screen bg-slate-950 text-slate-100 flex">
    <!-- Sidebar -->
    <aside class="w-64 bg-slate-900 border-r border-slate-800 flex flex-col flex-shrink-0">
      <!-- Brand Header -->
      <div class="h-16 px-6 border-b border-slate-800 flex items-center space-x-3">
        <div class="h-8 w-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
          <Layers class="w-5 h-5" />
        </div>
        <div>
          <span class="font-bold text-white text-base tracking-tight">Raiwall</span>
          <span class="text-xs text-slate-400 block -mt-0.5">WAF Gateway</span>
        </div>
      </div>

      <!-- Navigation Links -->
      <nav class="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        <button
          v-for="item in navItems"
          :key="item.path"
          @click="navigateTo(item.path)"
          :class="[
            'w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors text-left',
            currentPath === item.path
              ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          ]"
        >
          <component :is="item.icon" class="w-4 h-4" />
          <span>{{ item.name }}</span>
        </button>
      </nav>

      <!-- User and Logout -->
      <div class="p-4 border-t border-slate-800 bg-slate-900/50 flex items-center justify-between">
        <div class="flex items-center space-x-2">
          <div class="h-8 w-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-semibold text-slate-300">
            {{ authStore.user?.username?.slice(0, 2).toUpperCase() || 'AD' }}
          </div>
          <div>
            <span class="text-xs font-medium text-slate-200 block truncate max-w-[100px]">
              {{ authStore.user?.username || 'Admin' }}
            </span>
            <span class="text-[10px] text-emerald-400 uppercase tracking-wider block font-semibold">
              {{ authStore.user?.role || 'admin' }}
            </span>
          </div>
        </div>
        <button
          @click="handleLogout"
          title="Sign out"
          class="p-2 text-slate-400 hover:text-rose-400 hover:bg-slate-800 rounded-lg transition-colors"
        >
          <LogOut class="w-4 h-4" />
        </button>
      </div>
    </aside>

    <!-- Main Content Area -->
    <div class="flex-1 flex flex-col min-w-0">
      <!-- Top Bar -->
      <header class="h-16 bg-slate-900 border-b border-slate-800 px-6 flex items-center justify-between flex-shrink-0">
        <div class="flex items-center space-x-4">
          <!-- Active Version Pill -->
          <div class="flex items-center space-x-2 px-3 py-1 bg-slate-800/80 border border-slate-700 rounded-full text-xs text-slate-300">
            <span class="h-2 w-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span>Version <strong>v{{ configStore.activeVersion }}</strong> • LIVE</span>
          </div>

          <!-- Staged Changes Banner -->
          <button
            v-if="configStore.hasDraftChanges"
            @click="navigateTo('/deployments')"
            class="flex items-center space-x-2 px-3 py-1 bg-amber-500/10 border border-amber-500/30 rounded-full text-xs text-amber-400 hover:bg-amber-500/20 transition-colors"
          >
            <AlertTriangle class="w-3.5 h-3.5" />
            <span>{{ configStore.diffs.length }} staged changes ready to deploy</span>
          </button>
        </div>

        <div class="flex items-center space-x-3 text-xs text-slate-400">
          <span v-if="configStore.cluster?.redis_connected" class="flex items-center space-x-1.5 text-emerald-400">
            <span class="h-1.5 w-1.5 rounded-full bg-emerald-400"></span>
            <span>Cluster Synced</span>
          </span>
          <span v-else class="text-slate-500">Standalone Mode</span>
        </div>
      </header>

      <!-- View Slot -->
      <main class="flex-1 overflow-y-auto p-6 bg-slate-950">
        <slot />
      </main>
    </div>
  </div>
</template>
