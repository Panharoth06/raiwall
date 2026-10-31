<script setup lang="ts">
import { computed } from 'vue';
import { useRouter } from '@/router';
import { useAuthStore } from '@/stores/auth';
import { LogOut } from 'lucide-vue-next';

const router = useRouter();
const authStore = useAuthStore();

const initials = computed(() => {
  const name = authStore.user?.username || 'Operator';
  return name.slice(0, 2).toUpperCase();
});

const handleLogout = async () => {
  await authStore.logout();
  router.push('/login');
};
</script>

<template>
  <div data-testid="navbar-admin-profile" class="flex items-center gap-2 select-none">
    <div class="flex items-center gap-2 min-w-0">
      <div
        class="h-8 w-8 rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center text-xs font-bold text-primary shrink-0"
        :title="authStore.user?.username || 'Operator'"
      >
        {{ initials }}
      </div>
      <div class="min-w-0 hidden md:block">
        <span class="text-xs font-medium text-foreground block truncate leading-tight max-w-[110px]">
          {{ authStore.user?.username || 'Operator' }}
        </span>
        <span class="text-xs text-primary uppercase tracking-wider block font-semibold font-mono leading-tight">
          {{ authStore.user?.role || 'admin' }}
        </span>
      </div>
    </div>

    <button
      data-testid="logout-btn"
      type="button"
      @click="handleLogout"
      title="Sign out"
      aria-label="Sign out"
      class="p-1.5 text-muted-foreground hover:text-threat hover:bg-muted rounded-md transition-colors cursor-pointer shrink-0"
    >
      <LogOut class="w-4 h-4" />
    </button>
  </div>
</template>
