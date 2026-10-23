<script setup lang="ts">
import { ref, onMounted, computed } from 'vue';
import { identityApi, type IdentityAuthEvent } from '@/api/identity';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Loader2, RefreshCw, ScrollText, Search } from 'lucide-vue-next';

const events = ref<IdentityAuthEvent[]>([]);
const loading = ref(true);
const error = ref('');
const search = ref('');

const load = async () => {
  loading.value = true;
  error.value = '';
  try {
    events.value = await identityApi.listAuthEvents(200);
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to load auth logs';
  } finally {
    loading.value = false;
  }
};

onMounted(load);

const filtered = computed(() => {
  const q = search.value.trim().toLowerCase();
  if (!q) return events.value;
  return events.value.filter((e) =>
    `${e.username} ${e.app_id} ${e.host} ${e.client_ip} ${e.country}`.toLowerCase().includes(q),
  );
});

const failureCount = computed(() => events.value.filter((e) => e.result !== 'success').length);

const resultVariant = (result: string): 'default' | 'destructive' | 'secondary' => {
  if (result === 'success') return 'secondary';
  if (result === 'unknown_user' || result === 'invalid_password' || result === 'totp_failed') return 'destructive';
  return 'default';
};

const timeOf = (e: IdentityAuthEvent): string => {
  const ts = e.created_at || e.id;
  if (!ts) return '—';
  try {
    return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return ts.slice(0, 19);
  }
};
</script>

<template>
  <div class="flex flex-col h-full space-y-3">
    <div class="flex items-center justify-between shrink-0">
      <p class="text-xs text-muted-foreground" data-testid="authlog-summary">
        {{ failureCount }} failed of {{ events.length }} recorded attempts — newest first
      </p>
      <Button variant="outline" size="sm" data-testid="authlog-refresh" :disabled="loading" @click="load">
        <RefreshCw class="w-3.5 h-3.5" />
        Refresh
      </Button>
    </div>

    <div class="relative shrink-0">
      <Search class="w-3.5 h-3.5 absolute left-2 top-1/2 -translate-y-1/2 text-muted-foreground" />
      <Input v-model="search" placeholder="Filter by username, app, host, IP…" class="pl-7 text-xs" data-testid="authlog-search" />
    </div>

    <p v-if="error" class="text-xs text-destructive shrink-0" data-testid="authlog-error">{{ error }}</p>

    <div v-if="loading" class="flex items-center justify-center py-16 space-x-2 text-xs text-muted-foreground" data-testid="authlog-loading">
      <Loader2 class="w-4 h-4 animate-spin" />
      <span>Loading authentication log…</span>
    </div>

    <div v-else-if="filtered.length === 0" class="flex flex-col items-center justify-center py-16 space-y-2 text-xs text-muted-foreground" data-testid="authlog-empty">
      <ScrollText class="w-5 h-5" />
      <span v-if="search">No events match the filter</span>
      <span v-else>No login attempts recorded yet</span>
    </div>

    <div v-else class="border border-border rounded-lg overflow-auto flex-1 bg-background">
      <table class="w-full text-xs font-mono tabular-nums" data-testid="authlog-table">
        <thead class="bg-muted/50 sticky top-0 font-sans">
          <tr class="text-left text-[10px] uppercase tracking-wider text-muted-foreground">
            <th class="px-3 py-2 font-medium">Time</th>
            <th class="px-3 py-2 font-medium">Account</th>
            <th class="px-3 py-2 font-medium">Site</th>
            <th class="px-3 py-2 font-medium">Method</th>
            <th class="px-3 py-2 font-medium">Result</th>
            <th class="px-3 py-2 font-medium">IP</th>
            <th class="px-3 py-2 font-medium">Country</th>
            <th class="px-3 py-2 font-medium">Detail</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(e, i) in filtered" :key="`${e.username}-${e.result}-${e.created_at}`" class="border-t border-border hover:bg-muted/40" :data-testid="`authlog-row-${i}`">
            <td class="px-3 py-1.5 whitespace-nowrap text-muted-foreground">{{ timeOf(e) }}</td>
            <td class="px-3 py-1.5">{{ e.username }}</td>
            <td class="px-3 py-1.5">{{ e.app_id || '—' }}</td>
            <td class="px-3 py-1.5 text-muted-foreground">{{ e.method }}</td>
            <td class="px-3 py-1.5">
              <Badge :variant="resultVariant(e.result)" class="text-[10px]">{{ e.result }}</Badge>
            </td>
            <td class="px-3 py-1.5">{{ e.client_ip || '—' }}</td>
            <td class="px-3 py-1.5">{{ e.country || '—' }}</td>
            <td class="px-3 py-1.5 max-w-56 truncate text-muted-foreground" :title="e.detail">{{ e.detail || '—' }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
