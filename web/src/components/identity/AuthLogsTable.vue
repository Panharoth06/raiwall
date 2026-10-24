<script setup lang="ts">
import { ref, onMounted, computed } from 'vue';
import { identityApi, type IdentityAuthEvent } from '@/api/identity';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { SearchInput } from '@/components/ui/search-input';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
import { Loader2, RefreshCw, ScrollText } from 'lucide-vue-next';

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

    <SearchInput
      v-model="search"
      clearable
      placeholder="Filter by username, app, host, IP…"
      class="shrink-0 max-w-sm"
      data-testid="authlog-search"
    />

    <p v-if="error" class="text-xs text-destructive shrink-0" data-testid="authlog-error">{{ error }}</p>

    <div v-if="loading" class="flex-1 min-h-[300px] flex items-center justify-center space-x-2 text-xs text-muted-foreground" data-testid="authlog-loading">
      <Loader2 class="w-4 h-4 animate-spin" />
      <span>Loading authentication log…</span>
    </div>

    <div v-else-if="filtered.length === 0" class="flex-1 min-h-[300px] flex flex-col items-center justify-center space-y-2 text-xs text-muted-foreground text-center" data-testid="authlog-empty">
      <ScrollText class="w-6 h-6 text-muted-foreground/60 mb-1" />
      <span v-if="search" class="font-medium">No events match the filter</span>
      <span v-else class="font-medium">No login attempts recorded yet</span>
    </div>

    <div v-else class="flex-1 overflow-auto rounded-lg border border-border bg-card">
      <Table data-testid="authlog-table" container-class="overflow-visible">
        <TableHeader>
          <TableRow>
            <TableHead>Time</TableHead>
            <TableHead>Account</TableHead>
            <TableHead>Site</TableHead>
            <TableHead>Method</TableHead>
            <TableHead>Result</TableHead>
            <TableHead>IP</TableHead>
            <TableHead>Country</TableHead>
            <TableHead>Detail</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody class="font-mono tabular-nums">
          <TableRow v-for="(e, i) in filtered" :key="`${e.username}-${e.result}-${e.created_at}`" :data-testid="`authlog-row-${i}`">
            <TableCell class="whitespace-nowrap text-muted-foreground">{{ timeOf(e) }}</TableCell>
            <TableCell>{{ e.username }}</TableCell>
            <TableCell>{{ e.app_id || '—' }}</TableCell>
            <TableCell class="text-muted-foreground">{{ e.method }}</TableCell>
            <TableCell>
              <Badge :variant="resultVariant(e.result)" class="text-[10px]">{{ e.result }}</Badge>
            </TableCell>
            <TableCell>{{ e.client_ip || '—' }}</TableCell>
            <TableCell>{{ e.country || '—' }}</TableCell>
            <TableCell class="max-w-56 truncate text-muted-foreground" :title="e.detail">{{ e.detail || '—' }}</TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </div>
  </div>
</template>
