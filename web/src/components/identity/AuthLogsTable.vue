<script setup lang="ts">
import { ref, onMounted, computed, watch } from 'vue';
import { identityApi, type IdentityAuthEvent } from '@/api/identity';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { SearchInput } from '@/components/ui/search-input';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
import { TablePagination } from '@/components/ui/table-pagination';
import { Loader2, RefreshCw, ScrollText } from 'lucide-vue-next';

const events = ref<IdentityAuthEvent[]>([]);
const loading = ref(true);
const error = ref('');
const search = ref('');
const page = ref(1);
const pageSize = ref(20);

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

watch(search, () => {
  page.value = 1;
});

const paginatedEvents = computed(() => {
  const start = (page.value - 1) * pageSize.value;
  return filtered.value.slice(start, start + pageSize.value);
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
  <div class="flex flex-col h-full space-y-4">
    <!-- Action Toolbar -->
    <div class="flex flex-wrap items-center justify-between gap-3 shrink-0">
      <SearchInput
        v-model="search"
        clearable
        placeholder="Filter by username, app, host, IP…"
        class="w-72"
        data-testid="authlog-search"
      />
      <div class="flex items-center gap-3">
        <p class="text-xs text-muted-foreground font-mono" data-testid="authlog-summary">
          {{ failureCount }} failed of {{ events.length }} recorded attempts — newest first
        </p>
        <Button variant="outline" size="sm" class="gap-1.5" data-testid="authlog-refresh" :disabled="loading" @click="load">
          <RefreshCw class="w-3.5 h-3.5" :class="{ 'animate-spin': loading }" />
          Refresh
        </Button>
      </div>
    </div>

    <p v-if="error" class="text-xs text-destructive shrink-0" data-testid="authlog-error">{{ error }}</p>

    <!-- Table Container (Always rendered with header & borders) -->
    <div class="flex-1 overflow-auto rounded-lg border border-border bg-card">
      <Table data-testid="authlog-table" container-class="overflow-visible">
        <TableHeader>
          <TableRow>
            <TableHead class="w-40">Time</TableHead>
            <TableHead class="w-44">Account</TableHead>
            <TableHead class="w-40">Site</TableHead>
            <TableHead class="w-28">Method</TableHead>
            <TableHead class="w-28">Result</TableHead>
            <TableHead class="w-36">IP</TableHead>
            <TableHead class="w-24">Country</TableHead>
            <TableHead>Detail</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody class="font-mono tabular-nums">
          <!-- Loading State -->
          <TableRow v-if="loading">
            <TableCell colspan="8" class="h-64 text-center text-muted-foreground">
              <div class="flex flex-col items-center justify-center p-8 space-y-2" data-testid="authlog-loading">
                <Loader2 class="w-5 h-5 animate-spin text-primary mx-auto" />
                <span class="text-xs">Loading authentication log…</span>
              </div>
            </TableCell>
          </TableRow>

          <!-- Empty State -->
          <TableRow v-else-if="filtered.length === 0">
            <TableCell colspan="8" class="h-64 text-center align-middle">
              <div class="flex flex-col items-center justify-center py-10 px-4 space-y-2 text-center" data-testid="authlog-empty">
                <div class="w-10 h-10 rounded-full bg-muted/50 flex items-center justify-center mb-1">
                  <ScrollText class="w-5 h-5 text-muted-foreground/60" />
                </div>
                <div v-if="search" class="text-sm font-semibold text-foreground">No events match the filter</div>
                <div v-else class="text-sm font-semibold text-foreground">No login attempts recorded yet</div>
                <div class="text-xs text-muted-foreground max-w-sm">
                  {{ search ? 'Try adjusting your search query or clear the filter.' : 'Authentication attempts and session events will appear here in real time.' }}
                </div>
              </div>
            </TableCell>
          </TableRow>

          <!-- Event Rows -->
          <TableRow v-else v-for="(e, i) in paginatedEvents" :key="`${e.username}-${e.result}-${e.created_at}`" :data-testid="`authlog-row-${i}`">
            <TableCell class="whitespace-nowrap text-muted-foreground text-xs">{{ timeOf(e) }}</TableCell>
            <TableCell class="font-sans font-medium text-foreground text-xs">{{ e.username }}</TableCell>
            <TableCell class="text-xs">{{ e.app_id || '—' }}</TableCell>
            <TableCell class="text-muted-foreground text-xs">{{ e.method }}</TableCell>
            <TableCell>
              <Badge :variant="resultVariant(e.result)" class="text-xs">{{ e.result }}</Badge>
            </TableCell>
            <TableCell class="text-xs">{{ e.client_ip || '—' }}</TableCell>
            <TableCell class="text-xs">{{ e.country || '—' }}</TableCell>
            <TableCell class="max-w-56 truncate text-muted-foreground text-xs" :title="e.detail">{{ e.detail || '—' }}</TableCell>
          </TableRow>
        </TableBody>
      </Table>

      <!-- Pagination Footer -->
      <TablePagination
        :page="page"
        :page-size="pageSize"
        :total="filtered.length"
        :page-size-options="[10, 20, 50, 100]"
        item-label="logs"
        @update:page="(p) => page = p"
        @update:page-size="(s) => { pageSize = s; page = 1; }"
      />
    </div>
  </div>
</template>
