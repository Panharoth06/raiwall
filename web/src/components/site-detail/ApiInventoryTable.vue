<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { api, type APIResource } from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
import { Loader2, Radar, Search, Trash2 } from 'lucide-vue-next';

const props = defineProps<{ siteId: string }>();

const resources = ref<APIResource[]>([]);
const loading = ref(true);
const error = ref('');
const search = ref('');

const load = async () => {
  loading.value = true;
  error.value = '';
  try {
    resources.value = await api.listAPIResources(props.siteId);
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to load API inventory';
  } finally {
    loading.value = false;
  }
};

onMounted(load);

const filtered = computed(() => {
  const q = search.value.trim().toLowerCase();
  if (!q) return resources.value;
  return resources.value.filter((r) =>
    `${r.method} ${r.path_pattern} ${r.content_type}`.toLowerCase().includes(q),
  );
});

const methodVariant = (method: string): 'default' | 'destructive' | 'secondary' | 'outline' => {
  if (method === 'GET') return 'secondary';
  if (method === 'DELETE') return 'destructive';
  return 'default';
};

const prune = async (resource: APIResource) => {
  error.value = '';
  try {
    await api.deleteAPIResource(props.siteId, resource.id);
    resources.value = resources.value.filter((r) => r.id !== resource.id);
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Prune failed';
  }
};

const lastSeen = (r: APIResource): string => {
  if (!r.last_seen) return '—';
  try {
    return new Date(r.last_seen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  } catch {
    return '—';
  }
};
</script>

<template>
  <div class="space-y-3">
    <div class="flex items-center justify-between gap-2">
      <div class="relative flex-1 max-w-60">
        <Search class="w-3.5 h-3.5 absolute left-2 top-1/2 -translate-y-1/2 text-muted-foreground" />
        <Input v-model="search" placeholder="Search endpoints…" class="pl-7 text-xs" data-testid="inventory-search" />
      </div>
      <span class="text-xs text-muted-foreground" data-testid="inventory-summary">
        {{ resources.length }} auto-discovered endpoints — passive traffic catalog
      </span>
      <Button variant="outline" size="sm" data-testid="inventory-refresh" :disabled="loading" @click="load">
        <Loader2 v-if="loading" class="w-3.5 h-3.5 animate-spin" />
        Refresh
      </Button>
    </div>

    <p v-if="error" class="text-xs text-destructive" data-testid="inventory-error">{{ error }}</p>

    <div v-if="loading" class="flex items-center justify-center py-12 space-x-2 text-xs text-muted-foreground" data-testid="inventory-loading">
      <Loader2 class="w-4 h-4 animate-spin" />
      <span>Loading inventory…</span>
    </div>

    <div v-else-if="filtered.length === 0" class="flex flex-col items-center justify-center py-12 space-y-2 text-xs text-muted-foreground" data-testid="inventory-empty">
      <Radar class="w-5 h-5" />
      <span v-if="search">No endpoints match the search</span>
      <span v-else>No traffic observed yet — endpoints appear as clients hit the site</span>
    </div>

    <div v-else class="max-h-96 overflow-auto rounded-lg border border-border bg-card">
      <Table data-testid="inventory-table" container-class="overflow-visible">
        <TableHeader>
          <TableRow>
            <TableHead>Method</TableHead>
            <TableHead>Path Pattern</TableHead>
            <TableHead>Content Type</TableHead>
            <TableHead>Hits</TableHead>
            <TableHead>Last Seen</TableHead>
            <TableHead class="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody class="font-mono tabular-nums">
          <TableRow v-for="(resource, i) in filtered" :key="resource.id" :data-testid="`inventory-row-${i}`">
            <TableCell>
              <Badge :variant="methodVariant(resource.method)" class="text-[10px]">{{ resource.method }}</Badge>
            </TableCell>
            <TableCell class="font-medium">{{ resource.path_pattern }}</TableCell>
            <TableCell class="max-w-32 truncate text-muted-foreground" :title="resource.content_type">{{ resource.content_type || '—' }}</TableCell>
            <TableCell>{{ resource.hit_count }}</TableCell>
            <TableCell class="text-muted-foreground">{{ lastSeen(resource) }}</TableCell>
            <TableCell class="text-right">
              <Button variant="ghost" size="sm" class="h-6 px-1.5 text-destructive" :data-testid="`inventory-prune-${i}`" @click="prune(resource)">
                <Trash2 class="w-3.5 h-3.5" />
              </Button>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </div>
  </div>
</template>
