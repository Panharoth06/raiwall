<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { api, type AuditEvent } from '@/api/client';
import { Button } from '@/components/ui/button';
import {
  Table,
  TableHeader,
  TableBody,
  TableHead,
  TableRow,
  TableCell,
} from '@/components/ui/table';
import { EmptyState } from '@/components/ui/empty-state';
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';
import { History, RefreshCw } from 'lucide-vue-next';

const ACTIONS = [
  'login_success',
  'login_failure',
  'login_locked',
  'logout',
  'create',
  'update',
  'delete',
  'apply',
  'rollback',
  'password_reset',
  'session_revoke',
  'deactivate',
  'unban',
  'unban_all',
];

const events = ref<AuditEvent[]>([]);
const loading = ref(true);
const error = ref('');
const action = ref('all');
const limit = ref('50');
const offset = ref(0);

const hasNext = computed(() => events.value.length >= Number(limit.value));
const hasPrevious = computed(() => offset.value > 0);

const load = async () => {
  loading.value = true;
  error.value = '';
  try {
    const result = await api.listAuditEvents({
      action: action.value === 'all' ? undefined : action.value,
      limit: Number(limit.value),
      offset: offset.value,
    });
    events.value = result.events;
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to load the audit log';
  } finally {
    loading.value = false;
  }
};

const reload = () => {
  offset.value = 0;
  void load();
};

const nextPage = () => {
  offset.value += Number(limit.value);
  void load();
};

const previousPage = () => {
  offset.value = Math.max(0, offset.value - Number(limit.value));
  void load();
};

const formatTime = (value: string) => new Date(value).toISOString().replace('T', ' ').replace('.000Z', 'Z');

onMounted(() => {
  void load();
});
</script>

<template>
  <div class="space-y-4 font-sans">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 class="text-base font-semibold tracking-tight text-foreground">Audit Log</h2>
        <p class="mt-1 text-sm text-muted-foreground">
          Append-only record of control-plane changes and operator sign-ins. No update or delete endpoint exists.
        </p>
      </div>
      <div class="flex items-center gap-2">
        <Select v-model="action" @update:model-value="reload">
          <SelectTrigger class="h-8 w-[11rem]"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All actions</SelectItem>
            <SelectItem v-for="item in ACTIONS" :key="item" :value="item">{{ item }}</SelectItem>
          </SelectContent>
        </Select>
        <Select v-model="limit" @update:model-value="reload">
          <SelectTrigger class="h-8 w-[5.5rem]"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="50">50 rows</SelectItem>
            <SelectItem value="100">100 rows</SelectItem>
            <SelectItem value="200">200 rows</SelectItem>
          </SelectContent>
        </Select>
        <Button variant="outline" size="sm" class="gap-1.5" :disabled="loading" @click="load">
          <RefreshCw class="h-3.5 w-3.5" />
          Refresh
        </Button>
      </div>
    </div>

    <div v-if="loading" class="space-y-2" aria-busy="true" aria-label="Loading audit log">
      <div v-for="row in 4" :key="row" class="h-9 animate-pulse rounded-md bg-muted" />
    </div>

    <div v-else-if="error" class="rounded-md border border-threat/30 bg-threat/10 p-3 text-sm text-threat">
      <span>{{ error }}</span>
      <Button variant="outline" size="sm" class="ml-2" @click="load">Retry</Button>
    </div>

    <EmptyState
      v-else-if="events.length === 0"
      :icon="History"
      title="No audit events"
      description="Operator sign-ins and control-plane changes will appear here."
    />

    <template v-else>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Time</TableHead>
            <TableHead>Actor</TableHead>
            <TableHead>Action</TableHead>
            <TableHead>Target</TableHead>
            <TableHead>Request</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Client IP</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="event in events" :key="event.id">
            <TableCell class="whitespace-nowrap font-mono text-xs text-muted-foreground">
              {{ formatTime(event.occurred_at) }}
            </TableCell>
            <TableCell class="max-w-[10rem] truncate text-sm text-foreground">
              {{ event.actor_name || event.actor_type }}
              <span v-if="event.actor_type === 'api_key'" class="text-xs text-muted-foreground"> (key)</span>
            </TableCell>
            <TableCell class="font-mono text-xs text-foreground">{{ event.action }}</TableCell>
            <TableCell class="max-w-[12rem] truncate text-xs text-muted-foreground">
              <template v-if="event.target_type">
                {{ event.target_type }}<template v-if="event.target_id">/{{ event.target_id }}</template>
              </template>
              <template v-else>—</template>
            </TableCell>
            <TableCell class="max-w-[18rem] truncate font-mono text-xs text-muted-foreground">
              {{ event.method }} {{ event.path }}
            </TableCell>
            <TableCell class="font-mono text-xs" :class="(event.status_code ?? 0) >= 400 ? 'text-threat' : 'text-success'">
              {{ event.status_code || '—' }}
            </TableCell>
            <TableCell class="font-mono text-xs text-muted-foreground">{{ event.client_ip || '—' }}</TableCell>
          </TableRow>
        </TableBody>
      </Table>

      <div class="flex items-center justify-between text-sm text-muted-foreground">
        <span>Offset {{ offset }}</span>
        <div class="flex gap-2">
          <Button variant="outline" size="sm" :disabled="!hasPrevious || loading" @click="previousPage">Previous</Button>
          <Button variant="outline" size="sm" :disabled="!hasNext || loading" @click="nextPage">Next</Button>
        </div>
      </div>
    </template>
  </div>
</template>
