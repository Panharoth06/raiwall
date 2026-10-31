<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import type { ForensicEvent } from '@/types/telemetry';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { SearchInput } from '@/components/ui/search-input';
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from '@/components/ui/table';
import { TablePagination } from '@/components/ui/table-pagination';
import BotEventDetailDialog from '@/components/anti-bot/BotEventDetailDialog.vue';
import {
  Activity,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Fingerprint,
  Ghost,
  Eye,
  AlertTriangle,
  Globe,
} from 'lucide-vue-next';

const props = defineProps<{
  events: ForensicEvent[];
  challengeTotal: number;
  trapTotal: number;
  spoofTotal: number;
  uniqueJa4: number;
  loading?: boolean;
  error?: string;
}>();

const emit = defineEmits<{
  (e: 'refresh'): void;
}>();

const search = ref('');
const statusFilter = ref<'all' | 'challenge' | 'spoof' | 'trap'>('all');
const selectedEvent = ref<ForensicEvent | null>(null);
const drawerOpen = ref(false);
const page = ref(1);
const pageSize = ref(20);

const metrics = computed(() => [
  { label: 'Challenges', value: props.challengeTotal, icon: ShieldCheck, color: 'text-primary', testId: 'bot-metric-challenges' },
  { label: 'Trap hits', value: props.trapTotal, icon: Ghost, color: 'text-threat', testId: 'bot-metric-trap-hits' },
  { label: 'Spoof blocks', value: props.spoofTotal, icon: ShieldAlert, color: 'text-warning', testId: 'bot-metric-spoof-blocks' },
  { label: 'Unique JA4', value: props.uniqueJa4, icon: Fingerprint, color: 'text-info', testId: 'bot-metric-unique-ja4' },
]);

const filteredEvents = computed(() => {
  let list = props.events;
  const q = search.value.trim().toLowerCase();

  if (statusFilter.value === 'challenge') {
    list = list.filter((e) => e.status_code === 468 || e.action === 'challenge');
  } else if (statusFilter.value === 'spoof') {
    list = list.filter((e) => e.rule_id === 'bot_spoof' || e.action === 'block');
  } else if (statusFilter.value === 'trap') {
    list = list.filter((e) => e.rule_id === 'honeypot_trap' || e.action === 'ban');
  }

  if (!q) return list;

  return list.filter((e) => {
    const ip = e.client_ip || '';
    const host = e.host || '';
    const path = e.path || '';
    const ja4 = e.ja4 || '';
    return (
      ip.toLowerCase().includes(q) ||
      host.toLowerCase().includes(q) ||
      path.toLowerCase().includes(q) ||
      ja4.toLowerCase().includes(q)
    );
  });
});

watch([search, statusFilter], () => {
  page.value = 1;
});

const paginatedEvents = computed(() => {
  const start = (page.value - 1) * pageSize.value;
  return filteredEvents.value.slice(start, start + pageSize.value);
});

const formatTime = (value: string) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toISOString().replace('T', ' ').slice(0, 19);
};

const formatCount = (value: number) => value.toLocaleString('en-US');

const inspectEvent = (e: ForensicEvent) => {
  selectedEvent.value = e;
  drawerOpen.value = true;
};

const statusVariant = (statusCode?: number, action?: string) => {
  if (action === 'ban' || statusCode === 403) return 'destructive';
  if (statusCode === 468 || action === 'challenge') return 'warning';
  if (statusCode === 200 || action === 'allow') return 'secondary';
  return 'outline';
};
</script>

<template>
  <div class="space-y-4 font-sans" data-testid="bot-activity-card">
    <!-- Quick Metric Cards -->
    <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
      <div
        v-for="m in metrics"
        :key="m.label"
        :data-testid="m.testId"
        class="bg-card border border-border rounded-lg p-3.5 flex items-center justify-between"
      >
        <div>
          <span class="text-xs uppercase tracking-wider text-muted-foreground font-mono block">
            {{ m.label }}
          </span>
          <span class="text-xl font-bold font-mono tracking-tight text-foreground">
            {{ formatCount(m.value) }}
          </span>
        </div>
        <component :is="m.icon" class="w-5 h-5" :class="m.color" />
      </div>
    </div>

    <!-- Toolbar Filters & Controls -->
    <div class="flex flex-wrap items-center justify-between gap-3 bg-card border border-border p-3 rounded-lg">
      <div class="flex flex-wrap items-center gap-2">
        <SearchInput
          v-model="search"
          clearable
          placeholder="Filter IP, host, path, JA4…"
          class="w-64"
          data-testid="bot-activity-search"
        />

        <!-- Segmented Filter for Challenge Categories -->
        <div class="inline-flex rounded-lg border border-border p-0.5 bg-muted/40 text-xs">
          <button
            type="button"
            class="px-2.5 py-1 rounded font-medium transition-colors cursor-pointer"
            :class="statusFilter === 'all' ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'"
            @click="statusFilter = 'all'"
          >
            All
          </button>
          <button
            type="button"
            class="px-2.5 py-1 rounded font-medium transition-colors cursor-pointer"
            :class="statusFilter === 'challenge' ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'"
            @click="statusFilter = 'challenge'"
          >
            Challenges
          </button>
          <button
            type="button"
            class="px-2.5 py-1 rounded font-medium transition-colors cursor-pointer"
            :class="statusFilter === 'spoof' ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'"
            @click="statusFilter = 'spoof'"
          >
            Spoofed
          </button>
          <button
            type="button"
            class="px-2.5 py-1 rounded font-medium transition-colors cursor-pointer"
            :class="statusFilter === 'trap' ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'"
            @click="statusFilter = 'trap'"
          >
            Trap Hits
          </button>
        </div>
      </div>

      <div class="flex items-center gap-2">
        <span class="text-xs text-muted-foreground font-mono">
          {{ filteredEvents.length }} total events
        </span>
        <Button
          variant="outline"
          size="sm"
          class="h-8 gap-1.5 text-xs"
          :disabled="loading"
          data-testid="bot-activity-refresh-btn"
          @click="emit('refresh')"
        >
          <RefreshCw class="w-3.5 h-3.5" :class="{ 'animate-spin': loading }" />
          <span>Refresh</span>
        </Button>
      </div>
    </div>

    <!-- Error Banner -->
    <div
      v-if="error"
      class="p-3 bg-threat/10 border border-threat/20 rounded-lg flex items-center gap-2 text-xs text-threat"
    >
      <AlertTriangle class="w-4 h-4 shrink-0" />
      <span>{{ error }}</span>
    </div>

    <!-- Rich Data Table Container -->
    <div class="bg-card border border-border rounded-lg overflow-hidden">
      <Table container-class="overflow-visible">
        <TableHeader>
          <TableRow>
            <TableHead class="w-44">Time (UTC)</TableHead>
            <TableHead class="w-40">Client IP</TableHead>
            <TableHead class="w-44">Target Host</TableHead>
            <TableHead>Request Endpoint</TableHead>
            <TableHead class="w-28 text-center">Status</TableHead>
            <TableHead class="w-48">JA4 Fingerprint</TableHead>
            <TableHead class="w-24 text-right">Details</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody class="font-mono tabular-nums" data-testid="bot-activity-list">
          <!-- Loading State -->
          <TableRow v-if="loading && events.length === 0" data-testid="bot-activity-loading">
            <TableCell colspan="7" class="h-64 text-center text-muted-foreground">
              <div class="flex flex-col items-center justify-center p-8 space-y-2">
                <RefreshCw class="w-5 h-5 animate-spin text-primary mx-auto" />
                <span class="text-xs">Streaming challenge activity…</span>
              </div>
            </TableCell>
          </TableRow>

          <!-- Empty State -->
          <TableRow v-else-if="filteredEvents.length === 0" data-testid="bot-activity-empty">
            <TableCell colspan="7" class="h-64 text-center align-middle">
              <div class="flex flex-col items-center justify-center py-10 px-4 space-y-2 text-center">
                <div class="w-10 h-10 rounded-full bg-muted/50 flex items-center justify-center mb-1">
                  <Activity class="w-5 h-5 text-muted-foreground/60" />
                </div>
                <div v-if="search || statusFilter !== 'all'" class="text-sm font-semibold text-foreground">
                  No activity matches the current filters
                </div>
                <div v-else class="text-sm font-semibold text-foreground">
                  No Bot Activity Recorded
                </div>
                <div class="text-xs text-muted-foreground max-w-sm">
                  {{ search || statusFilter !== 'all' ? 'Try adjusting your search criteria or resetting filters.' : 'Browser challenges, honeypot hits, and JA4 spoofing blocks will appear here in real time.' }}
                </div>
              </div>
            </TableCell>
          </TableRow>

          <!-- Telemetry Event Rows -->
          <TableRow
            v-else
            v-for="event in paginatedEvents"
            :key="event.event_id"
            class="group cursor-pointer hover:bg-muted/50 transition-colors"
            @click="inspectEvent(event)"
          >
            <TableCell class="text-xs text-muted-foreground whitespace-nowrap">
              {{ formatTime(event.timestamp) }}
            </TableCell>
            <TableCell class="text-xs font-semibold text-foreground">
              <div class="flex items-center gap-1.5">
                <span>{{ event.client_ip }}</span>
                <span v-if="event.country" class="text-muted-foreground text-xs uppercase">
                  ({{ event.country }})
                </span>
              </div>
            </TableCell>
            <TableCell class="text-xs text-foreground truncate max-w-44" :title="event.host">
              {{ event.host || '—' }}
            </TableCell>
            <TableCell class="max-w-md truncate text-xs" :title="`${event.method} ${event.path}`">
              <span class="px-1.5 py-0.5 rounded text-xs font-bold mr-1.5 uppercase" :class="event.method === 'GET' ? 'bg-primary/10 text-primary' : 'bg-muted text-foreground'">
                {{ event.method }}
              </span>
              <span class="text-foreground font-mono">{{ event.path }}</span>
            </TableCell>
            <TableCell class="text-center">
              <Badge :variant="statusVariant(event.status_code, event.action)" class="text-xs uppercase">
                {{ event.status_code || event.action }}
              </Badge>
            </TableCell>
            <TableCell class="text-xs">
              <span class="font-mono text-muted-foreground truncate block max-w-44" :title="event.ja4 || 'no-ja4'">
                {{ event.ja4 || 'no-ja4' }}
              </span>
            </TableCell>
            <TableCell class="text-right">
              <Button variant="ghost" size="sm" class="h-7 w-7 p-0" title="Inspect Event" @click.stop="inspectEvent(event)">
                <Eye class="w-3.5 h-3.5 text-muted-foreground group-hover:text-foreground" />
              </Button>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>

      <!-- Pagination Footer -->
      <TablePagination
        :page="page"
        :page-size="pageSize"
        :total="filteredEvents.length"
        :page-size-options="[10, 20, 50, 100]"
        item-label="events"
        @update:page="(p) => page = p"
        @update:page-size="(s) => { pageSize = s; page = 1; }"
      />
    </div>

    <!-- Forensic Details Dialog / Inspector -->
    <BotEventDetailDialog
      :open="drawerOpen"
      :event="selectedEvent"
      @update:open="(val) => drawerOpen = val"
    />
  </div>
</template>
