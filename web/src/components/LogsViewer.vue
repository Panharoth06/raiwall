<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue';
import {
  ShieldAlert,
  FileCode,
  ExternalLink,
  X,
  CheckCircle2,
  AlertTriangle,
  Ban,
  Database,
  RotateCw,
  ChevronLeft,
  ChevronRight,
  AlertCircle,
} from 'lucide-vue-next';
import { api } from '@/api/client';
import type { ForensicEvent, ExceptionDraft } from '@/types/telemetry';
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
import { SearchInput } from '@/components/ui/search-input';

const props = withDefaults(
  defineProps<{
    pageSize?: number;
    initialAction?: string;
  }>(),
  {
    pageSize: 20,
    initialAction: 'all',
  }
);

const emit = defineEmits<{
  (e: 'create-exception', draft: ExceptionDraft): void;
}>();

const logs = ref<ForensicEvent[]>([]);
const totalLogs = ref<number>(0);
const isLoading = ref<boolean>(false);
const error = ref<string | null>(null);

const searchQuery = ref<string>('');
const selectedAction = ref<string>(props.initialAction);
const currentPage = ref<number>(1);
const activeEvent = ref<ForensicEvent | null>(null);

async function fetchLogs() {
  isLoading.value = true;
  error.value = null;

  try {
    const offset = (currentPage.value - 1) * props.pageSize;
    const res = await api.listEvents({
      limit: props.pageSize,
      offset,
      action: selectedAction.value !== 'all' ? selectedAction.value : undefined,
      client_ip: searchQuery.value.trim() ? searchQuery.value.trim() : undefined,
    });

    if (res && Array.isArray(res.events)) {
      logs.value = res.events;
      totalLogs.value = res.total ?? res.events.length;
    } else {
      logs.value = [];
      totalLogs.value = 0;
    }
  } catch (err: any) {
    error.value = err?.message || 'Failed to query forensic logs from database';
    logs.value = [];
  } finally {
    isLoading.value = false;
  }
}

onMounted(() => {
  fetchLogs();
});

watch(selectedAction, () => {
  currentPage.value = 1;
  fetchLogs();
});

let searchDebounceTimer: any = null;
watch(searchQuery, () => {
  clearTimeout(searchDebounceTimer);
  searchDebounceTimer = setTimeout(() => {
    currentPage.value = 1;
    fetchLogs();
  }, 300);
});

const totalPages = computed(() => {
  const pages = Math.ceil(totalLogs.value / props.pageSize);
  return pages > 0 ? pages : 1;
});

function prevPage() {
  if (currentPage.value > 1) {
    currentPage.value--;
    fetchLogs();
  }
}

function nextPage() {
  if (currentPage.value < totalPages.value) {
    currentPage.value++;
    fetchLogs();
  }
}

const filteredLogs = computed(() => {
  if (!searchQuery.value) return logs.value;
  const q = searchQuery.value.toLowerCase();
  return logs.value.filter((ev) => {
    return (
      ev.client_ip.toLowerCase().includes(q) ||
      (ev.rule_id && ev.rule_id.toLowerCase().includes(q)) ||
      ev.method.toLowerCase().includes(q) ||
      ev.path.toLowerCase().includes(q) ||
      (ev.geo_data?.country && ev.geo_data.country.toLowerCase().includes(q))
    );
  });
});

function getActionBadgeClass(action: string): string {
  switch (action) {
    case 'allow':
      return 'bg-success/10 text-success border-success/30';
    case 'block':
      return 'bg-threat/10 text-threat border-threat/30';
    case 'challenge':
      return 'bg-warning/10 text-warning border-warning/30';
    case 'ban':
      return 'bg-threat/20 text-threat border-threat/40';
    default:
      return 'bg-muted text-muted-foreground border-border';
  }
}

function openModal(ev: ForensicEvent) {
  activeEvent.value = ev;
}

function closeModal() {
  activeEvent.value = null;
}

function handleCreateException(ev: ForensicEvent) {
  const cleanPath = ev.path.split('?')[0];
  const draft: ExceptionDraft = {
    host: ev.host || '*',
    path: cleanPath,
    method: ev.method,
    location: ev.method === 'GET' ? 'query' : 'body',
    param: '*',
    rule_id: ev.rule_id || '*',
  };
  emit('create-exception', draft);
  closeModal();
}

function formatLatency(durNs: number): string {
  const ms = durNs / 1000000;
  return ms < 1 ? `${(ms * 1000).toFixed(0)}µs` : `${ms.toFixed(1)}ms`;
}

function isPrivateIP(ip: string): boolean {
  if (!ip) return false;
  return (
    ip === '127.0.0.1' ||
    ip === '::1' ||
    ip === 'localhost' ||
    ip.startsWith('192.168.') ||
    ip.startsWith('10.') ||
    ip.startsWith('172.16.') ||
    ip.startsWith('172.17.') ||
    ip.startsWith('172.18.') ||
    ip.startsWith('172.19.') ||
    ip.startsWith('172.20.') ||
    ip.startsWith('172.21.') ||
    ip.startsWith('172.22.') ||
    ip.startsWith('172.23.') ||
    ip.startsWith('172.24.') ||
    ip.startsWith('172.25.') ||
    ip.startsWith('172.26.') ||
    ip.startsWith('172.27.') ||
    ip.startsWith('172.28.') ||
    ip.startsWith('172.29.') ||
    ip.startsWith('172.30.') ||
    ip.startsWith('172.31.')
  );
}

function getPayloadOrQuery(ev: ForensicEvent): string {
  if (ev.truncated_payload && ev.truncated_payload.trim() !== '') {
    return ev.truncated_payload;
  }
  if (ev.path && ev.path.includes('?')) {
    const qs = ev.path.slice(ev.path.indexOf('?') + 1);
    try {
      return decodeURIComponent(qs);
    } catch {
      return qs;
    }
  }
  return '(No payload or query parameters)';
}
</script>

<template>
  <div class="flex flex-col h-full bg-card text-card-foreground rounded-xl border border-border shadow-none overflow-hidden font-sans">
    <!-- Header Controls Toolbar -->
    <div class="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5 border-b border-border bg-card/90 backdrop-blur-md relative z-20">
      <!-- Title & Log Counter -->
      <div class="flex items-center gap-3">
        <span
          data-testid="logs-title"
          class="text-xs font-semibold tracking-wider uppercase text-muted-foreground"
        >
          Forensic Logs
        </span>
        <span class="text-xs text-muted-foreground/60">|</span>
        <span class="text-xs text-muted-foreground font-mono">
          {{ totalLogs }} records
        </span>
      </div>

      <!-- Controls: Search, Action Filter, Refresh -->
      <div class="flex items-center gap-2.5">
        <SearchInput
          v-model="searchQuery"
          clearable
          placeholder="Filter IP, Rule, Method, Country…"
          data-testid="logs-search-input"
          class="w-48 sm:w-64"
        />

        <!-- Action Filter Select -->
        <div class="relative z-30">
          <Select v-model="selectedAction">
            <SelectTrigger class="h-8 w-32 border-input bg-background text-foreground text-xs">
              <SelectValue placeholder="All Actions" />
            </SelectTrigger>
            <SelectContent class="border-border bg-popover text-popover-foreground z-50">
              <SelectItem value="all">All Actions</SelectItem>
              <SelectItem value="allow">Allow</SelectItem>
              <SelectItem value="block">Block</SelectItem>
              <SelectItem value="challenge">Challenge</SelectItem>
              <SelectItem value="ban">Ban</SelectItem>
            </SelectContent>
          </Select>
          <select
            v-model="selectedAction"
            data-testid="logs-action-filter-select"
            class="sr-only"
            tabindex="-1"
            aria-hidden="true"
          >
            <option value="all">All Actions</option>
            <option value="allow">Allow</option>
            <option value="block">Block</option>
            <option value="challenge">Challenge</option>
            <option value="ban">Ban</option>
          </select>
        </div>

        <!-- Refresh Button -->
        <button
          type="button"
          data-testid="logs-refresh-btn"
          @click="fetchLogs"
          :disabled="isLoading"
          class="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-border bg-muted text-foreground hover:bg-muted/80 disabled:opacity-50 transition-all cursor-pointer"
          title="Refresh Historical Logs"
        >
          <RotateCw class="w-3.5 h-3.5" :class="{ 'animate-spin': isLoading }" />
          <span>Refresh</span>
        </button>
      </div>
    </div>

    <!-- Error Banner -->
    <div
      v-if="error"
      class="px-5 py-2.5 bg-threat/10 border-b border-threat/20 text-threat text-xs flex items-center justify-between"
    >
      <div class="flex items-center gap-2">
        <AlertCircle class="w-4 h-4 text-threat shrink-0" />
        <span>{{ error }}</span>
      </div>
      <button
        type="button"
        @click="fetchLogs"
        class="underline hover:text-threat/80 font-medium cursor-pointer"
      >
        Retry
      </button>
    </div>

    <!-- Logs Table -->
    <div class="flex-1 overflow-auto">
      <Table container-class="overflow-visible">
        <TableHeader>
          <TableRow>
            <TableHead>Time</TableHead>
            <TableHead>Action</TableHead>
            <TableHead>Method & Path</TableHead>
            <TableHead>Client IP & Geo</TableHead>
            <TableHead>Rule / Threat</TableHead>
            <TableHead>Latency</TableHead>
            <TableHead class="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody class="font-mono tabular-nums">
          <TableRow
            v-for="ev in filteredLogs"
            :key="ev.event_id"
            data-testid="log-row"
            class="group cursor-pointer"
            @click="openModal(ev)"
          >
            <!-- Time -->
            <TableCell class="text-muted-foreground whitespace-nowrap">
              {{ new Date(ev.timestamp).toLocaleString() }}
            </TableCell>

            <!-- Action Badge -->
            <TableCell class="whitespace-nowrap">
              <span
                class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold tracking-wide uppercase border"
                :class="getActionBadgeClass(ev.action)"
              >
                <CheckCircle2 v-if="ev.action === 'allow'" class="w-2.5 h-2.5" />
                <ShieldAlert v-else-if="ev.action === 'block'" class="w-2.5 h-2.5" />
                <AlertTriangle v-else-if="ev.action === 'challenge'" class="w-2.5 h-2.5" />
                <Ban v-else-if="ev.action === 'ban'" class="w-2.5 h-2.5" />
                {{ ev.action }}
              </span>
            </TableCell>

            <!-- Method & Path -->
            <TableCell class="max-w-xs truncate text-foreground">
              <span class="font-bold text-primary mr-1.5">{{ ev.method }}</span>
              <span :title="ev.path">{{ ev.path }}</span>
            </TableCell>

            <!-- Client IP & Geo -->
            <TableCell class="whitespace-nowrap text-foreground">
              <span>{{ ev.client_ip }}</span>
              <span v-if="ev.geo_data?.country" class="ml-1.5 text-muted-foreground text-[11px]">
                [{{ ev.geo_data.country }}]
              </span>
            </TableCell>

            <!-- Rule / Threat -->
            <TableCell class="whitespace-nowrap">
              <span v-if="ev.rule_id" class="text-warning font-semibold">
                {{ ev.rule_id }}
              </span>
              <span v-else class="text-muted-foreground">-</span>
            </TableCell>

            <!-- Latency -->
            <TableCell class="text-muted-foreground whitespace-nowrap">
              {{ formatLatency(ev.latency) }}
            </TableCell>

            <!-- Action Buttons -->
            <TableCell class="text-right whitespace-nowrap" @click.stop>
              <button
                v-if="ev.action !== 'allow'"
                type="button"
                data-testid="log-create-exception-quick-btn"
                @click="handleCreateException(ev)"
                class="px-2 py-1 text-[11px] font-medium text-primary hover:text-primary-foreground bg-primary/10 hover:bg-primary border border-primary/30 rounded transition-all mr-2 shadow-none cursor-pointer"
                title="Create 1-Click Rule Exception"
              >
                Exception
              </button>
              <button
                type="button"
                @click="openModal(ev)"
                class="px-2 py-1 text-[11px] font-medium text-muted-foreground hover:text-foreground bg-muted hover:bg-muted/80 border border-border rounded transition-all cursor-pointer"
              >
                Inspect
              </button>
            </TableCell>
          </TableRow>

          <!-- Empty State -->
          <TableRow v-if="!isLoading && filteredLogs.length === 0">
            <TableCell colspan="7" class="py-12 text-center font-sans text-muted-foreground">
              <Database class="w-8 h-8 mx-auto mb-2 text-muted-foreground/60 opacity-60" />
              <p class="text-sm font-medium">No forensic logs found</p>
              <p class="text-xs text-muted-foreground/80 mt-1">Logs stored in the database matching your criteria will appear here</p>
            </TableCell>
          </TableRow>

          <!-- Loading State -->
          <TableRow v-if="isLoading && filteredLogs.length === 0">
            <TableCell colspan="7" class="py-12 text-center font-sans text-muted-foreground">
              <RotateCw class="w-8 h-8 mx-auto mb-2 text-primary animate-spin opacity-80" />
              <p class="text-sm font-medium">Querying forensic logs...</p>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </div>

    <!-- Pagination Footer -->
    <div class="flex items-center justify-between px-5 py-2.5 border-t border-border bg-card text-xs text-muted-foreground font-sans">
      <div>
        <span>Showing </span>
        <span class="font-mono text-foreground font-medium">
          {{ totalLogs > 0 ? (currentPage - 1) * props.pageSize + 1 : 0 }}
        </span>
        <span> to </span>
        <span class="font-mono text-foreground font-medium">
          {{ Math.min(currentPage * props.pageSize, totalLogs) }}
        </span>
        <span> of </span>
        <span class="font-mono text-foreground font-medium">{{ totalLogs }}</span>
        <span> records</span>
      </div>

      <div class="flex items-center gap-2">
        <button
          type="button"
          data-testid="logs-prev-page-btn"
          @click="prevPage"
          :disabled="currentPage <= 1 || isLoading"
          class="flex items-center gap-1 px-2.5 py-1 rounded border border-border bg-muted text-foreground hover:bg-muted/80 disabled:opacity-40 disabled:cursor-not-allowed transition-all cursor-pointer"
        >
          <ChevronLeft class="w-3.5 h-3.5" />
          <span>Previous</span>
        </button>

        <span class="px-2 font-mono text-foreground font-medium">
          Page {{ currentPage }} / {{ totalPages }}
        </span>

        <button
          type="button"
          data-testid="logs-next-page-btn"
          @click="nextPage"
          :disabled="currentPage >= totalPages || isLoading"
          class="flex items-center gap-1 px-2.5 py-1 rounded border border-border bg-muted text-foreground hover:bg-muted/80 disabled:opacity-40 disabled:cursor-not-allowed transition-all cursor-pointer"
        >
          <span>Next</span>
          <ChevronRight class="w-3.5 h-3.5" />
        </button>
      </div>
    </div>

    <!-- Forensic Detail Modal -->
    <div
      v-if="activeEvent"
      data-testid="forensic-modal"
      class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
    >
      <div class="w-full max-w-3xl max-h-[85vh] flex flex-col bg-popover border border-border rounded-xl shadow-none overflow-hidden font-sans text-popover-foreground">
        <!-- Modal Header -->
        <div class="flex items-center justify-between px-6 py-4 border-b border-border bg-card">
          <div class="flex items-center gap-3">
            <div class="p-2 rounded-lg bg-muted border border-border text-foreground">
              <FileCode class="w-5 h-5 text-muted-foreground" />
            </div>
            <div>
              <h3 class="text-sm font-bold text-foreground flex items-center gap-2">
                <span>{{ activeEvent.action === 'allow' ? 'Traffic Log Context' : 'Forensic Incident Context' }}</span>
                <span
                  class="px-2 py-0.5 rounded text-[10px] font-semibold uppercase border"
                  :class="getActionBadgeClass(activeEvent.action)"
                >
                  {{ activeEvent.action }}
                </span>
              </h3>
              <p class="text-xs text-muted-foreground font-mono mt-0.5">
                ID: {{ activeEvent.event_id }} • {{ new Date(activeEvent.timestamp).toISOString() }}
              </p>
            </div>
          </div>
          <button
            type="button"
            data-testid="modal-close-btn"
            @click="closeModal"
            class="p-1.5 text-muted-foreground hover:text-foreground hover:bg-muted rounded-lg transition-colors cursor-pointer"
          >
            <X class="w-5 h-5" />
          </button>
        </div>

        <!-- Modal Body Content -->
        <div class="flex-1 overflow-y-auto p-6 space-y-5 text-xs font-mono bg-popover text-popover-foreground">
          <!-- Request & Client Summary Grid -->
          <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 font-sans">
            <div class="p-3 bg-muted/40 border border-border rounded-lg">
              <span class="text-[10px] text-muted-foreground uppercase tracking-wider block mb-1">Target Host</span>
              <span class="font-mono text-foreground truncate block">{{ activeEvent.host }}</span>
            </div>
            <div class="p-3 bg-muted/40 border border-border rounded-lg">
              <span class="text-[10px] text-muted-foreground uppercase tracking-wider block mb-1">Client IP</span>
              <span class="font-mono text-foreground block">{{ activeEvent.client_ip }}</span>
            </div>
            <div class="p-3 bg-muted/40 border border-border rounded-lg">
              <span class="text-[10px] text-muted-foreground uppercase tracking-wider block mb-1">Rule ID</span>
              <span class="font-mono text-warning font-semibold block truncate">
                {{ activeEvent.rule_id || 'NONE' }}
              </span>
            </div>
            <div class="p-3 bg-muted/40 border border-border rounded-lg">
              <span class="text-[10px] text-muted-foreground uppercase tracking-wider block mb-1">Latency</span>
              <span class="font-mono text-foreground block">{{ formatLatency(activeEvent.latency) }}</span>
            </div>
          </div>

          <!-- JA4 Fingerprint & GeoData -->
          <div class="p-3.5 bg-muted/30 border border-border rounded-lg space-y-1.5">
            <div v-if="activeEvent.ja4" class="flex items-center gap-2">
              <span class="text-muted-foreground">JA4 Fingerprint:</span>
              <span class="text-foreground font-semibold">{{ activeEvent.ja4 }}</span>
            </div>
            <div v-if="activeEvent.geo_data" class="flex items-center gap-2">
              <span class="text-muted-foreground">Geo Intelligence:</span>
              <span class="text-foreground">
                {{ activeEvent.geo_data.country || (isPrivateIP(activeEvent.client_ip) ? 'Internal / Private Network (RFC 1918)' : 'Unknown / Unresolved') }}
                {{ activeEvent.geo_data.city ? ', ' + activeEvent.geo_data.city : '' }}
                {{ activeEvent.geo_data.asn ? ' (AS' + activeEvent.geo_data.asn + ')' : '' }}
              </span>
            </div>
          </div>

          <!-- Sanitized Headers -->
          <div>
            <h4 class="text-xs font-semibold text-foreground uppercase tracking-wider font-sans mb-2 flex items-center justify-between">
              <span>Sanitized Request Headers</span>
              <span class="text-[10px] text-muted-foreground font-normal">PII/PCI-DSS masked</span>
            </h4>
            <div class="p-3.5 bg-muted/60 border border-border rounded-lg overflow-x-auto max-h-48 text-foreground font-mono text-xs">
              <pre>{{ JSON.stringify(activeEvent.headers || {}, null, 2) }}</pre>
            </div>
          </div>

          <!-- Sanitized Raw Payload / Query Snippet -->
          <div>
            <h4 class="text-xs font-semibold text-foreground uppercase tracking-wider font-sans mb-2 flex items-center justify-between">
              <span>{{ activeEvent.method === 'GET' ? 'Inspected Query & URI Parameters' : 'Payload Snippet' }}</span>
              <span class="text-[10px] text-muted-foreground font-normal">Clamped to 2 KB cap</span>
            </h4>
            <div class="p-3.5 bg-muted/60 border border-border rounded-lg overflow-x-auto max-h-48 text-foreground font-mono text-xs">
              <pre>{{ getPayloadOrQuery(activeEvent) }}</pre>
            </div>
          </div>
        </div>

        <!-- Modal Footer Actions -->
        <div class="flex items-center justify-between px-6 py-3.5 border-t border-border bg-card font-sans">
          <div class="text-xs text-muted-foreground">
            <span v-if="activeEvent.action === 'allow'" class="text-success flex items-center gap-1.5 font-medium">
              <CheckCircle2 class="w-3.5 h-3.5 text-success" />
              <span>Request verified benign and allowed. No false-positive rule exception required.</span>
            </span>
            <span v-else>
              Clicking Create Exception pre-populates bypass criteria in Access Control
            </span>
          </div>
          <div class="flex items-center gap-2">
            <button
              type="button"
              @click="closeModal"
              class="px-4 py-2 text-xs font-medium text-foreground hover:bg-muted rounded-lg border border-border transition-colors cursor-pointer"
            >
              Close
            </button>
            <button
              v-if="activeEvent.action !== 'allow'"
              type="button"
              data-testid="log-modal-create-exception-btn"
              @click="handleCreateException(activeEvent)"
              class="flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-primary-foreground bg-primary hover:bg-primary/90 active:brightness-95 rounded-lg shadow-none transition-colors cursor-pointer"
            >
              <ExternalLink class="w-3.5 h-3.5" />
              <span>Create Exception</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
