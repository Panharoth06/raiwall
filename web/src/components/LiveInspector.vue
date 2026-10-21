<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import {
  Play,
  Pause,
  Trash2,
  Search,
  ShieldAlert,
  FileCode,
  ExternalLink,
  X,
  CheckCircle2,
  AlertTriangle,
  Ban,
  Activity,
} from 'lucide-vue-next';
import { useEventStream } from '@/composables/useEventStream';
import type { ForensicEvent, ExceptionDraft } from '@/types/telemetry';
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';

const props = withDefaults(
  defineProps<{
    initialFilter?: { action?: string; rule_id?: string; country?: string };
    maxEvents?: number;
    streamComposable?: ReturnType<typeof useEventStream>;
  }>(),
  {
    maxEvents: 200,
  }
);

const emit = defineEmits<{
  (e: 'create-exception', draft: ExceptionDraft): void;
}>();

// Use injected or default event stream composable
const stream = props.streamComposable || useEventStream(props.initialFilter, props.maxEvents);
const { events, isConnected, isPaused, pause, resume, clear } = stream;

onMounted(() => {
  if (!props.streamComposable) {
    stream.connect();
  }
});

onUnmounted(() => {
  if (!props.streamComposable) {
    stream.disconnect();
  }
});

// Search and filter state
const searchQuery = ref('');
const selectedAction = ref<string>('all');
const activeEvent = ref<ForensicEvent | null>(null);

const filteredEvents = computed(() => {
  return events.value.filter((ev) => {
    if (selectedAction.value !== 'all' && ev.action !== selectedAction.value) {
      return false;
    }
    if (!searchQuery.value) return true;
    const q = searchQuery.value.toLowerCase();
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
      return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
    case 'block':
      return 'bg-rose-500/10 text-rose-400 border-rose-500/20';
    case 'challenge':
      return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
    case 'ban':
      return 'bg-purple-500/10 text-purple-400 border-purple-500/20';
    default:
      return 'bg-zinc-500/10 text-zinc-400 border-zinc-500/20';
  }
}

function getSeverityBadgeClass(sev: string): string {
  switch (sev) {
    case 'critical':
      return 'text-rose-400 bg-rose-500/10';
    case 'high':
      return 'text-orange-400 bg-orange-500/10';
    case 'medium':
      return 'text-amber-400 bg-amber-500/10';
    case 'low':
      return 'text-blue-400 bg-blue-500/10';
    default:
      return 'text-zinc-400 bg-zinc-500/10';
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
  <div class="flex flex-col h-full bg-[#0d0f14] text-zinc-100 rounded-xl border border-zinc-800 shadow-2xl overflow-hidden font-sans">
    <!-- Header Controls Toolbar -->
    <div class="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5 border-b border-zinc-800 bg-[#12151c]/90 backdrop-blur-md">
      <!-- Connection & Title -->
      <div class="flex items-center gap-3">
        <div class="flex items-center gap-2">
          <div
            data-testid="status-indicator"
            class="w-2.5 h-2.5 rounded-full transition-all duration-300"
            :class="isConnected ? 'bg-emerald-400 shadow-[0_0_8px_#34d399]' : 'bg-rose-500'"
          />
          <span class="text-xs font-semibold tracking-wider uppercase text-zinc-400">
            {{ isConnected ? 'Live Telemetry' : 'Disconnected' }}
          </span>
        </div>
        <span class="text-xs text-zinc-600">|</span>
        <span class="text-xs text-zinc-400 font-mono">
          {{ filteredEvents.length }} events
        </span>
      </div>

      <!-- Controls: Pause/Resume, Clear, Filter, Search -->
      <div class="flex items-center gap-2.5">
        <!-- Search Input -->
        <div class="relative">
          <Search class="absolute left-2.5 top-2.5 w-3.5 h-3.5 text-zinc-500" />
          <input
            v-model="searchQuery"
            type="text"
            placeholder="Filter IP, Rule, Method, Country..."
            data-testid="live-search-input"
            class="w-48 sm:w-64 pl-8 pr-3 py-1.5 text-xs bg-zinc-900 border border-zinc-700/80 rounded-lg text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all"
          />
        </div>

        <!-- Action Filter Select Component Dropdown -->
        <div class="relative">
          <Select v-model="selectedAction">
            <SelectTrigger class="h-8 w-32 border-zinc-700/80 bg-zinc-900 text-zinc-200 text-xs">
              <SelectValue placeholder="All Actions" />
            </SelectTrigger>
            <SelectContent class="border-zinc-700 bg-zinc-900 text-zinc-200">
              <SelectItem value="all">All Actions</SelectItem>
              <SelectItem value="allow">Allow</SelectItem>
              <SelectItem value="block">Block</SelectItem>
              <SelectItem value="challenge">Challenge</SelectItem>
              <SelectItem value="ban">Ban</SelectItem>
            </SelectContent>
          </Select>
          <select
            v-model="selectedAction"
            data-testid="action-filter-select"
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

        <!-- Pause / Resume Toggle -->
        <button
          type="button"
          data-testid="pause-resume-btn"
          @click="isPaused ? resume() : pause()"
          class="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border transition-all"
          :class="
            isPaused
              ? 'bg-amber-500/15 border-amber-500/40 text-amber-300 hover:bg-amber-500/25'
              : 'bg-zinc-800 border-zinc-700 text-zinc-300 hover:bg-zinc-700'
          "
        >
          <Play v-if="isPaused" class="w-3.5 h-3.5" />
          <Pause v-else class="w-3.5 h-3.5" />
          <span>{{ isPaused ? 'Resume' : 'Pause' }}</span>
        </button>

        <!-- Clear Table Button -->
        <button
          type="button"
          data-testid="clear-events-btn"
          @click="clear"
          class="p-1.5 text-zinc-400 hover:text-zinc-200 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded-lg transition-all"
          title="Clear Event Stream"
        >
          <Trash2 class="w-3.5 h-3.5" />
        </button>
      </div>
    </div>

    <!-- Live Event Table -->
    <div class="flex-1 overflow-auto">
      <table class="w-full text-left border-collapse text-xs">
        <thead class="sticky top-0 bg-[#12151c] text-zinc-400 font-semibold border-b border-zinc-800 z-10 shadow-sm">
          <tr>
            <th class="py-2.5 px-4">Time</th>
            <th class="py-2.5 px-4">Action</th>
            <th class="py-2.5 px-4">Method & Path</th>
            <th class="py-2.5 px-4">Client IP & Geo</th>
            <th class="py-2.5 px-4">Rule / Threat</th>
            <th class="py-2.5 px-4">Latency</th>
            <th class="py-2.5 px-4 text-right">Actions</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-zinc-800/60 font-mono">
          <tr
            v-for="ev in filteredEvents"
            :key="ev.event_id"
            data-testid="event-row"
            class="hover:bg-zinc-800/40 transition-colors group cursor-pointer"
            @click="openModal(ev)"
          >
            <!-- Time -->
            <td class="py-2.5 px-4 text-zinc-400 whitespace-nowrap">
              {{ new Date(ev.timestamp).toLocaleTimeString() }}
            </td>

            <!-- Action Badge -->
            <td class="py-2.5 px-4 whitespace-nowrap">
              <span
                class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold tracking-wide uppercase border"
                :class="getActionBadgeClass(ev.action)"
              >
                <CheckCircle2 v-if="ev.action === 'allow'" class="w-2.5 h-2.5 text-slate-400" />
                <ShieldAlert v-else-if="ev.action === 'block'" class="w-2.5 h-2.5 text-slate-400" />
                <AlertTriangle v-else-if="ev.action === 'challenge'" class="w-2.5 h-2.5 text-slate-400" />
                <Ban v-else-if="ev.action === 'ban'" class="w-2.5 h-2.5 text-slate-400" />
                {{ ev.action }}
              </span>
            </td>

            <!-- Method & Path -->
            <td class="py-2.5 px-4 max-w-xs truncate text-zinc-200">
              <span class="font-bold text-cyan-400 mr-1.5">{{ ev.method }}</span>
              <span :title="ev.path">{{ ev.path }}</span>
            </td>

            <!-- Client IP & Geo -->
            <td class="py-2.5 px-4 whitespace-nowrap text-zinc-300">
              <span>{{ ev.client_ip }}</span>
              <span v-if="ev.geo_data?.country" class="ml-1.5 text-zinc-500 text-[11px]">
                [{{ ev.geo_data.country }}]
              </span>
            </td>

            <!-- Rule / Threat -->
            <td class="py-2.5 px-4 whitespace-nowrap">
              <span v-if="ev.rule_id" class="text-amber-300 font-semibold">
                {{ ev.rule_id }}
              </span>
              <span v-else class="text-zinc-600">-</span>
            </td>

            <!-- Latency -->
            <td class="py-2.5 px-4 text-zinc-400 whitespace-nowrap">
              {{ formatLatency(ev.latency) }}
            </td>

            <!-- Action Buttons -->
            <td class="py-2.5 px-4 text-right whitespace-nowrap" @click.stop>
              <button
                v-if="ev.action !== 'allow'"
                type="button"
                data-testid="create-exception-quick-btn"
                @click="handleCreateException(ev)"
                class="px-2 py-1 text-[11px] font-medium text-primary hover:text-primary-foreground bg-primary/10 hover:bg-primary border border-primary/30 rounded transition-all mr-2 shadow-none"
                title="Create 1-Click Rule Exception"
              >
                Exception
              </button>
              <button
                type="button"
                @click="openModal(ev)"
                class="px-2 py-1 text-[11px] font-medium text-muted-foreground hover:text-foreground bg-muted hover:bg-muted/80 border border-border rounded transition-all"
              >
                Inspect
              </button>
            </td>
          </tr>

          <!-- Empty State -->
          <tr v-if="filteredEvents.length === 0">
            <td colspan="7" class="py-12 text-center text-zinc-500 font-sans">
              <Activity class="w-8 h-8 mx-auto mb-2 text-zinc-600 opacity-60 animate-pulse" />
              <p class="text-sm font-medium">Waiting for incoming telemetry events...</p>
              <p class="text-xs text-zinc-600 mt-1">Events will appear automatically via Server-Sent Events</p>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Forensic Detail Modal -->
    <div
      v-if="activeEvent"
      data-testid="forensic-modal"
      class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm"
    >
      <div class="w-full max-w-3xl max-h-[85vh] flex flex-col bg-[#12151c] border border-zinc-700 rounded-xl shadow-2xl overflow-hidden font-sans">
        <!-- Modal Header -->
        <div class="flex items-center justify-between px-6 py-4 border-b border-border bg-card">
          <div class="flex items-center gap-3">
            <div class="p-2 rounded-lg bg-muted border border-border text-foreground">
              <FileCode class="w-5 h-5 text-muted-foreground" />
            </div>
            <div>
              <h3 class="text-sm font-bold text-foreground flex items-center gap-2">
                <span>{{ activeEvent.action === 'allow' ? 'Traffic Telemetry Context' : 'Forensic Incident Context' }}</span>
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
            class="p-1.5 text-muted-foreground hover:text-foreground hover:bg-muted rounded-lg transition-colors"
          >
            <X class="w-5 h-5" />
          </button>
        </div>

        <!-- Modal Body Content -->
        <div class="flex-1 overflow-y-auto p-6 space-y-5 text-xs font-mono">
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
              <span class="font-mono text-amber-400 font-semibold block truncate">
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
            <div class="p-3.5 bg-muted/50 border border-border rounded-lg overflow-x-auto max-h-48 text-foreground">
              <pre>{{ JSON.stringify(activeEvent.headers || {}, null, 2) }}</pre>
            </div>
          </div>

          <!-- Sanitized Raw Payload / Query Snippet -->
          <div>
            <h4 class="text-xs font-semibold text-foreground uppercase tracking-wider font-sans mb-2 flex items-center justify-between">
              <span>{{ activeEvent.method === 'GET' ? 'Inspected Query & URI Parameters' : 'Payload Snippet' }}</span>
              <span class="text-[10px] text-muted-foreground font-normal">Clamped to 2 KB cap</span>
            </h4>
            <div class="p-3.5 bg-muted/50 border border-border rounded-lg overflow-x-auto max-h-48 text-foreground">
              <pre>{{ getPayloadOrQuery(activeEvent) }}</pre>
            </div>
          </div>
        </div>

        <!-- Modal Footer Actions -->
        <div class="flex items-center justify-between px-6 py-3.5 border-t border-border bg-card font-sans">
          <div class="text-xs text-muted-foreground">
            <span v-if="activeEvent.action === 'allow'" class="text-emerald-400 flex items-center gap-1.5 font-medium">
              <CheckCircle2 class="w-3.5 h-3.5" />
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
              class="px-4 py-2 text-xs font-medium text-foreground hover:bg-muted rounded-lg border border-border transition-colors"
            >
              Close
            </button>
            <button
              v-if="activeEvent.action !== 'allow'"
              type="button"
              data-testid="modal-create-exception-btn"
              @click="handleCreateException(activeEvent)"
              class="flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-primary-foreground bg-primary hover:bg-primary/90 active:brightness-95 rounded-lg shadow-none transition-colors"
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
