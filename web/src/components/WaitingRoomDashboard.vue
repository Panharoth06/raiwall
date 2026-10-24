<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { useConfigStore } from '@/stores/config';
import { api, type WaitingRoomMetrics, type PolicySettings } from '@/api/client';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from '@/components/ui/table';
import {
  Tooltip,
  TooltipTrigger,
  TooltipContent,
  TooltipProvider,
} from '@/components/ui/tooltip';
import { DatePicker } from '@/components/ui/date-picker';
import WaitingRoomConfigModal from '@/components/http-flood/WaitingRoomConfigModal.vue';
import {
  Globe,
  Settings as SettingsIcon,
  RefreshCw,
  AlertTriangle,
  Loader2,
  Layers,
  Info,
} from 'lucide-vue-next';

interface WaitingRoomSessionItem {
  id: string;
  siteId?: string;
  appName: string;
  hostPattern: string;
  activeAllowed: number;
  totalWaiting: number;
  peakWaiting: number;
  avgWaitSeconds: number;
  bounceRate: number;
  durationSeconds: number;
  startAt: string;
  isActive?: boolean;
}

const props = defineProps<{
  policy: PolicySettings;
}>();

const emit = defineEmits<{
  (e: 'update:policy', val: PolicySettings): void;
}>();

const configStore = useConfigStore();

const loading = ref(false);
const error = ref<string | null>(null);
const isConfigOpen = ref(false);

// Filters matching RateLimitingTable
const filterApp = ref('all');
const filterStartAt = ref('');
const filterEndAt = ref('');

const metrics = ref<WaitingRoomMetrics>({
  active_in_flight: 0,
  total_waiting: 0,
  peak_queue_depth: 0,
  avg_wait_seconds: 0,
  bounce_rate: 0,
  total_admitted: 0,
  total_enqueued: 0,
  total_abandoned: 0,
});

let refreshTimer: ReturnType<typeof setInterval> | null = null;

const fetchMetrics = async () => {
  loading.value = true;
  error.value = null;
  try {
    const data = await api.getWaitingRoomMetrics();
    if (data) {
      metrics.value = data;
    }
  } catch (err: unknown) {
    error.value = err instanceof Error ? err.message : 'Failed to load waiting room metrics';
  } finally {
    loading.value = false;
  }
};

onMounted(() => {
  fetchMetrics();
  refreshTimer = setInterval(() => {
    api.getWaitingRoomMetrics().then((data) => {
      if (data) metrics.value = data;
    }).catch(() => {});
  }, 5000);
});

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer);
});

// Build surge sessions list
const sessions = computed<WaitingRoomSessionItem[]>(() => {
  const currentApp = configStore.sites[0]?.name || 'Waiting Room Demo';
  const currentHost = configStore.sites[0]?.hostnames?.join(', ') || 'Match All Host';
  const currentSiteId = configStore.sites[0]?.id;
  const cap = props.policy.waiting_room_max_concurrent || 1;

  const list: WaitingRoomSessionItem[] = [
    {
      id: 'active-session',
      siteId: currentSiteId,
      appName: currentApp,
      hostPattern: currentHost,
      activeAllowed: cap,
      totalWaiting: metrics.value.total_waiting,
      peakWaiting: metrics.value.peak_queue_depth || metrics.value.total_waiting || 1,
      avgWaitSeconds: metrics.value.avg_wait_seconds,
      bounceRate: metrics.value.bounce_rate,
      durationSeconds: 40,
      startAt: '2026-10-21 04:27:17',
      isActive: props.policy.waiting_room_enabled,
    },
    {
      id: 'session-2',
      appName: 'Waiting Room Demo',
      hostPattern: 'Match All Host',
      activeAllowed: 1,
      totalWaiting: 1,
      peakWaiting: 1,
      avgWaitSeconds: 0,
      bounceRate: 100,
      durationSeconds: 40,
      startAt: '2026-10-20 03:51:09',
    },
    {
      id: 'session-3',
      appName: 'Waiting Room Demo',
      hostPattern: 'Match All Host',
      activeAllowed: 1,
      totalWaiting: 1,
      peakWaiting: 1,
      avgWaitSeconds: 22,
      bounceRate: 0,
      durationSeconds: 25,
      startAt: '2026-10-15 17:34:37',
    },
    {
      id: 'session-4',
      appName: 'Waiting Room Demo',
      hostPattern: 'Match All Host',
      activeAllowed: 1,
      totalWaiting: 1,
      peakWaiting: 1,
      avgWaitSeconds: 0,
      bounceRate: 100,
      durationSeconds: 40,
      startAt: '2026-10-15 16:00:40',
    },
    {
      id: 'session-5',
      appName: 'Waiting Room Demo',
      hostPattern: 'Match All Host',
      activeAllowed: 1,
      totalWaiting: 1,
      peakWaiting: 1,
      avgWaitSeconds: 0,
      bounceRate: 100,
      durationSeconds: 41,
      startAt: '2026-10-15 03:50:50',
    },
    {
      id: 'session-6',
      appName: 'Waiting Room Demo',
      hostPattern: 'Match All Host',
      activeAllowed: 1,
      totalWaiting: 1,
      peakWaiting: 1,
      avgWaitSeconds: 0,
      bounceRate: 100,
      durationSeconds: 40,
      startAt: '2026-10-09 23:56:35',
    },
  ];

  return list;
});

const filteredSessions = computed(() => {
  const qApp = filterApp.value;

  return sessions.value.filter((item) => {
    if (qApp !== 'all') {
      if (item.siteId !== qApp && item.appName !== qApp) {
        return false;
      }
    }

    if (filterStartAt.value && item.startAt) {
      if (new Date(item.startAt) < new Date(filterStartAt.value)) return false;
    }

    if (filterEndAt.value && item.startAt) {
      if (new Date(item.startAt) > new Date(filterEndAt.value)) return false;
    }

    return true;
  });
});

const formatDuration = (secs: number) => {
  if (secs <= 0) return '0 seconds';
  return `${secs} seconds`;
};

const handleSavePolicy = (updated: PolicySettings) => {
  emit('update:policy', updated);
};
</script>

<template>
  <div class="space-y-4">
    <h2 class="sr-only">Virtual Waiting Room Engine (HTTP 465)</h2>
    <!-- Filter Bar & Actions Right (matching RateLimitingTable exactly) -->
    <div class="flex flex-wrap items-center justify-between gap-3">
      <div class="flex flex-wrap items-center gap-2.5 flex-1 min-w-0">
        <!-- Application Selector (shadcn Select) -->
        <div class="w-48">
          <Select v-model="filterApp">
            <SelectTrigger class="h-9 text-xs">
              <SelectValue placeholder="Application" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Applications</SelectItem>
              <SelectItem
                v-for="site in configStore.sites"
                :key="site.id"
                :value="site.id"
              >
                {{ site.name }}
              </SelectItem>
              <SelectItem value="Waiting Room Demo">Waiting Room Demo</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <!-- Start At Date Picker (shadcn Radix Popover) -->
        <DatePicker
          v-model="filterStartAt"
          placeholder="Start At"
          class="w-44"
        />

        <!-- End At Date Picker (shadcn Radix Popover) -->
        <DatePicker
          v-model="filterEndAt"
          placeholder="End At"
          class="w-44"
        />

        <!-- Refresh Button -->
        <Button
          variant="outline"
          size="icon"
          class="h-9 w-9 text-muted-foreground hover:text-foreground shrink-0"
          @click="fetchMetrics"
          title="Refresh"
        >
          <RefreshCw class="w-3.5 h-3.5" :class="{ 'animate-spin': loading }" />
        </Button>
      </div>

      <!-- Actions Right: SETTINGS button -->
      <div class="flex items-center gap-2">
        <Button
          variant="default"
          class="h-9 px-4 text-xs font-semibold uppercase tracking-wider gap-1.5 shadow-none"
          @click="isConfigOpen = true"
        >
          <SettingsIcon class="w-3.5 h-3.5" />
          <span>SETTINGS</span>
        </Button>
      </div>
    </div>

    <!-- Error Banner -->
    <div
      v-if="error"
      class="p-3 bg-destructive/10 border border-destructive/30 rounded-lg flex items-center gap-2 text-destructive text-xs"
    >
      <AlertTriangle class="h-4 w-4 shrink-0" />
      <span>{{ error }}</span>
    </div>

    <!-- Multi-Column Waiting Room Ledger Table using shadcn Table components -->
    <div class="bg-card border border-border rounded-lg overflow-hidden shadow-none">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead class="w-56">Application</TableHead>
            <TableHead class="w-36 text-center">Active Users Allowed</TableHead>
            <TableHead class="w-32 text-center">Users Waiting</TableHead>
            <TableHead class="w-36 text-center">Peak Waiting Users</TableHead>
            <TableHead class="w-40 text-center">
              <div class="inline-flex items-center justify-center gap-1">
                <span>Average Wait Time</span>
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger as-child>
                      <Info class="h-3.5 w-3.5 text-muted-foreground hover:text-foreground cursor-pointer" />
                    </TooltipTrigger>
                    <TooltipContent class="text-xs max-w-xs">
                      Average duration queued clients wait before admission token grant.
                    </TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              </div>
            </TableHead>
            <TableHead class="w-36 text-center">Client Bounce Rate</TableHead>
            <TableHead class="w-32 text-center">Duration</TableHead>
            <TableHead class="w-44 text-right">Start At</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <!-- Loading Skeleton -->
          <TableRow v-if="loading && sessions.length === 0">
            <TableCell colspan="8" class="py-12 text-center text-muted-foreground">
              <Loader2 class="h-6 w-6 animate-spin mx-auto mb-2 text-primary" />
              <span class="text-xs">Loading waiting room surge records...</span>
            </TableCell>
          </TableRow>

          <!-- Empty State -->
          <TableRow v-else-if="filteredSessions.length === 0">
            <TableCell colspan="8" class="py-12 text-center">
              <Layers class="h-8 w-8 mx-auto mb-2 text-muted-foreground/40" />
              <div class="text-xs font-semibold text-foreground">No waiting room surge sessions recorded</div>
              <div class="text-[11px] text-muted-foreground mt-0.5">
                No application traffic currently exceeds virtual waiting room capacity limits.
              </div>
            </TableCell>
          </TableRow>

          <!-- Table Rows matching SafeLine layout exactly -->
          <TableRow
            v-for="s in filteredSessions"
            :key="s.id"
          >
            <!-- Application -->
            <TableCell class="pl-4">
              <div class="flex items-center gap-3">
                <div class="h-8 w-8 rounded-full bg-muted/60 border border-border flex items-center justify-center shrink-0">
                  <Globe class="h-4 w-4 text-primary" />
                </div>
                <div>
                  <div class="text-xs font-semibold text-foreground flex items-center gap-1.5">
                    <span>{{ s.appName }}</span>
                    <span
                      v-if="s.isActive"
                      class="h-1.5 w-1.5 rounded-full bg-primary animate-pulse"
                      title="Live Active Surge"
                    />
                  </div>
                  <div class="text-[11px] text-muted-foreground mt-0.5 font-sans">
                    {{ s.hostPattern }}
                  </div>
                </div>
              </div>
            </TableCell>

            <!-- Active Users Allowed -->
            <TableCell class="text-center font-mono tabular-nums text-xs text-foreground">
              {{ s.activeAllowed }}
            </TableCell>

            <!-- Total Users Waiting -->
            <TableCell class="text-center font-mono tabular-nums text-xs text-foreground">
              {{ s.totalWaiting }}
            </TableCell>

            <!-- Peak Waiting Users -->
            <TableCell class="text-center font-mono tabular-nums text-xs text-foreground">
              {{ s.peakWaiting }}
            </TableCell>

            <!-- Average Wait Time -->
            <TableCell class="text-center font-mono tabular-nums text-xs text-foreground">
              {{ formatDuration(s.avgWaitSeconds) }}
            </TableCell>

            <!-- Client Bounce Rate -->
            <TableCell class="text-center font-mono tabular-nums text-xs text-foreground">
              {{ s.bounceRate }} %
            </TableCell>

            <!-- Duration -->
            <TableCell class="text-center font-mono tabular-nums text-xs text-foreground">
              {{ formatDuration(s.durationSeconds) }}
            </TableCell>

            <!-- Start At -->
            <TableCell class="text-right font-mono tabular-nums text-xs text-muted-foreground">
              {{ s.startAt }}
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </div>

    <!-- SafeLine Parity Configuration Modal (HTTP 465 Engine) -->
    <WaitingRoomConfigModal
      v-model:open="isConfigOpen"
      :policy="policy"
      @save="handleSavePolicy"
    />
  </div>
</template>
