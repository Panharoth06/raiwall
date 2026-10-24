<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { useRouter } from '@/router';
import { useConfigStore } from '@/stores/config';
import { api, type BanEntry } from '@/api/client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { DatePicker } from '@/components/ui/date-picker';
import RateLimitDetailDrawer from '@/components/http-flood/RateLimitDetailDrawer.vue';
import {
  Globe,
  Settings as SettingsIcon,
  RefreshCw,
  AlertTriangle,
  Loader2,
  ShieldOff,
  SlidersHorizontal,
} from 'lucide-vue-next';

const router = useRouter();
const configStore = useConfigStore();

const bans = ref<BanEntry[]>([]);
const loading = ref(false);
const error = ref<string | null>(null);

// Detail Slider Drawer State
const selectedBan = ref<BanEntry | null>(null);
const showDetailDrawer = ref(false);

const openDetail = (entry: BanEntry) => {
  selectedBan.value = entry;
  showDetailDrawer.value = true;
};

// Filters
const filterIp = ref('');
const filterApp = ref('all');
const filterStartAt = ref('');
const filterEndAt = ref('');

const pendingReleaseKey = ref<string | null>(null);
const releasedKeys = ref<Set<string>>(new Set());
const showUnblockAllModal = ref(false);
const unblockAllPending = ref(false);

let refreshTimer: ReturnType<typeof setInterval> | null = null;
let countdownTimer: ReturnType<typeof setInterval> | null = null;

const loadBans = async () => {
  loading.value = true;
  error.value = null;
  try {
    const data = await api.listBans();
    bans.value = data || [];
  } catch (err: unknown) {
    error.value = err instanceof Error ? err.message : 'Failed to load active bans';
  } finally {
    loading.value = false;
  }
};

onMounted(() => {
  loadBans();
  refreshTimer = setInterval(() => {
    api.listBans().then((data) => {
      bans.value = data || [];
    }).catch(() => {});
  }, 5000);

  countdownTimer = setInterval(() => {
    for (const b of bans.value) {
      if (b.remaining_seconds > 0) {
        b.remaining_seconds--;
      }
    }
  }, 1000);
});

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer);
  if (countdownTimer) clearInterval(countdownTimer);
});

// GeoIP Resolver Helper
const resolveCountry = (ip?: string, country?: string): string => {
  if (country) return country;
  if (!ip) return 'Unknown';
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('127.') || ip.startsWith('172.16.')) {
    return 'Internal Network';
  }
  if (ip.startsWith('51.12.')) return 'Sweden';
  if (ip.startsWith('159.89.') || ip.startsWith('151.243.')) return 'Germany';
  if (ip.startsWith('165.154.')) return 'Russia';
  if (ip.startsWith('185.177.')) return 'France';
  if (ip.startsWith('94.154.')) return 'Turkey';
  if (ip.startsWith('198.51.')) return 'United States';
  return 'Global';
};

// Application Resolver Helper
const resolveAppName = (siteId?: string): { name: string; host: string } => {
  if (siteId && configStore.sites?.length) {
    const s = configStore.sites.find((item) => item.id === siteId);
    if (s) {
      return { name: s.name, host: s.domains?.[0] || 'Specific Host' };
    }
  }
  return { name: 'Dashboard Proxy', host: 'Match All Host' };
};

// Reason and Action Text Formatter
const formatDetail = (entry: BanEntry) => {
  const r = (entry.reason || '').toLowerCase();
  let reason = entry.reason || 'Basic Access Limit was triggered';
  let action = 'Anti-Bot Challenge 1 minutes';

  if (r.includes('tier1') || r.includes('velocity') || r.includes('access')) {
    reason = '1 Reqs within 60 seconds, Basic Access Limit was triggered';
    action = 'Anti-Bot Challenge 1 minutes';
  } else if (r.includes('tier2') || r.includes('attack')) {
    reason = '10 Attacks within 60 seconds, Basic Attack Limit was triggered';
    action = 'Auto-Ban 30 minutes';
  } else if (r.includes('tier3') || r.includes('scanner') || r.includes('error')) {
    reason = '10 403/404 errors within 10 seconds, Basic Error Limit was triggered';
    action = 'Auto-Ban 30 minutes';
  }

  if (entry.duration) {
    const mins = Math.max(1, Math.round(entry.duration / (60 * 1000000000) || entry.duration / 60));
    action = `${r.includes('tier1') ? 'Anti-Bot Challenge' : 'Auto-Ban'} ${mins} minutes`;
  }

  return { reason, action };
};

const getTierBadge = (reason?: string) => {
  const r = (reason || '').toLowerCase();
  if (r.includes('tier2') || r.includes('attack')) {
    return {
      name: 'Attack Limit',
      cls: 'bg-threat/10 text-threat border-threat/20',
    };
  }
  if (r.includes('tier3') || r.includes('scanner') || r.includes('error')) {
    return {
      name: 'Scanner Trap',
      cls: 'bg-warning/10 text-warning border-warning/20',
    };
  }
  return {
    name: 'Access Velocity',
    cls: 'bg-primary/10 text-primary border-primary/20',
  };
};

const formatStartAt = (isoDate?: string): string => {
  if (!isoDate) {
    const d = new Date();
    return d.toISOString().replace('T', ' ').substring(0, 19);
  }
  try {
    const d = new Date(isoDate);
    const pad = (n: number) => (n < 10 ? '0' + n : n);
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  } catch {
    return isoDate;
  }
};

const formatCountdown = (seconds: number): string => {
  if (seconds <= 0) return 'Expired';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) {
    return `${h}h ${m < 10 ? '0' : ''}${m}m ${s < 10 ? '0' : ''}${s}s`;
  }
  return `${m}m ${s < 10 ? '0' : ''}${s}s`;
};

const filteredBans = computed(() => {
  const qIp = filterIp.value.toLowerCase().trim();
  const qApp = filterApp.value;

  return bans.value.filter((b) => {
    if (qIp) {
      const matchIp =
        b.key.toLowerCase().includes(qIp) ||
        (b.client_ip && b.client_ip.toLowerCase().includes(qIp)) ||
        (b.ja4 && b.ja4.toLowerCase().includes(qIp)) ||
        b.reason.toLowerCase().includes(qIp);
      if (!matchIp) return false;
    }

    if (qApp !== 'all') {
      if (b.site_id !== qApp) return false;
    }

    if (filterStartAt.value && b.banned_at) {
      if (new Date(b.banned_at) < new Date(filterStartAt.value)) return false;
    }

    if (filterEndAt.value && b.banned_at) {
      if (new Date(b.banned_at) > new Date(filterEndAt.value)) return false;
    }

    return true;
  });
});

const handleReleaseSingle = async (entry: BanEntry) => {
  pendingReleaseKey.value = entry.key;
  try {
    await api.releaseBan({ key: entry.key, ip: entry.client_ip });
    releasedKeys.value.add(entry.key);
    bans.value = bans.value.filter((b) => b.key !== entry.key);
  } catch (err: unknown) {
    error.value = err instanceof Error ? err.message : 'Failed to release ban';
  } finally {
    pendingReleaseKey.value = null;
  }
};

const handleConfirmUnblockAll = async () => {
  unblockAllPending.value = true;
  try {
    await api.releaseAllBans();
    bans.value = [];
    showUnblockAllModal.value = false;
  } catch (err: unknown) {
    error.value = err instanceof Error ? err.message : 'Failed to emergency unblock all';
  } finally {
    unblockAllPending.value = false;
  }
};

const goToSettings = () => {
  router.push('/http-flood/limits/settings');
};
</script>

<template>
  <div class="space-y-4">
    <!-- Filter Bar & SafeLine Action Buttons (Pure shadcn components) -->
    <div class="flex flex-wrap items-center justify-between gap-3">
      <div class="flex flex-wrap items-center gap-2.5 flex-1 min-w-0">
        <!-- IP Filter -->
        <Input
          v-model="filterIp"
          placeholder="IP Addr"
          class="h-9 w-48 text-xs font-sans"
        />

        <!-- Application Selector -->
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
          @click="loadBans"
          title="Refresh"
        >
          <RefreshCw class="w-3.5 h-3.5" :class="{ 'animate-spin': loading }" />
        </Button>
      </div>

      <!-- Actions Right: UNBLOCK ALL and SETTINGS -->
      <div class="flex items-center gap-2">
        <Button
          variant="outline"
          class="h-9 px-4 text-xs font-bold text-primary border border-primary bg-primary/10 hover:bg-primary/20 hover:text-primary uppercase tracking-wider transition-colors disabled:opacity-40 disabled:border-border disabled:bg-transparent disabled:text-muted-foreground flex items-center gap-1.5"
          :disabled="bans.length === 0 || loading"
          @click="showUnblockAllModal = true"
        >
          <ShieldOff class="w-3.5 h-3.5 shrink-0" />
          <span>UNBLOCK ALL</span>
        </Button>

        <Button
          variant="default"
          class="h-9 px-4 text-xs font-semibold uppercase tracking-wider gap-1.5 shadow-none"
          @click="goToSettings"
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

    <!-- SafeLine Multi-Column Rate Limiting Table using shadcn Table components -->
    <div class="bg-card border border-border rounded-lg overflow-hidden shadow-none">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead class="w-52">IP Addr</TableHead>
            <TableHead class="w-48">Application</TableHead>
            <TableHead class="min-w-[280px]">Detail</TableHead>
            <TableHead class="w-24 text-center">Blocked</TableHead>
            <TableHead class="w-44">Start At</TableHead>
            <TableHead class="w-28 text-right">Action</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <!-- Loading Skeleton -->
          <TableRow v-if="loading && bans.length === 0">
            <TableCell colspan="6" class="py-12 text-center text-muted-foreground">
              <Loader2 class="h-6 w-6 animate-spin mx-auto mb-2 text-primary" />
              <span class="text-xs">Loading active rate limit records...</span>
            </TableCell>
          </TableRow>

          <!-- Empty State -->
          <TableRow v-else-if="filteredBans.length === 0">
            <TableCell colspan="6" class="py-12 text-center">
              <ShieldOff class="h-8 w-8 mx-auto mb-2 text-muted-foreground/40" />
              <div class="text-xs font-semibold text-foreground">No active client bans</div>
              <div class="text-[11px] text-muted-foreground mt-0.5">
                No IP addresses currently exceed access velocity, attack threshold, or scanner limits.
              </div>
            </TableCell>
          </TableRow>

          <!-- Table Rows (Compact with Details Slider Drawer) -->
          <TableRow
            v-for="entry in filteredBans"
            :key="entry.key"
            class="group cursor-pointer"
            @click="openDetail(entry)"
          >
            <!-- 1. IP Addr + Country + JA4 -->
            <TableCell>
              <div class="flex items-center gap-2">
                <span class="font-mono font-medium text-foreground text-xs">
                  {{ entry.client_ip || entry.key }}
                </span>
                <span class="text-[11px] text-muted-foreground">
                  {{ resolveCountry(entry.client_ip, entry.country) }}
                </span>
                <span
                  v-if="entry.ja4"
                  class="font-mono text-[10px] px-1 py-0.2 rounded bg-muted text-muted-foreground border border-border truncate max-w-[120px]"
                >
                  {{ entry.ja4 }}
                </span>
              </div>
            </TableCell>

            <!-- 2. Application -->
            <TableCell>
              <div class="flex items-center gap-1.5">
                <Globe class="w-3.5 h-3.5 text-primary shrink-0" />
                <span class="font-medium text-foreground text-xs truncate max-w-[140px]">
                  {{ resolveAppName(entry.site_id).name }}
                </span>
                <span class="text-[11px] text-muted-foreground truncate max-w-[120px]">
                  ({{ resolveAppName(entry.site_id).host }})
                </span>
              </div>
            </TableCell>

            <!-- 3. Detail: Reason & Action -->
            <TableCell>
              <div class="flex items-center gap-2">
                <span
                  class="font-medium text-[11px] px-2 py-0.5 rounded border shrink-0"
                  :class="getTierBadge(entry.reason).cls"
                >
                  {{ getTierBadge(entry.reason).name }}
                </span>
                <span class="text-xs text-muted-foreground truncate max-w-[200px]">
                  {{ formatDetail(entry).action }}
                </span>
                <span
                  v-if="entry.remaining_seconds > 0"
                  class="text-[11px] text-muted-foreground font-mono shrink-0"
                >
                  ({{ formatCountdown(entry.remaining_seconds) }})
                </span>
                <span class="sr-only">({{ entry.reason }})</span>
              </div>
            </TableCell>

            <!-- 4. Blocked Hits -->
            <TableCell class="text-center">
              <span class="font-mono font-semibold text-foreground text-xs tabular-nums">
                {{ entry.blocked_count ?? 0 }}
              </span>
            </TableCell>

            <!-- 5. Start At -->
            <TableCell class="font-mono text-[11px] text-muted-foreground tabular-nums">
              {{ formatStartAt(entry.banned_at) }}
            </TableCell>

            <!-- 6. Action / Status -->
            <TableCell class="text-right">
              <div class="flex items-center justify-end gap-1.5" @click.stop>
                <span
                  role="button"
                  tabindex="0"
                  class="inline-flex items-center justify-center rounded-md text-xs font-medium h-7 px-2 text-muted-foreground hover:text-foreground hover:bg-muted transition-colors cursor-pointer select-none"
                  @click.stop="openDetail(entry)"
                  @keydown.enter.space.prevent="openDetail(entry)"
                >
                  <SlidersHorizontal class="h-3 w-3 mr-1" />
                  <span>Details</span>
                </span>
                <span
                  v-if="releasedKeys.has(entry.key)"
                  class="text-xs font-medium text-muted-foreground px-2"
                >
                  Unblocked
                </span>
                <Button
                  v-else
                  variant="ghost"
                  size="sm"
                  class="h-7 px-2 text-xs font-medium text-primary hover:text-primary hover:bg-primary/10"
                  :disabled="pendingReleaseKey === entry.key"
                  @click.stop="handleReleaseSingle(entry)"
                >
                  <Loader2
                    v-if="pendingReleaseKey === entry.key"
                    class="h-3 w-3 animate-spin mr-1"
                  />
                  <span>Unblock</span>
                </Button>
              </div>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </div>

    <!-- Slide-over Right Drawer (Sheet) for Granular Ban Forensics -->
    <RateLimitDetailDrawer
      v-model:open="showDetailDrawer"
      :entry="selectedBan"
      :unblocking="pendingReleaseKey === selectedBan?.key"
      @unblock="handleReleaseSingle"
    />

    <!-- Emergency Unblock All Confirmation Modal -->
    <Dialog :open="showUnblockAllModal" @update:open="(val) => (showUnblockAllModal = val)">
      <DialogContent class="sm:max-w-md bg-card text-foreground border-border">
        <DialogHeader>
          <div class="flex items-center gap-2 text-destructive mb-1">
            <AlertTriangle class="h-5 w-5" />
            <DialogTitle class="text-sm">Emergency Unblock All Clients?</DialogTitle>
          </div>
          <DialogDescription class="text-xs text-muted-foreground leading-relaxed">
            This operation will immediately flush all active client bans across the local node and publish an unblock broadcast to all cluster nodes. Malicious traffic will be re-evaluated from scratch.
          </DialogDescription>
        </DialogHeader>

        <div class="p-3 bg-destructive/10 border border-destructive/20 rounded-md text-xs text-destructive">
          Warning: {{ bans.length }} active ban{{ bans.length === 1 ? '' : 's' }} will be permanently removed.
        </div>

        <DialogFooter class="flex items-center justify-end gap-2 pt-2">
          <Button
            variant="outline"
            size="sm"
            class="h-8 text-xs"
            :disabled="unblockAllPending"
            @click="showUnblockAllModal = false"
          >
            Cancel
          </Button>
          <Button
            variant="destructive"
            size="sm"
            class="h-8 text-xs font-semibold gap-1.5"
            :disabled="unblockAllPending"
            @click="handleConfirmUnblockAll"
          >
            <Loader2 v-if="unblockAllPending" class="h-3.5 w-3.5 animate-spin" />
            <span>Confirm Emergency Unblock</span>
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
