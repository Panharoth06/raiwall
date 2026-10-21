<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { api, type BanEntry } from '@/api/client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  ShieldAlert,
  ShieldCheck,
  Search,
  RefreshCw,
  AlertTriangle,
  Loader2,
  Trash2,
} from 'lucide-vue-next';

const bans = ref<BanEntry[]>([]);
const loading = ref(false);
const error = ref<string | null>(null);
const searchQuery = ref('');
const pendingReleaseKey = ref<string | null>(null);
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
  // Poll ban list every 5 seconds
  refreshTimer = setInterval(() => {
    api.listBans().then((data) => {
      bans.value = data || [];
    }).catch(() => {});
  }, 5000);

  // Decrement remaining seconds locally every 1 second
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

const filteredBans = computed(() => {
  const q = searchQuery.value.toLowerCase().trim();
  if (!q) return bans.value;
  return bans.value.filter(
    (b) =>
      b.key.toLowerCase().includes(q) ||
      (b.client_ip && b.client_ip.toLowerCase().includes(q)) ||
      (b.ja4 && b.ja4.toLowerCase().includes(q)) ||
      b.reason.toLowerCase().includes(q)
  );
});

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

const handleReleaseSingle = async (entry: BanEntry) => {
  pendingReleaseKey.value = entry.key;
  try {
    await api.releaseBan({ key: entry.key, ip: entry.client_ip });
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
</script>

<template>
  <div class="space-y-4">
    <!-- Action Bar -->
    <div class="flex flex-wrap items-center justify-between gap-3">
      <div class="relative w-72">
        <Search class="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
        <Input
          v-model="searchQuery"
          placeholder="Filter by IP, JA4 or reason..."
          class="pl-8 h-8 text-xs font-mono"
        />
      </div>

      <div class="flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          class="h-8 gap-1.5 text-xs"
          :disabled="loading"
          @click="loadBans"
        >
          <RefreshCw class="h-3.5 w-3.5" :class="{ 'animate-spin': loading }" />
          <span>Refresh</span>
        </Button>

        <Button
          variant="destructive"
          size="sm"
          class="h-8 gap-1.5 text-xs font-semibold"
          :disabled="bans.length === 0 || loading"
          @click="showUnblockAllModal = true"
        >
          <AlertTriangle class="h-3.5 w-3.5" />
          <span>UNBLOCK ALL</span>
        </Button>
      </div>
    </div>

    <!-- Error Banner -->
    <div
      v-if="error"
      class="p-3 bg-destructive/10 border border-destructive/20 rounded-md text-destructive text-xs flex items-center justify-between gap-3"
    >
      <div class="flex items-center gap-2 min-w-0">
        <AlertTriangle class="h-4 w-4 shrink-0 text-destructive" />
        <span class="truncate">{{ error }}</span>
      </div>
      <Button variant="ghost" size="sm" class="h-6 text-xs text-destructive hover:bg-destructive/10 shrink-0" @click="loadBans">Retry</Button>
    </div>

    <!-- Table Container -->
    <div class="border border-border rounded-lg bg-card overflow-hidden">
      <!-- Loading Skeleton -->
      <div v-if="loading && bans.length === 0" class="p-8 text-center text-muted-foreground text-xs">
        <Loader2 class="h-5 w-5 animate-spin mx-auto mb-2 text-primary" />
        <span>Loading active banned client registry...</span>
      </div>

      <!-- Empty State -->
      <div
        v-else-if="filteredBans.length === 0"
        class="p-8 text-center text-muted-foreground text-xs"
      >
        <ShieldCheck class="h-8 w-8 mx-auto mb-2 text-primary/70" />
        <p class="font-medium text-foreground text-sm">No active client bans</p>
        <p class="text-sm mt-1 text-muted-foreground max-w-md mx-auto">
          All incoming client traffic is currently within rate limits. Tier 1–3 volumetric filters and scanner traps are actively monitoring incoming requests.
        </p>
      </div>

      <!-- Active Bans Table -->
      <table v-else class="w-full text-xs text-left border-collapse">
        <thead>
          <tr class="border-b border-border bg-muted/40 text-muted-foreground text-xs uppercase tracking-wider">
            <th class="py-2.5 px-3 font-semibold">Target Client</th>
            <th class="py-2.5 px-3 font-semibold">Trigger Reason</th>
            <th class="py-2.5 px-3 font-semibold">Banned At</th>
            <th class="py-2.5 px-3 font-semibold">Time Remaining</th>
            <th class="py-2.5 px-3 font-semibold text-right">Actions</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-border font-sans">
          <tr
            v-for="entry in filteredBans"
            :key="entry.key"
            class="hover:bg-muted/20 transition-colors"
          >
            <!-- Target Client (IP + JA4) -->
            <td class="py-2.5 px-3 font-mono">
              <div class="font-semibold text-foreground text-xs">
                {{ entry.client_ip || entry.key }}
              </div>
              <div v-if="entry.ja4" class="text-xs text-muted-foreground truncate max-w-xs mt-0.5">
                JA4: {{ entry.ja4 }}
              </div>
            </td>

            <!-- Reason -->
            <td class="py-2.5 px-3">
              <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono bg-muted text-foreground border border-border">
                <ShieldAlert class="h-3 w-3 text-destructive" />
                {{ entry.reason }}
              </span>
            </td>

            <!-- Banned At -->
            <td class="py-2.5 px-3 text-muted-foreground font-mono text-xs">
              {{ new Date(entry.banned_at).toLocaleTimeString() }}
            </td>

            <!-- Remaining Duration -->
            <td class="py-2.5 px-3 font-mono font-medium tabular-nums text-foreground text-xs">
              {{ formatCountdown(entry.remaining_seconds) }}
            </td>

            <!-- Actions -->
            <td class="py-2.5 px-3 text-right">
              <Button
                variant="outline"
                size="sm"
                class="h-7 text-xs gap-1"
                :disabled="pendingReleaseKey === entry.key"
                @click="handleReleaseSingle(entry)"
              >
                <Loader2 v-if="pendingReleaseKey === entry.key" class="h-3 w-3 animate-spin" />
                <span v-else>Unblock</span>
              </Button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Emergency Unblock All Confirmation Modal -->
    <Dialog :open="showUnblockAllModal" @update:open="showUnblockAllModal = $event">
      <DialogContent class="sm:max-w-md">
        <DialogHeader>
          <div class="flex items-center gap-2 text-destructive">
            <AlertTriangle class="h-5 w-5" />
            <DialogTitle>Emergency "Unblock All" Confirmation</DialogTitle>
          </div>
          <DialogDescription class="pt-2 text-xs text-muted-foreground">
            Are you sure you want to release all <strong>{{ bans.length }}</strong> active client bans?
            This will immediately evict all banned IPs from local memory, Redis ban sets, and broadcast an unblock notification across all cluster nodes.
          </DialogDescription>
        </DialogHeader>

        <DialogFooter class="gap-2 sm:gap-0">
          <Button variant="outline" size="sm" @click="showUnblockAllModal = false">
            Cancel
          </Button>
          <Button
            variant="destructive"
            size="sm"
            class="gap-1.5"
            :disabled="unblockAllPending"
            @click="handleConfirmUnblockAll"
          >
            <Loader2 v-if="unblockAllPending" class="h-3.5 w-3.5 animate-spin" />
            <Trash2 v-else class="h-3.5 w-3.5" />
            <span>Confirm Emergency Unblock</span>
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
