<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed } from 'vue';
import { api, type WaitingRoomMetrics, type PolicySettings } from '@/api/client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { NumberInput } from '@/components/ui/number-input';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import {
  Users,
  Clock,
  TrendingDown,
  RefreshCw,
  Layers,
  ArrowUpRight,
  ShieldCheck,
  AlertCircle,
  Activity,
  Plus,
  X,
} from 'lucide-vue-next';

const props = defineProps<{
  policy: PolicySettings;
}>();

const emit = defineEmits<{
  (e: 'update:policy', val: PolicySettings): void;
}>();

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

const loading = ref(false);
const newPathInput = ref('');
let pollTimer: ReturnType<typeof setInterval> | null = null;

const fetchMetrics = async () => {
  loading.value = true;
  try {
    const data = await api.getWaitingRoomMetrics();
    if (data) {
      metrics.value = data;
    }
  } catch {
    // Gracefully handle offline or unprovisioned waiting room
  } finally {
    loading.value = false;
  }
};

onMounted(() => {
  fetchMetrics();
  pollTimer = setInterval(fetchMetrics, 3000);
});

onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer);
});

const currentPaths = computed(() => props.policy.waiting_room_paths || []);

const addPath = () => {
  const p = newPathInput.value.trim();
  if (!p) return;
  const existing = currentPaths.value;
  if (!existing.includes(p)) {
    emit('update:policy', {
      ...props.policy,
      waiting_room_paths: [...existing, p],
    });
  }
  newPathInput.value = '';
};

const removePath = (idx: number) => {
  const updated = [...currentPaths.value];
  updated.splice(idx, 1);
  emit('update:policy', {
    ...props.policy,
    waiting_room_paths: updated,
  });
};

const toggleWaitingRoom = () => {
  emit('update:policy', {
    ...props.policy,
    waiting_room_enabled: !props.policy.waiting_room_enabled,
  });
};
</script>

<template>
  <div class="space-y-6">
    <!-- Header with Enable/Disable Toggle & Live Refresh -->
    <div class="flex flex-wrap items-center justify-between gap-3 p-4 border border-border rounded-lg bg-card">
      <div class="flex items-center gap-3">
        <div
          class="h-9 w-9 rounded-md border flex items-center justify-center shrink-0"
          :class="policy.waiting_room_enabled ? 'border-primary/40 bg-primary/10 text-primary' : 'border-border bg-muted text-muted-foreground'"
        >
          <Activity class="h-4 w-4" />
        </div>
        <div>
          <div class="flex items-center gap-2">
            <h3 class="text-xs font-semibold uppercase tracking-wider text-foreground">
              Virtual Waiting Room Engine (HTTP 465)
            </h3>
            <span
              class="px-1.5 py-0.5 rounded text-[10px] font-mono font-medium"
              :class="policy.waiting_room_enabled ? 'bg-primary/20 text-primary border border-primary/30' : 'bg-muted text-muted-foreground border border-border'"
            >
              {{ policy.waiting_room_enabled ? 'ACTIVE' : 'DISABLED' }}
            </span>
          </div>
          <p class="text-sm text-muted-foreground mt-1 leading-relaxed">
            Sheds flash crowds and queues surplus traffic with deterministic HTTP 465 responses.
          </p>
        </div>
      </div>

      <div class="flex items-center gap-2.5">
        <div class="flex items-center gap-1.5">
          <label class="text-[11px] text-muted-foreground whitespace-nowrap">Capacity:</label>
          <NumberInput
            :model-value="policy.waiting_room_max_concurrent"
            :min="1"
            suffix="users"
            class="h-8 w-28 text-xs font-mono shadow-none"
            @update:model-value="(val) => emit('update:policy', { ...policy, waiting_room_max_concurrent: val ?? 100 })"
          />
        </div>

        <Button
          variant="outline"
          size="sm"
          class="h-8 gap-1 text-xs"
          @click="fetchMetrics"
        >
          <RefreshCw class="h-3.5 w-3.5" :class="{ 'animate-spin': loading }" />
          <span>Refresh</span>
        </Button>
        <Button
          :variant="policy.waiting_room_enabled ? 'destructive' : 'default'"
          size="sm"
          class="h-8 text-xs font-semibold"
          @click="toggleWaitingRoom"
        >
          {{ policy.waiting_room_enabled ? 'Disable Waiting Room' : 'Enable Waiting Room' }}
        </Button>
      </div>
    </div>

    <!-- Live Telemetry Gauge Cards Grid -->
    <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
      <!-- Active In-Flight -->
      <Card class="bg-card border-border">
        <CardHeader class="p-3 pb-1 flex flex-row items-center justify-between space-y-0">
          <CardTitle class="text-[11px] font-medium text-muted-foreground uppercase">
            Active In-Flight
          </CardTitle>
          <Users class="h-3.5 w-3.5 text-muted-foreground" />
        </CardHeader>
        <CardContent class="p-3 pt-0">
          <div class="text-xl font-bold font-mono tabular-nums text-foreground">
            {{ metrics.active_in_flight }}
            <span class="text-xs font-normal text-muted-foreground">/ {{ policy.waiting_room_max_concurrent }}</span>
          </div>
          <p class="text-xs text-muted-foreground mt-1">Concurrent allowed leases</p>
        </CardContent>
      </Card>

      <!-- Users in Queue -->
      <Card class="bg-card border-border">
        <CardHeader class="p-3 pb-1 flex flex-row items-center justify-between space-y-0">
          <CardTitle class="text-[11px] font-medium text-muted-foreground uppercase">
            Users Waiting
          </CardTitle>
          <Layers class="h-3.5 w-3.5 text-muted-foreground" />
        </CardHeader>
        <CardContent class="p-3 pt-0">
          <div class="text-xl font-bold font-mono tabular-nums text-foreground">
            {{ metrics.total_waiting }}
          </div>
          <p class="text-xs text-muted-foreground mt-1">Peak Depth: {{ metrics.peak_queue_depth }}</p>
        </CardContent>
      </Card>

      <!-- Avg Wait Time -->
      <Card class="bg-card border-border">
        <CardHeader class="p-3 pb-1 flex flex-row items-center justify-between space-y-0">
          <CardTitle class="text-[11px] font-medium text-muted-foreground uppercase">
            Avg Wait Time
          </CardTitle>
          <Clock class="h-3.5 w-3.5 text-muted-foreground" />
        </CardHeader>
        <CardContent class="p-3 pt-0">
          <div class="text-xl font-bold font-mono tabular-nums text-foreground">
            {{ metrics.avg_wait_seconds.toFixed(1) }}s
          </div>
          <p class="text-xs text-muted-foreground mt-1">Total Admitted: {{ metrics.total_admitted }}</p>
        </CardContent>
      </Card>

      <!-- Bounce Rate -->
      <Card class="bg-card border-border">
        <CardHeader class="p-3 pb-1 flex flex-row items-center justify-between space-y-0">
          <CardTitle class="text-[11px] font-medium text-muted-foreground uppercase">
            Client Bounce Rate
          </CardTitle>
          <TrendingDown class="h-3.5 w-3.5 text-muted-foreground" />
        </CardHeader>
        <CardContent class="p-3 pt-0">
          <div class="text-xl font-bold font-mono tabular-nums text-foreground">
            {{ metrics.bounce_rate.toFixed(1) }}%
          </div>
          <p class="text-xs text-muted-foreground mt-1">Abandoned: {{ metrics.total_abandoned }}</p>
        </CardContent>
      </Card>
    </div>

    <!-- Targeted Path Prefixes Settings -->
    <div class="p-4 border border-border rounded-lg bg-card space-y-3">
      <div class="flex items-center justify-between">
        <div>
          <h4 class="text-xs font-semibold text-foreground">Targeted Path Prefixes</h4>
          <p class="text-sm text-muted-foreground mt-1 leading-relaxed">
            Only requests matching these path prefixes will enter the waiting room during flash crowd surges. Leave empty to target all paths.
          </p>
        </div>
      </div>

      <!-- Add Path Row -->
      <div class="flex items-center gap-2 max-w-md">
        <Input
          v-model="newPathInput"
          placeholder="e.g. /tickets/*, /checkout"
          class="h-8 text-xs font-mono"
          @keydown.enter.prevent="addPath"
        />
        <Button variant="outline" size="sm" class="h-8 gap-1 text-xs shrink-0" @click="addPath">
          <Plus class="h-3 w-3" />
          <span>Add Prefix</span>
        </Button>
      </div>

      <!-- Path Badges -->
      <div class="flex flex-wrap gap-1.5 pt-1">
        <span
          v-if="currentPaths.length === 0"
          class="text-xs text-muted-foreground italic"
        >
          All paths targeted by default (/*)
        </span>
        <span
          v-for="(p, idx) in currentPaths"
          :key="idx"
          class="inline-flex items-center gap-1.5 px-2 py-1 rounded bg-muted text-foreground border border-border text-xs font-mono"
        >
          <span>{{ p }}</span>
          <button
            type="button"
            class="text-muted-foreground hover:text-foreground"
            @click="removePath(idx)"
          >
            <X class="h-3 w-3" />
          </button>
        </span>
      </div>
    </div>
  </div>
</template>
