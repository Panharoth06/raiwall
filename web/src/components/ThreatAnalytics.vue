<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import {
  TrendingUp,
  ShieldAlert,
  Activity,
  Globe2,
  Server,
  Zap,
} from 'lucide-vue-next';
import type { AggregateStats, ForensicEvent } from '@/types/telemetry';

const props = withDefaults(
  defineProps<{
    stats?: AggregateStats;
    latestEvents?: ForensicEvent[];
    refreshInterval?: number;
  }>(),
  {
    refreshInterval: 10000,
  }
);

const emit = defineEmits<{
  (e: 'refresh'): void;
}>();

const internalStats = ref<AggregateStats>({
  total_requests: 0,
  total_blocked: 0,
  block_ratio: 0,
  time_buckets: [],
  top_countries: [],
  top_rules: [],
  top_ips: [],
});

const activeStats = computed(() => props.stats || internalStats.value);

async function fetchStats() {
  try {
    const res = await fetch('/.raiwall/api/events/stats');
    if (res.ok) {
      const data = await res.json();
      internalStats.value = data;
    }
  } catch {
    // Keep fallback in offline/test environment
  }
}

onMounted(() => {
  if (!props.stats) {
    fetchStats();
  }
});

const blockPercentage = computed(() => {
  return (activeStats.value.block_ratio * 100).toFixed(2);
});

// Max bucket volume for scaling chart bars
const maxBucketVolume = computed(() => {
  let max = 1;
  for (const b of activeStats.value.time_buckets) {
    if (b.total > max) max = b.total;
  }
  return max;
});
</script>

<template>
  <div class="flex flex-col gap-5 p-6 bg-card text-card-foreground rounded-xl border border-border shadow-none font-sans">
    <!-- Header Title & Metric Cards -->
    <div class="flex flex-wrap items-center justify-between gap-4">
      <div>
        <h2 class="text-base font-bold text-foreground tracking-tight flex items-center gap-2">
          <Activity class="w-4 h-4 text-muted-foreground" />
          Threat Intelligence & Traffic Analytics
        </h2>
        <p class="text-xs text-muted-foreground mt-0.5">
          Real-time security telemetry, threat distribution, and origin analytics
        </p>
      </div>
      <button
        type="button"
        data-testid="refresh-stats-btn"
        @click="fetchStats(); emit('refresh')"
        class="px-3 py-1.5 text-xs font-medium text-foreground hover:bg-muted/80 bg-muted border border-border rounded-lg transition-colors flex items-center gap-1.5 shadow-none cursor-pointer"
      >
        <Zap class="w-3.5 h-3.5 text-muted-foreground" />
        <span>Refresh Stats</span>
      </button>
    </div>

    <!-- 4 KPI Summary Cards -->
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
      <!-- Total Requests -->
      <div class="p-4 bg-card border border-border rounded-xl relative overflow-hidden">
        <div class="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1">
          Total Requests
        </div>
        <div data-testid="metric-total-requests" class="text-2xl font-bold font-mono text-foreground">
          {{ activeStats.total_requests.toLocaleString() }}
        </div>
        <div class="text-xs text-muted-foreground mt-1 flex items-center gap-1">
          <span class="text-success font-semibold">Active</span> Gateway Throughput
        </div>
      </div>

      <!-- Blocked Threats -->
      <div class="p-4 bg-card border border-border rounded-xl relative overflow-hidden">
        <div class="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1">
          Threats Blocked
        </div>
        <div data-testid="metric-total-blocked" class="text-2xl font-bold font-mono text-threat">
          {{ activeStats.total_blocked.toLocaleString() }}
        </div>
        <div class="text-xs text-muted-foreground mt-1">
          <span class="text-threat font-semibold">{{ blockPercentage }}%</span> Block Ratio
        </div>
      </div>

      <!-- Top Attacking Country -->
      <div class="p-4 bg-card border border-border rounded-xl relative overflow-hidden">
        <div class="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1">
          Top Threat Origin
        </div>
        <div data-testid="metric-top-country" class="text-2xl font-bold font-mono text-warning truncate">
          {{ activeStats.top_countries[0]?.key || 'N/A' }}
        </div>
        <div class="text-xs text-muted-foreground mt-1">
          {{ activeStats.top_countries[0]?.count.toLocaleString() || '0' }} events
        </div>
      </div>

      <!-- Top Triggered Rule -->
      <div class="p-4 bg-card border border-border rounded-xl relative overflow-hidden">
        <div class="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1">
          Top Block Rule
        </div>
        <div data-testid="metric-top-rule" class="text-lg font-bold font-mono text-primary truncate">
          {{ activeStats.top_rules[0]?.key || 'NONE' }}
        </div>
        <div class="text-xs text-muted-foreground mt-1">
          {{ activeStats.top_rules[0]?.count.toLocaleString() || '0' }} triggers
        </div>
      </div>
    </div>

    <!-- Charts & Analytics Section -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-5">
      <!-- Time-Series Volume & Attack Chart -->
      <div class="lg:col-span-2 p-5 bg-card border border-border rounded-xl flex flex-col justify-between">
        <div class="flex items-center justify-between mb-4">
          <div class="text-sm font-semibold text-foreground uppercase tracking-wider flex items-center gap-1.5">
            <TrendingUp class="w-4 h-4 text-muted-foreground" />
            Traffic & Attack Volume (Time Buckets)
          </div>
          <div class="flex items-center gap-3 text-xs font-mono">
            <span class="flex items-center gap-1 text-muted-foreground">
              <span class="w-2 h-2 rounded-full bg-primary"></span> Total
            </span>
            <span class="flex items-center gap-1 text-muted-foreground">
              <span class="w-2 h-2 rounded-full bg-threat"></span> Blocked
            </span>
          </div>
        </div>

        <!-- Rendered Histogram Bars -->
        <div
          data-testid="time-buckets-chart"
          class="h-44 flex items-end gap-1.5 pt-4 pb-2 border-b border-border overflow-x-auto"
        >
          <div
            v-for="(bucket, idx) in activeStats.time_buckets"
            :key="idx"
            class="flex-1 min-w-[20px] max-w-[40px] flex flex-col justify-end items-center group relative h-full"
          >
            <!-- Hover Tooltip -->
            <div class="absolute bottom-full mb-1 hidden group-hover:flex flex-col bg-popover border border-border text-popover-foreground px-2 py-1 rounded text-xs whitespace-nowrap z-20 shadow-none">
              <span class="font-bold text-foreground">{{ new Date(bucket.bucket).toLocaleTimeString() }}</span>
              <span class="text-primary">Total: {{ bucket.total }}</span>
              <span class="text-threat">Blocked: {{ bucket.block }}</span>
            </div>

            <!-- Total Bar (primary) with Blocked Segment (threat) -->
            <div
              class="w-full rounded-t bg-primary/20 border-t border-primary/50 relative overflow-hidden flex flex-col justify-end transition-all duration-300"
              :style="{ height: `${Math.max(8, (bucket.total / maxBucketVolume) * 100)}%` }"
            >
              <div
                class="w-full bg-threat/70 rounded-t"
                :style="{ height: `${bucket.total > 0 ? (bucket.block / bucket.total) * 100 : 0}%` }"
              />
            </div>
          </div>

          <div
            v-if="activeStats.time_buckets.length === 0"
            class="w-full h-full flex items-center justify-center text-xs text-muted-foreground"
          >
            No time bucket data available in current window
          </div>
        </div>
      </div>

      <!-- Threat Rule Breakdown -->
      <div class="p-5 bg-card border border-border rounded-xl flex flex-col">
        <div class="text-sm font-semibold text-foreground uppercase tracking-wider mb-3 flex items-center gap-1.5">
          <ShieldAlert class="w-4 h-4 text-muted-foreground" />
          Top Threat Rules
        </div>
        <div class="space-y-3 flex-1 overflow-y-auto">
          <div
            v-for="rule in activeStats.top_rules"
            :key="rule.key"
            data-testid="rule-row"
            class="space-y-1"
          >
            <div class="flex justify-between text-xs font-mono">
              <span class="text-foreground font-semibold truncate">{{ rule.key }}</span>
              <span class="text-muted-foreground">{{ rule.count.toLocaleString() }}</span>
            </div>
            <div class="w-full bg-muted rounded-full h-1.5 overflow-hidden">
              <div
                class="bg-gradient-to-r from-threat to-warning h-full rounded-full transition-all duration-500"
                :style="{
                  width: `${activeStats.total_blocked > 0 ? (rule.count / activeStats.total_blocked) * 100 : 0}%`,
                }"
              />
            </div>
          </div>
          <div v-if="activeStats.top_rules.length === 0" class="text-xs text-muted-foreground text-center py-8">
            No threats recorded
          </div>
        </div>
      </div>
    </div>

    <!-- Top Countries & Top IPs Footer Grid -->
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <!-- Top Attacking Countries -->
      <div class="p-4 bg-card border border-border rounded-xl">
        <h3 class="text-base font-semibold text-foreground uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
          <Globe2 class="w-4 h-4 text-muted-foreground" />
          Top Attacking Countries
        </h3>
        <div class="space-y-2">
          <div
            v-for="(c, idx) in activeStats.top_countries.slice(0, 5)"
            :key="c.key"
            class="flex items-center justify-between text-xs font-mono p-1.5 rounded hover:bg-muted/50"
          >
            <span class="flex items-center gap-2">
              <span class="text-muted-foreground text-xs">#{{ idx + 1 }}</span>
              <span class="font-bold text-foreground">{{ c.key }}</span>
            </span>
            <span class="text-muted-foreground">{{ c.count.toLocaleString() }} hits</span>
          </div>
        </div>
      </div>

      <!-- Top Client IPs -->
      <div class="p-4 bg-card border border-border rounded-xl">
        <h3 class="text-base font-semibold text-foreground uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
          <Server class="w-4 h-4 text-muted-foreground" />
          Top Suspicious IPs
        </h3>
        <div class="space-y-2">
          <div
            v-for="(ip, idx) in activeStats.top_ips.slice(0, 5)"
            :key="ip.key"
            class="flex items-center justify-between text-xs font-mono p-1.5 rounded hover:bg-muted/50"
          >
            <span class="flex items-center gap-2">
              <span class="text-muted-foreground text-xs">#{{ idx + 1 }}</span>
              <span class="font-bold text-foreground">{{ ip.key }}</span>
            </span>
            <span class="text-muted-foreground">{{ ip.count.toLocaleString() }} hits</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
