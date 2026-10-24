<script setup lang="ts">
import { computed } from 'vue';
import {
  Activity,
  Send,
  Users,
  Globe,
  ShieldAlert,
  Lock,
} from 'lucide-vue-next';
import type { AggregateStats } from '@/types/telemetry';

const props = defineProps<{
  stats: AggregateStats;
  liveQps: number;
}>();

function formatMetric(num?: number): string {
  if (num === undefined || num === null) return '0';
  if (num >= 1_000_000) {
    return (num / 1_000_000).toFixed(1) + 'M';
  }
  if (num >= 1_000) {
    return (num / 1_000).toFixed(1) + 'k';
  }
  return num.toLocaleString();
}
</script>

<template>
  <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-7 gap-3">
    <!-- 1. Requests -->
    <div class="p-3.5 bg-card border border-border rounded-xl flex flex-col justify-between">
      <div class="flex items-center justify-between text-muted-foreground mb-2">
        <span class="text-xs font-semibold">Requests</span>
        <Activity class="w-3.5 h-3.5 text-primary" />
      </div>
      <div data-testid="metric-requests" class="text-2xl font-bold font-mono tabular-nums text-foreground">
        {{ formatMetric(stats.total_requests) }}
      </div>
    </div>

    <!-- 2. Views (PV) -->
    <div class="p-3.5 bg-card border border-border rounded-xl flex flex-col justify-between">
      <div class="flex items-center justify-between text-muted-foreground mb-2">
        <span class="text-xs font-semibold">Views (PV)</span>
        <Send class="w-3.5 h-3.5 text-info" />
      </div>
      <div data-testid="metric-page-views" class="text-2xl font-bold font-mono tabular-nums text-foreground">
        {{ formatMetric(stats.page_views) }}
      </div>
    </div>

    <!-- 3. Visitors (UV) -->
    <div class="p-3.5 bg-card border border-border rounded-xl flex flex-col justify-between">
      <div class="flex items-center justify-between text-muted-foreground mb-2">
        <span class="text-xs font-semibold">Visitors (UV)</span>
        <Users class="w-3.5 h-3.5 text-primary" />
      </div>
      <div data-testid="metric-unique-visitors" class="text-2xl font-bold font-mono tabular-nums text-foreground">
        {{ formatMetric(stats.unique_visitors) }}
      </div>
    </div>

    <!-- 4. Unique IP -->
    <div class="p-3.5 bg-card border border-border rounded-xl flex flex-col justify-between">
      <div class="flex items-center justify-between text-muted-foreground mb-2">
        <span class="text-xs font-semibold">Unique IP</span>
        <Globe class="w-3.5 h-3.5 text-warning" />
      </div>
      <div data-testid="metric-unique-ips" class="text-2xl font-bold font-mono tabular-nums text-foreground">
        {{ formatMetric(stats.unique_ips) }}
      </div>
    </div>

    <!-- 5. Blocked -->
    <div class="p-3.5 bg-card border border-border rounded-xl flex flex-col justify-between">
      <div class="flex items-center justify-between text-muted-foreground mb-2">
        <span class="text-xs font-semibold">Blocked</span>
        <ShieldAlert class="w-3.5 h-3.5 text-threat" />
      </div>
      <div data-testid="metric-blocked" class="text-2xl font-bold font-mono tabular-nums text-threat">
        {{ formatMetric(stats.total_blocked) }}
      </div>
    </div>

    <!-- 6. IP Addr (Blocked IP) -->
    <div class="p-3.5 bg-card border border-border rounded-xl flex flex-col justify-between">
      <div class="flex items-center justify-between text-muted-foreground mb-2">
        <span class="text-xs font-semibold">IP Addr</span>
        <Lock class="w-3.5 h-3.5 text-threat" />
      </div>
      <div data-testid="metric-blocked-ips" class="text-2xl font-bold font-mono tabular-nums text-threat">
        {{ stats.blocked_ips ?? 0 }}
      </div>
    </div>

    <!-- 7. Query Per Second (QPS) -->
    <div class="p-3.5 bg-card border border-border rounded-xl flex flex-col justify-between col-span-2 sm:col-span-1">
      <div class="flex items-center justify-between text-muted-foreground mb-2">
        <span class="text-xs font-semibold">Query Per Second</span>
        <div class="flex items-center gap-1">
          <span class="w-2 h-2 rounded-full bg-success animate-ping opacity-75" />
          <span class="w-2 h-2 rounded-full bg-success relative" />
        </div>
      </div>
      <div data-testid="metric-live-qps" class="text-2xl font-bold font-mono tabular-nums text-foreground flex items-baseline gap-1">
        <span>{{ liveQps.toFixed(0) }}</span>
        <span class="text-[11px] font-sans text-muted-foreground font-normal">req/s</span>
      </div>
    </div>
  </div>
</template>
