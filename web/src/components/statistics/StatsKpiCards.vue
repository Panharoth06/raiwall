<script setup lang="ts">
import {
  Activity,
  Send,
  Users,
  Globe,
  ShieldAlert,
  Lock,
} from 'lucide-vue-next'
import type { AggregateStats } from '@/types/telemetry'
import { Card, CardContent } from '@/components/ui/card'

const props = defineProps<{
  stats: AggregateStats
  liveQps: number
}>()

function formatMetric(num?: number): string {
  if (num === undefined || num === null) return '0'
  if (num >= 1_000_000) {
    return (num / 1_000_000).toFixed(1) + 'M'
  }
  if (num >= 1_000) {
    return (num / 1_000).toFixed(1) + 'k'
  }
  return num.toLocaleString()
}
</script>

<template>
  <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-7 gap-4">
    <!-- 1. Requests -->
    <Card class="flex flex-col justify-between">
      <CardContent class="p-4 flex flex-col justify-between h-full">
        <div class="flex items-center justify-between text-muted-foreground mb-2">
          <span class="text-xs font-semibold">Requests</span>
          <Activity class="w-4 h-4 text-primary" />
        </div>
        <div data-testid="metric-requests" class="text-2xl font-bold font-mono tabular-nums text-foreground">
          {{ formatMetric(stats.total_requests) }}
        </div>
      </CardContent>
    </Card>

    <!-- 2. Views (PV) -->
    <Card class="flex flex-col justify-between">
      <CardContent class="p-4 flex flex-col justify-between h-full">
        <div class="flex items-center justify-between text-muted-foreground mb-2">
          <span class="text-xs font-semibold">Views (PV)</span>
          <Send class="w-4 h-4 text-info" />
        </div>
        <div data-testid="metric-page-views" class="text-2xl font-bold font-mono tabular-nums text-foreground">
          {{ formatMetric(stats.page_views) }}
        </div>
      </CardContent>
    </Card>

    <!-- 3. Visitors (UV) -->
    <Card class="flex flex-col justify-between">
      <CardContent class="p-4 flex flex-col justify-between h-full">
        <div class="flex items-center justify-between text-muted-foreground mb-2">
          <span class="text-xs font-semibold">Visitors (UV)</span>
          <Users class="w-4 h-4 text-primary" />
        </div>
        <div data-testid="metric-unique-visitors" class="text-2xl font-bold font-mono tabular-nums text-foreground">
          {{ formatMetric(stats.unique_visitors) }}
        </div>
      </CardContent>
    </Card>

    <!-- 4. Unique IP -->
    <Card class="flex flex-col justify-between">
      <CardContent class="p-4 flex flex-col justify-between h-full">
        <div class="flex items-center justify-between text-muted-foreground mb-2">
          <span class="text-xs font-semibold">Unique IP</span>
          <Globe class="w-4 h-4 text-warning" />
        </div>
        <div data-testid="metric-unique-ips" class="text-2xl font-bold font-mono tabular-nums text-foreground">
          {{ formatMetric(stats.unique_ips) }}
        </div>
      </CardContent>
    </Card>

    <!-- 5. Blocked -->
    <Card class="flex flex-col justify-between">
      <CardContent class="p-4 flex flex-col justify-between h-full">
        <div class="flex items-center justify-between text-muted-foreground mb-2">
          <span class="text-xs font-semibold">Blocked</span>
          <ShieldAlert class="w-4 h-4 text-threat" />
        </div>
        <div data-testid="metric-blocked" class="text-2xl font-bold font-mono tabular-nums text-threat">
          {{ formatMetric(stats.total_blocked) }}
        </div>
      </CardContent>
    </Card>

    <!-- 6. IP Addr (Blocked IP) -->
    <Card class="flex flex-col justify-between">
      <CardContent class="p-4 flex flex-col justify-between h-full">
        <div class="flex items-center justify-between text-muted-foreground mb-2">
          <span class="text-xs font-semibold">IP Addr</span>
          <Lock class="w-4 h-4 text-threat" />
        </div>
        <div data-testid="metric-blocked-ips" class="text-2xl font-bold font-mono tabular-nums text-threat">
          {{ stats.blocked_ips ?? 0 }}
        </div>
      </CardContent>
    </Card>

    <!-- 7. Query Per Second (QPS) -->
    <Card class="flex flex-col justify-between col-span-2 sm:col-span-1">
      <CardContent class="p-4 flex flex-col justify-between h-full">
        <div class="flex items-center justify-between text-muted-foreground mb-2">
          <span class="text-xs font-semibold">Query Per Second</span>
          <div class="flex items-center gap-1">
            <span class="w-2 h-2 rounded-full bg-success animate-ping opacity-75" />
            <span class="w-2 h-2 rounded-full bg-success relative" />
          </div>
        </div>
        <div data-testid="metric-live-qps" class="text-2xl font-bold font-mono tabular-nums text-foreground flex items-baseline gap-1">
          <span>{{ liveQps.toFixed(0) }}</span>
          <span class="text-xs font-sans text-muted-foreground font-normal">req/s</span>
        </div>
      </CardContent>
    </Card>
  </div>
</template>
