<script setup lang="ts">
import { AlertTriangle, AlertCircle } from 'lucide-vue-next'
import type { AggregateStats } from '@/types/telemetry'
import { Card, CardContent } from '@/components/ui/card'

const props = defineProps<{
  stats: AggregateStats
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

function formatRate(rate?: number): string {
  if (rate === undefined || rate === null || isNaN(rate)) return '0.00%'
  return (rate * 100).toFixed(2) + '%'
}
</script>

<template>
  <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
    <!-- 1. 4xx Errors -->
    <Card class="flex flex-col justify-between">
      <CardContent class="p-4 flex flex-col justify-between h-full">
        <div class="flex items-center justify-between text-muted-foreground mb-2">
          <span class="text-xs font-semibold">4xx Errors</span>
          <AlertTriangle class="w-4 h-4 text-warning" />
        </div>
        <div data-testid="metric-4xx-errors" class="text-2xl font-bold font-mono tabular-nums text-foreground">
          {{ formatMetric(stats.status_4xx) }}
        </div>
      </CardContent>
    </Card>

    <!-- 2. Error Rate (4xx) -->
    <Card class="flex flex-col justify-between">
      <CardContent class="p-4 flex flex-col justify-between h-full">
        <div class="flex items-center justify-between text-muted-foreground mb-2">
          <span class="text-xs font-semibold">Error Rate</span>
          <AlertTriangle class="w-4 h-4 text-warning" />
        </div>
        <div data-testid="metric-4xx-rate" class="text-2xl font-bold font-mono tabular-nums text-foreground">
          {{ formatRate(stats.status_4xx_rate) }}
        </div>
      </CardContent>
    </Card>

    <!-- 3. 4xx Blocked -->
    <Card class="flex flex-col justify-between">
      <CardContent class="p-4 flex flex-col justify-between h-full">
        <div class="flex items-center justify-between text-muted-foreground mb-2">
          <span class="text-xs font-semibold">4xx Blocked</span>
          <AlertTriangle class="w-4 h-4 text-threat" />
        </div>
        <div data-testid="metric-4xx-blocked" class="text-2xl font-bold font-mono tabular-nums text-threat">
          {{ formatMetric(stats.status_4xx_blocked) }}
        </div>
      </CardContent>
    </Card>

    <!-- 4. Blocked Rate -->
    <Card class="flex flex-col justify-between">
      <CardContent class="p-4 flex flex-col justify-between h-full">
        <div class="flex items-center justify-between text-muted-foreground mb-2">
          <span class="text-xs font-semibold">Blocked Rate</span>
          <AlertTriangle class="w-4 h-4 text-threat" />
        </div>
        <div data-testid="metric-blocked-rate" class="text-2xl font-bold font-mono tabular-nums text-threat">
          {{ formatRate(stats.status_4xx_blocked_rate) }}
        </div>
      </CardContent>
    </Card>

    <!-- 5. 5xx Errors -->
    <Card class="flex flex-col justify-between">
      <CardContent class="p-4 flex flex-col justify-between h-full">
        <div class="flex items-center justify-between text-muted-foreground mb-2">
          <span class="text-xs font-semibold">5xx Errors</span>
          <AlertCircle class="w-4 h-4 text-threat" />
        </div>
        <div data-testid="metric-5xx-errors" class="text-2xl font-bold font-mono tabular-nums text-foreground">
          {{ formatMetric(stats.status_5xx) }}
        </div>
      </CardContent>
    </Card>

    <!-- 6. Error Rate (5xx) -->
    <Card class="flex flex-col justify-between">
      <CardContent class="p-4 flex flex-col justify-between h-full">
        <div class="flex items-center justify-between text-muted-foreground mb-2">
          <span class="text-xs font-semibold">Error Rate</span>
          <AlertCircle class="w-4 h-4 text-threat" />
        </div>
        <div data-testid="metric-5xx-rate" class="text-2xl font-bold font-mono tabular-nums text-foreground">
          {{ formatRate(stats.status_5xx_rate) }}
        </div>
      </CardContent>
    </Card>
  </div>
</template>
