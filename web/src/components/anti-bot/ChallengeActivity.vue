<script setup lang="ts">
import { computed } from 'vue';
import type { ForensicEvent } from '@/types/telemetry';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Activity,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Fingerprint,
  Ghost,
} from 'lucide-vue-next';

const VISIBLE_EVENTS = 12;

const props = defineProps<{
  events: ForensicEvent[];
  challengeTotal: number;
  trapTotal: number;
  spoofTotal: number;
  uniqueJa4: number;
  loading?: boolean;
  error?: string;
}>();

const emit = defineEmits<{
  (e: 'refresh'): void;
}>();

const visibleEvents = computed(() => props.events.slice(0, VISIBLE_EVENTS));
const hiddenCount = computed(() => Math.max(props.events.length - VISIBLE_EVENTS, 0));

const metrics = computed(() => [
  { label: 'Challenges', value: props.challengeTotal, icon: ShieldCheck },
  { label: 'Trap hits', value: props.trapTotal, icon: Ghost },
  { label: 'Spoof blocks', value: props.spoofTotal, icon: ShieldAlert },
  { label: 'Unique JA4', value: props.uniqueJa4, icon: Fingerprint },
]);

const formatTime = (value: string) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toISOString().slice(11, 19);
};

const formatCount = (value: number) => value.toLocaleString('en-US');
</script>

<template>
  <div class="bg-card border border-border rounded-lg min-w-0" data-testid="bot-activity-card">
    <div class="flex items-center justify-between gap-2 px-4 py-3 border-b border-border">
      <div class="flex items-center gap-2 min-w-0">
        <Activity class="w-4 h-4 text-muted-foreground shrink-0" />
        <h2 class="text-sm font-semibold uppercase tracking-wider text-foreground truncate">
          Challenge Activity
        </h2>
        <Badge variant="outline" class="font-mono uppercase text-xs">24h</Badge>
      </div>

      <Button
        variant="ghost"
        size="icon"
        class="h-7 w-7 text-muted-foreground hover:text-foreground"
        title="Refresh activity"
        :disabled="loading"
        data-testid="bot-refresh-activity"
        @click="emit('refresh')"
      >
        <RefreshCw class="w-3.5 h-3.5" :class="{ 'animate-spin': loading }" />
      </Button>
    </div>

    <!-- Metrics -->
    <div class="grid grid-cols-2 gap-px bg-border">
      <div
        v-for="metric in metrics"
        :key="metric.label"
        class="bg-card px-3 py-2.5"
        :data-testid="`bot-metric-${metric.label.toLowerCase().replace(' ', '-')}`"
      >
        <div class="flex items-center gap-1.5 text-xs font-mono uppercase tracking-wider text-muted-foreground">
          <component :is="metric.icon" class="w-3 h-3" />
          <span>{{ metric.label }}</span>
        </div>
        <div class="mt-1 font-mono text-sm font-semibold tabular-nums text-foreground">
          <span v-if="loading" class="inline-block h-4 w-10 bg-muted animate-pulse rounded" />
          <span v-else>{{ formatCount(metric.value) }}</span>
        </div>
      </div>
    </div>

    <!-- Recent challenges -->
    <div class="border-t border-border">
      <div class="flex items-center justify-between px-4 py-2">
        <span class="text-xs font-mono font-semibold uppercase tracking-wider text-muted-foreground">
          Recent challenges
        </span>
        <span class="text-xs font-mono text-muted-foreground tabular-nums">
          {{ formatCount(challengeTotal) }} total
        </span>
      </div>

      <div v-if="loading" class="px-4 pb-3 space-y-2" data-testid="bot-activity-loading">
        <div v-for="i in 3" :key="i" class="h-8 rounded bg-muted/60 animate-pulse" />
      </div>

      <div v-else-if="error" class="px-4 pb-4" data-testid="bot-activity-error">
        <div class="flex items-start gap-2 rounded-md border border-threat/30 bg-threat/10 px-3 py-2 text-xs text-threat">
          <ShieldAlert class="w-3.5 h-3.5 mt-px shrink-0" />
          <div class="min-w-0">
            <p class="font-medium">Activity unavailable</p>
            <p class="font-mono break-all opacity-90">{{ error }}</p>
          </div>
        </div>
        <Button variant="outline" size="sm" class="mt-2 gap-1.5" @click="emit('refresh')">
          <RefreshCw class="w-3.5 h-3.5" />
          <span>Retry</span>
        </Button>
      </div>

      <div v-else-if="visibleEvents.length === 0" class="px-4 pt-6 pb-8 text-center" data-testid="bot-activity-empty">
        <ShieldCheck class="w-8 h-8 text-success mx-auto mb-2" />
        <p class="text-base font-semibold text-foreground">No challenges served in the last 24h</p>
        <p class="mt-1 text-xs text-muted-foreground">
          Browser traffic was not challenged under the current mode.
        </p>
      </div>

      <ul v-else class="divide-y divide-border/60" data-testid="bot-activity-list">
        <li
          v-for="event in visibleEvents"
          :key="event.event_id"
          class="px-4 py-2 flex items-start justify-between gap-3"
        >
          <div class="min-w-0">
            <div class="flex items-center gap-1.5 min-w-0">
              <span class="font-mono text-xs text-foreground">{{ event.client_ip }}</span>
              <span class="font-mono text-xs text-muted-foreground">{{ formatTime(event.timestamp) }}</span>
              <Badge variant="warning" class="font-mono text-xs px-1.5 py-0">{{ event.status_code }}</Badge>
            </div>
            <p class="mt-0.5 truncate font-mono text-xs text-muted-foreground" :title="event.path">
              {{ event.method }} {{ event.path }}
            </p>
          </div>
          <div class="shrink-0 max-w-[120px] text-right">
            <span
              class="block truncate font-mono text-xs text-muted-foreground"
              :title="event.ja4 || 'No TLS fingerprint'"
            >
              {{ event.ja4 || 'no-ja4' }}
            </span>
            <span class="font-mono text-xs text-muted-foreground/70">{{ event.host }}</span>
          </div>
        </li>
        <li v-if="hiddenCount > 0" class="px-4 py-2 text-center">
          <span class="text-xs font-mono text-muted-foreground">
            +{{ hiddenCount }} more in this sample
          </span>
        </li>
      </ul>
    </div>
  </div>
</template>
