<script setup lang="ts">
import { AlertCircle, RotateCw, ShieldAlert, Timer } from 'lucide-vue-next';
import type { Incident } from '@/types/telemetry';

/** Aggregated incident cards: one card per client_ip + host 5-minute cluster. */
defineProps<{
  incidents: Incident[];
  loading?: boolean;
  error?: string | null;
}>();

const emit = defineEmits<{
  (e: 'open', incident: Incident): void;
  (e: 'refresh'): void;
}>();

function severityClass(severity: string): string {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'text-threat bg-threat/10 border-threat/30';
    case 'medium':
      return 'text-warning bg-warning/10 border-warning/30';
    default:
      return 'text-info bg-info/10 border-info/30';
  }
}

function spanSeconds(incident: Incident): number {
  const start = new Date(incident.start_time).getTime();
  const end = new Date(incident.end_time).getTime();
  if (Number.isNaN(start) || Number.isNaN(end) || end < start) return 0;
  return Math.round((end - start) / 1000);
}
</script>

<template>
  <div class="flex-1 overflow-auto p-4">
    <div v-if="loading" class="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-3">
      <div
        v-for="index in 6"
        :key="index"
        class="h-32 rounded-lg border border-border bg-muted/30 animate-pulse"
      />
    </div>

    <div v-else-if="error" class="py-12 text-center text-xs font-sans">
      <AlertCircle class="w-7 h-7 mx-auto mb-2 text-threat" />
      <p class="text-foreground font-medium">Failed to load aggregated incidents</p>
      <p class="text-muted-foreground mt-1">{{ error }}</p>
      <button
        type="button"
        data-testid="incidents-retry"
        class="mt-3 inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-muted hover:bg-muted/80 border border-border rounded-lg text-foreground cursor-pointer"
        @click="emit('refresh')"
      >
        <RotateCw class="w-3.5 h-3.5" />
        Retry
      </button>
    </div>

    <div v-else-if="incidents.length === 0" class="py-12 text-center text-xs font-sans">
      <ShieldAlert class="w-7 h-7 mx-auto mb-2 text-muted-foreground/60" />
      <p class="text-foreground font-medium">No incident clusters in this window</p>
      <p class="text-muted-foreground mt-1">Attack bursts are grouped by client IP, host, and 5-minute window.</p>
      <button
        type="button"
        data-testid="incidents-retry"
        class="mt-3 inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-muted hover:bg-muted/80 border border-border rounded-lg text-foreground cursor-pointer"
        @click="emit('refresh')"
      >
        <RotateCw class="w-3.5 h-3.5" />
        Refresh
      </button>
    </div>

    <div v-else data-testid="incident-list" class="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-3">
      <button
        v-for="incident in incidents"
        :key="incident.id"
        type="button"
        data-testid="incident-card"
        class="text-left p-3.5 rounded-lg border border-border bg-card hover:bg-muted/30 transition-colors cursor-pointer font-sans"
        @click="emit('open', incident)"
      >
        <div class="flex items-center justify-between gap-2">
          <span class="font-mono text-xs font-semibold text-foreground truncate">{{ incident.client_ip }}</span>
          <span
            v-if="incident.max_severity"
            class="px-1.5 py-0.5 rounded border text-[10px] font-semibold uppercase tracking-wide"
            :class="severityClass(incident.max_severity)"
          >
            {{ incident.max_severity }}
          </span>
        </div>

        <p class="mt-1 text-[11px] font-mono text-muted-foreground truncate">{{ incident.host }}</p>

        <p class="mt-2 text-xs text-foreground truncate">
          {{ incident.category || incident.top_rule_id || 'Unclassified' }}
        </p>

        <div class="mt-2.5 flex items-center gap-3 text-[11px] text-muted-foreground font-mono tabular-nums">
          <span>{{ incident.total_events }} events</span>
          <span class="text-threat">{{ incident.total_blocked }} blocked</span>
          <span class="inline-flex items-center gap-1">
            <Timer class="w-3 h-3" />
            {{ spanSeconds(incident) }}s
          </span>
        </div>
      </button>
    </div>
  </div>
</template>
