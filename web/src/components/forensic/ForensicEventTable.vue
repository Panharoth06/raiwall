<script setup lang="ts">
import { CheckCircle2, ShieldAlert, AlertTriangle, Ban, Activity } from 'lucide-vue-next';
import type { ForensicEvent } from '@/types/telemetry';

/** Dense granular forensic log table for live and historical events. */
defineProps<{
  events: ForensicEvent[];
}>();

const emit = defineEmits<{
  (e: 'inspect', event: ForensicEvent): void;
  (e: 'create-exception', event: ForensicEvent): void;
}>();

function getActionBadgeClass(action: string): string {
  switch (action) {
    case 'allow':
      return 'bg-success/10 text-success border-success/30';
    case 'block':
      return 'bg-threat/10 text-threat border-threat/30';
    case 'challenge':
      return 'bg-warning/10 text-warning border-warning/30';
    case 'ban':
      return 'bg-threat/20 text-threat border-threat/40';
    default:
      return 'bg-muted text-muted-foreground border-border';
  }
}

function formatLatency(durNs: number): string {
  const ms = durNs / 1000000;
  return ms < 1 ? `${(ms * 1000).toFixed(0)}µs` : `${ms.toFixed(1)}ms`;
}
</script>

<template>
  <div class="flex-1 overflow-auto">
    <table class="w-full text-left border-collapse text-xs">
      <thead class="sticky top-0 bg-muted/60 text-muted-foreground font-semibold border-b border-border z-10">
        <tr>
          <th class="py-2.5 px-4">Time</th>
          <th class="py-2.5 px-4">Action</th>
          <th class="py-2.5 px-4">Method &amp; Path</th>
          <th class="py-2.5 px-4">Client IP &amp; Geo</th>
          <th class="py-2.5 px-4">Rule / Threat</th>
          <th class="py-2.5 px-4">Latency</th>
          <th class="py-2.5 px-4 text-right">Actions</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-border font-mono">
        <tr
          v-for="ev in events"
          :key="ev.event_id"
          data-testid="event-row"
          class="hover:bg-muted/40 transition-colors cursor-pointer"
          @click="emit('inspect', ev)"
        >
          <td class="py-2.5 px-4 text-muted-foreground whitespace-nowrap">
            {{ new Date(ev.timestamp).toLocaleTimeString() }}
          </td>
          <td class="py-2.5 px-4 whitespace-nowrap">
            <span
              class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold tracking-wide uppercase border"
              :class="getActionBadgeClass(ev.action)"
            >
              <CheckCircle2 v-if="ev.action === 'allow'" class="w-2.5 h-2.5" />
              <ShieldAlert v-else-if="ev.action === 'block'" class="w-2.5 h-2.5" />
              <AlertTriangle v-else-if="ev.action === 'challenge'" class="w-2.5 h-2.5" />
              <Ban v-else-if="ev.action === 'ban'" class="w-2.5 h-2.5" />
              {{ ev.action }}
            </span>
          </td>
          <td class="py-2.5 px-4 max-w-xs truncate text-foreground">
            <span class="font-bold text-primary mr-1.5">{{ ev.method }}</span>
            <span :title="ev.path">{{ ev.path }}</span>
          </td>
          <td class="py-2.5 px-4 whitespace-nowrap text-foreground">
            <span>{{ ev.client_ip }}</span>
            <span v-if="ev.geo_data?.country" class="ml-1.5 text-muted-foreground text-[11px]">
              [{{ ev.geo_data.country }}]
            </span>
          </td>
          <td class="py-2.5 px-4 whitespace-nowrap">
            <span v-if="ev.rule_id" class="text-warning font-semibold">{{ ev.rule_id }}</span>
            <span v-else class="text-muted-foreground">-</span>
          </td>
          <td class="py-2.5 px-4 text-muted-foreground whitespace-nowrap">
            {{ formatLatency(ev.latency) }}
          </td>
          <td class="py-2.5 px-4 text-right whitespace-nowrap" @click.stop>
            <button
              v-if="ev.action !== 'allow'"
              type="button"
              data-testid="create-exception-quick-btn"
              class="px-2 py-1 text-[11px] font-medium text-primary hover:text-primary-foreground bg-primary/10 hover:bg-primary border border-primary/30 rounded transition-all mr-2 cursor-pointer"
              title="Create 1-Click Rule Exception"
              @click="emit('create-exception', ev)"
            >
              Exception
            </button>
            <button
              type="button"
              class="px-2 py-1 text-[11px] font-medium text-muted-foreground hover:text-foreground bg-muted hover:bg-muted/80 border border-border rounded transition-all cursor-pointer"
              @click="emit('inspect', ev)"
            >
              Inspect
            </button>
          </td>
        </tr>

        <tr v-if="events.length === 0">
          <td colspan="7" class="py-12 text-center text-muted-foreground font-sans">
            <Activity class="w-8 h-8 mx-auto mb-2 text-muted-foreground/60 opacity-60 animate-pulse" />
            <p class="text-sm font-medium">Waiting for incoming telemetry events...</p>
            <p class="text-xs text-muted-foreground/80 mt-1">Events appear automatically via server-sent events</p>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
