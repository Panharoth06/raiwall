<script setup lang="ts">
import { CheckCircle2, ShieldAlert, AlertTriangle, Ban, Activity } from 'lucide-vue-next';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
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
    <Table container-class="overflow-visible">
      <TableHeader>
        <TableRow>
          <TableHead class="w-32">Time</TableHead>
          <TableHead class="w-28">Action</TableHead>
          <TableHead>Method &amp; Path</TableHead>
          <TableHead class="w-44">Client IP &amp; Geo</TableHead>
          <TableHead class="w-36">Rule / Threat</TableHead>
          <TableHead class="w-24">Latency</TableHead>
          <TableHead class="w-40 text-right">Actions</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody class="font-mono tabular-nums">
        <TableRow
          v-for="ev in events"
          :key="ev.event_id"
          data-testid="event-row"
          class="cursor-pointer"
          @click="emit('inspect', ev)"
        >
          <TableCell class="whitespace-nowrap text-muted-foreground">
            {{ new Date(ev.timestamp).toLocaleTimeString() }}
          </TableCell>
          <TableCell class="whitespace-nowrap">
            <span
              class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold tracking-wide uppercase border"
              :class="getActionBadgeClass(ev.action)"
            >
              <CheckCircle2 v-if="ev.action === 'allow'" class="w-2.5 h-2.5" />
              <ShieldAlert v-else-if="ev.action === 'block'" class="w-2.5 h-2.5" />
              <AlertTriangle v-else-if="ev.action === 'challenge'" class="w-2.5 h-2.5" />
              <Ban v-else-if="ev.action === 'ban'" class="w-2.5 h-2.5" />
              {{ ev.action }}
            </span>
          </TableCell>
          <TableCell class="max-w-xs truncate text-foreground">
            <span class="font-bold text-primary mr-1.5">{{ ev.method }}</span>
            <span :title="ev.path">{{ ev.path }}</span>
          </TableCell>
          <TableCell class="whitespace-nowrap text-foreground">
            <span>{{ ev.client_ip }}</span>
            <span v-if="ev.geo_data?.country" class="ml-1.5 text-muted-foreground text-xs">
              [{{ ev.geo_data.country }}]
            </span>
          </TableCell>
          <TableCell class="whitespace-nowrap">
            <span v-if="ev.rule_id" class="text-warning font-semibold">{{ ev.rule_id }}</span>
            <span v-else class="text-muted-foreground">-</span>
          </TableCell>
          <TableCell class="whitespace-nowrap text-muted-foreground">
            {{ formatLatency(ev.latency) }}
          </TableCell>
          <TableCell class="whitespace-nowrap text-right" @click.stop>
            <button
              v-if="ev.action !== 'allow'"
              type="button"
              data-testid="create-exception-quick-btn"
              class="px-2 py-1 text-xs font-medium text-primary hover:text-primary-foreground bg-primary/10 hover:bg-primary border border-primary/30 rounded transition-all mr-2 cursor-pointer"
              title="Create 1-Click Rule Exception"
              @click="emit('create-exception', ev)"
            >
              Exception
            </button>
            <button
              type="button"
              class="px-2 py-1 text-xs font-medium text-muted-foreground hover:text-foreground bg-muted hover:bg-muted/80 border border-border rounded transition-all cursor-pointer"
              @click="emit('inspect', ev)"
            >
              Inspect
            </button>
          </TableCell>
        </TableRow>

        <TableRow v-if="events.length === 0">
          <TableCell colspan="7" class="h-80 text-center font-sans text-muted-foreground align-top">
            <div class="flex flex-col items-center justify-start pt-10 pb-12 p-8">
              <Activity class="w-8 h-8 mx-auto mb-3 text-muted-foreground/60 opacity-60 animate-pulse" />
              <p class="text-base font-semibold text-foreground">Waiting for incoming telemetry events...</p>
              <p class="text-xs text-muted-foreground mt-1">Events appear automatically via server-sent events</p>
            </div>
          </TableCell>
        </TableRow>
      </TableBody>
    </Table>
  </div>
</template>
