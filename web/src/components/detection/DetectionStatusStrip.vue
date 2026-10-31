<script setup lang="ts">
import { computed } from 'vue';
import { Badge } from '@/components/ui/badge';
import type { DetectionStatus } from '@/api/detection';
import { ShieldCheck, ShieldAlert, Eye, Cpu, Package, Layers } from 'lucide-vue-next';

const props = defineProps<{
  status: DetectionStatus | null;
  loading?: boolean;
}>();

const modeClass = computed(() => {
  switch (props.status?.detection_mode) {
    case 'block':
      return 'border-success/30 bg-success/10 text-success';
    case 'alert':
      return 'border-warning/30 bg-warning/10 text-warning';
    case 'off':
      return 'border-border bg-muted text-muted-foreground';
    default:
      return 'border-primary/30 bg-primary/10 text-primary';
  }
});

const statusHeadline = computed(() => {
  switch (props.status?.detection_mode) {
    case 'block':
      return 'Active Threat Protection';
    case 'alert':
      return 'Monitoring & Audit Mode';
    case 'off':
      return 'Protection Paused';
    default:
      return 'Standard Protection';
  }
});

const statusSubtext = computed(() => {
  switch (props.status?.detection_mode) {
    case 'block':
      return 'Malicious requests are automatically blocked with HTTP 403 before reaching your servers.';
    case 'alert':
      return 'Threats are logged in real-time telemetry without interrupting any user requests.';
    case 'off':
      return 'WAF inspection is currently paused; all traffic passes through directly.';
    default:
      return 'Traffic is inspected across compiled AST engines, virtual patches, and anomaly scoring.';
  }
});
</script>

<template>
  <div
    v-if="loading"
    class="h-20 rounded-xl bg-muted/50 animate-pulse"
    data-testid="detection-status-loading"
  />
  <div
    v-else
    class="rounded-xl border border-border bg-card p-4 space-y-3 font-sans"
    data-testid="detection-status-strip"
  >
    <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
      <div class="flex items-center gap-3">
        <div
          class="p-2.5 rounded-lg border flex items-center justify-center shrink-0"
          :class="status?.detection_mode === 'block' ? 'bg-success/10 border-success/30 text-success' : status?.detection_mode === 'alert' ? 'bg-warning/10 border-warning/30 text-warning' : 'bg-muted border-border text-muted-foreground'"
        >
          <ShieldCheck v-if="status?.detection_mode === 'block'" class="w-5 h-5" />
          <Eye v-else-if="status?.detection_mode === 'alert'" class="w-5 h-5" />
          <ShieldAlert v-else class="w-5 h-5" />
        </div>
        <div>
          <div class="flex items-center gap-2 flex-wrap">
            <h2 class="text-sm font-semibold text-foreground">
              {{ statusHeadline }}
            </h2>
            <Badge variant="outline" class="font-mono text-xs uppercase" :class="modeClass">
              {{ status?.detection_mode.toUpperCase() || 'UNKNOWN' }}
            </Badge>
            <span
              v-if="status?.crs_enabled && !status?.crs_engine_available"
              class="text-warning text-xs font-mono font-medium"
              data-testid="crs-engine-unavailable"
            >
              · CRS ENGINE OFF
            </span>
          </div>
          <p class="text-xs text-muted-foreground mt-0.5">
            {{ statusSubtext }}
          </p>
        </div>
      </div>

      <div class="flex items-center gap-2 text-xs font-mono tabular-nums text-muted-foreground flex-wrap">
        <span class="px-2.5 py-1 rounded-md bg-muted/40 border border-border">
          Preset: <span class="text-foreground uppercase font-semibold">{{ status?.sensitivity || 'standard' }}</span>
        </span>
      </div>
    </div>

    <!-- Human-Friendly Protection Counters -->
    <div class="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2.5 border-t border-border/70 text-xs">
      <div class="flex items-center gap-2">
        <Cpu class="w-3.5 h-3.5 text-primary shrink-0" />
        <span class="text-muted-foreground">AST Parsers:</span>
        <span class="font-mono font-semibold text-foreground">14 Engines (&lt; 2µs)</span>
      </div>
      <div class="flex items-center gap-2">
        <ShieldCheck class="w-3.5 h-3.5 text-success shrink-0" />
        <span class="text-muted-foreground">Virtual Patches:</span>
        <span class="font-mono font-semibold text-foreground">87 Bundled CVEs</span>
      </div>
      <div class="flex items-center gap-2">
        <Package class="w-3.5 h-3.5 text-info shrink-0" />
        <span class="text-muted-foreground">Rule Packs:</span>
        <span class="font-mono font-semibold text-foreground">{{ status?.rule_packs || 1 }} Active</span>
      </div>
      <div class="flex items-center gap-2">
        <Layers class="w-3.5 h-3.5 text-warning shrink-0" />
        <span class="text-muted-foreground">Exceptions:</span>
        <span class="font-mono font-semibold text-foreground">{{ status?.exceptions || 0 }} Bypasses</span>
      </div>
    </div>
  </div>
</template>
