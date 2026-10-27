<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue';
import { Globe as GlobeIcon, Shield } from 'lucide-vue-next';
import GlobeCdn from '@/components/GlobeCdn.vue';
import type { CdnMarker, CdnArc } from '@/components/cobeDefaults';
import type { ForensicEvent } from '@/types/telemetry';

const props = withDefaults(
  defineProps<{
    events?: ForensicEvent[];
    gatewayLat?: number;
    gatewayLon?: number;
    width?: number;
    height?: number;
  }>(),
  {
    events: () => [],
    gatewayLat: 37.7749,
    gatewayLon: -122.4194,
    width: 600,
    height: 400,
  }
);

interface ThreatArc {
  id: string;
  startLat: number;
  startLon: number;
  endLat: number;
  endLon: number;
  ruleID?: string;
  region: string;
}

const activeArcs = ref<ThreatArc[]>([]);

function addAttackArc(event: ForensicEvent) {
  if (!event.geo_data || event.geo_data.latitude === undefined || event.geo_data.longitude === undefined) {
    return;
  }
  if (event.action === 'allow') return;

  const id = `arc-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;

  activeArcs.value.push({
    id,
    startLat: event.geo_data.latitude,
    startLon: event.geo_data.longitude,
    endLat: props.gatewayLat,
    endLon: props.gatewayLon,
    ruleID: event.rule_id,
    region: event.geo_data.country || 'Threat',
  });

  if (activeArcs.value.length > 25) {
    activeArcs.value.shift();
  }
}

watch(
  () => props.events,
  (newEvents) => {
    if (newEvents && newEvents.length > 0) {
      newEvents.forEach((ev) => addAttackArc(ev));
    }
  },
  { deep: true }
);

onMounted(() => {
  // Pre-populate with sample attack arcs for demonstration
  activeArcs.value.push(
    {
      id: 'demo-1',
      startLat: 39.9042,
      startLon: 116.4074,
      endLat: props.gatewayLat,
      endLon: props.gatewayLon,
      region: 'CN',
      ruleID: 'SQLI_ATTACK',
    },
    {
      id: 'demo-2',
      startLat: 55.7558,
      startLon: 37.6173,
      endLat: props.gatewayLat,
      endLon: props.gatewayLon,
      region: 'RU',
      ruleID: 'RATE_LIMIT_TIER2',
    }
  );
});

const dynamicMarkers = computed<CdnMarker[]>(() => {
  const markers: CdnMarker[] = [
    {
      id: 'gateway',
      location: [props.gatewayLat, props.gatewayLon],
      region: 'GATEWAY',
    },
  ];

  activeArcs.value.forEach((arc) => {
    markers.push({
      id: `m-${arc.id}`,
      location: [arc.startLat, arc.startLon],
      region: arc.region,
    });
  });

  return markers;
});

const dynamicArcs = computed<CdnArc[]>(() => {
  return activeArcs.value.map((arc) => ({
    id: arc.id,
    from: [arc.startLat, arc.startLon],
    to: [arc.endLat, arc.endLon],
    value: Math.floor(Math.random() * 50) + 120,
  }));
});
</script>

<template>
  <div
    data-testid="attack-globe-container"
    class="flex flex-col items-center justify-center p-5 bg-card text-card-foreground rounded-xl border border-border shadow-none relative overflow-hidden font-sans"
  >
    <!-- Header overlay -->
    <div class="absolute top-4 left-5 z-10 flex items-center gap-2">
      <GlobeIcon class="w-4 h-4 text-muted-foreground" />
      <span class="text-xs font-bold uppercase tracking-wider text-foreground">
        3D Attack Globe (Geolocated Threats)
      </span>
    </div>

    <!-- Active Arcs Counter -->
    <div class="absolute top-4 right-5 z-10 flex items-center gap-2 text-xs font-mono text-muted-foreground">
      <span class="w-2 h-2 rounded-full bg-threat animate-ping"></span>
      <span>{{ activeArcs.length }} Active Attack Arcs</span>
    </div>

    <!-- 3D Cobe Globe -->
    <GlobeCdn
      :markers="dynamicMarkers"
      :arcs="dynamicArcs"
      data-test-id="attack-globe-canvas"
      class="w-full max-w-[420px]"
    />

    <!-- Bottom Gateway Tag -->
    <div
      class="absolute bottom-4 z-10 flex items-center gap-3 text-xs font-mono text-muted-foreground bg-muted/80 px-3 py-1 rounded-full border border-border backdrop-blur-md"
    >
      <div class="flex items-center gap-1.5 text-foreground font-semibold">
        <Shield class="w-3.5 h-3.5 text-muted-foreground" />
        Protected Gateway
      </div>
      <span class="text-muted-foreground">|</span>
      <span>Lat: {{ gatewayLat.toFixed(2) }}, Lon: {{ gatewayLon.toFixed(2) }}</span>
    </div>
  </div>
</template>
