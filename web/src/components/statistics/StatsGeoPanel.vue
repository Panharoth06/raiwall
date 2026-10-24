<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed, watch } from 'vue';
import { Check } from 'lucide-vue-next';
import { Button } from '@/components/ui/button';
import { continents, countryCoords } from './geoData';
import GlobeCdn from '@/components/GlobeCdn.vue';
import { defaultMarkers, defaultArcs, type CdnMarker, type CdnArc } from '@/components/cobeDefaults';
import type { TopCount } from '@/types/telemetry';

const props = defineProps<{
  countries: TopCount[];
  selectedCountry?: string;
  totalRequests: number;
  totalBlocked: number;
}>();

const emit = defineEmits<{
  (e: 'selectCountry', country: string): void;
}>();

const viewMode = ref<'3d' | '2d'>('3d');
const dataMode = ref<'requests' | 'blocked'>('requests');

const canvasRef = ref<HTMLCanvasElement | null>(null);
let animId: number | null = null;

const maxCountryCount = computed(() => {
  let max = 1;
  for (const c of props.countries) {
    if (c.count > max) max = c.count;
  }
  return max;
});

// Dynamic Markers & Arcs generated from real telemetry country hits
const dynamicMarkers = computed<CdnMarker[]>(() => {
  if (!props.countries || props.countries.length === 0) {
    return defaultMarkers;
  }

  const markers: CdnMarker[] = [
    { id: 'cdn-iad', location: [38.95, -77.45], region: 'iad1' },
    { id: 'cdn-sfo', location: [37.62, -122.38], region: 'sfo1' },
  ];

  props.countries.slice(0, 8).forEach((c, idx) => {
    const coord = countryCoords[c.key] || { lat: 20 + (idx % 4) * 10, lon: 10 + idx * 25 };
    const id = `country-${c.key.toLowerCase().replace(/[^a-z0-9]/g, '-')}`;
    const regionName = c.key.length > 8 ? c.key.slice(0, 7) + '.' : c.key;
    markers.push({
      id,
      location: [coord.lat, coord.lon],
      region: regionName,
    });
  });

  return markers;
});

const dynamicArcs = computed<CdnArc[]>(() => {
  if (!props.countries || props.countries.length === 0) {
    return defaultArcs;
  }

  return props.countries.slice(0, 6).map((c, idx) => {
    const coord = countryCoords[c.key] || { lat: 20 + (idx % 4) * 10, lon: 10 + idx * 25 };
    const targetGateway: [number, number] = idx % 2 === 0 ? [38.95, -77.45] : [37.62, -122.38];
    const trafficVal = Math.max(50, Math.round(c.count / 100));

    return {
      id: `arc-${c.key.toLowerCase().replace(/[^a-z0-9]/g, '-')}`,
      from: [coord.lat, coord.lon],
      to: targetGateway,
      value: trafficVal,
    };
  });
});

function project2D(lat: number, lon: number, w: number, h: number) {
  return {
    x: ((lon + 180) / 360) * (w - 40) + 20,
    y: ((90 - lat) / 180) * (h - 40) + 20,
  };
}

function render2D() {
  if (viewMode.value !== '2d') return;
  if (!canvasRef.value) {
    animId = requestAnimationFrame(render2D);
    return;
  }

  const canvas = canvasRef.value;
  let ctx: CanvasRenderingContext2D | null = null;
  try {
    ctx = canvas.getContext('2d');
  } catch {
    return;
  }
  if (!ctx) return;

  const w = canvas.width;
  const h = canvas.height;
  const landmassColor = '#0f766e';
  const landmassBorder = '#115e59';

  ctx.clearRect(0, 0, w, h);

  // 2D World Map Flat Projection
  ctx.fillStyle = 'rgba(204, 251, 241, 0.4)';
  ctx.fillRect(10, 10, w - 20, h - 20);
  ctx.strokeStyle = '#2dd4bf';
  ctx.lineWidth = 1;
  ctx.strokeRect(10, 10, w - 20, h - 20);

  // 2D Continents
  continents.forEach((cont) => {
    ctx.beginPath();
    cont.points.forEach(([lat, lon], idx) => {
      const p = project2D(lat, lon, w, h);
      if (idx === 0) ctx.moveTo(p.x, p.y);
      else ctx.lineTo(p.x, p.y);
    });
    ctx.closePath();
    ctx.fillStyle = landmassColor;
    ctx.fill();
    ctx.strokeStyle = landmassBorder;
    ctx.lineWidth = 1;
    ctx.stroke();
  });

  // 2D Markers
  props.countries.forEach((country) => {
    const coord = countryCoords[country.key] || { lat: 25, lon: 10 };
    const p = project2D(coord.lat, coord.lon, w, h);
    const isSelected = props.selectedCountry === country.key;
    const markerColor = dataMode.value === 'blocked' ? '#f43f5e' : '#047857';

    ctx.beginPath();
    ctx.arc(p.x, p.y, isSelected ? 7 : 4, 0, 2 * Math.PI);
    ctx.fillStyle = isSelected ? '#ffffff' : markerColor;
    ctx.fill();
    ctx.strokeStyle = '#ffffff';
    ctx.lineWidth = 1.2;
    ctx.stroke();
  });

  animId = requestAnimationFrame(render2D);
}

watch(viewMode, (newMode) => {
  if (newMode === '2d') {
    animId = requestAnimationFrame(render2D);
  } else if (animId) {
    cancelAnimationFrame(animId);
    animId = null;
  }
});

onMounted(() => {
  if (viewMode.value === '2d') {
    animId = requestAnimationFrame(render2D);
  }
});

onUnmounted(() => {
  if (animId) cancelAnimationFrame(animId);
});

function formatCount(num: number): string {
  if (num >= 1_000_000) return (num / 1_000_000).toFixed(1) + 'M';
  if (num >= 1_000) return (num / 1_000).toFixed(1) + 'k';
  return num.toLocaleString();
}
</script>

<template>
  <div class="p-5 bg-card border border-border rounded-xl flex flex-col justify-between">
    <!-- Header with Toggles -->
    <div class="flex flex-wrap items-center justify-between gap-3 mb-4">
      <h3 class="text-sm font-bold text-foreground tracking-tight">Geo Location</h3>

      <div class="flex items-center gap-2">
        <!-- 3D / 2D Toggle -->
        <div class="flex items-center p-0.5 bg-muted rounded-lg border border-border text-xs font-mono">
          <Button
            type="button"
            size="sm"
            data-testid="toggle-3d"
            :variant="viewMode === '3d' ? 'secondary' : 'ghost'"
            class="h-6 px-2 text-xs font-mono shadow-none"
            @click="viewMode = '3d'"
          >
            3D
          </Button>
          <Button
            type="button"
            size="sm"
            data-testid="toggle-2d"
            :variant="viewMode === '2d' ? 'secondary' : 'ghost'"
            class="h-6 px-2 text-xs font-mono shadow-none"
            @click="viewMode = '2d'"
          >
            2D
          </Button>
        </div>

        <!-- Requests / Blocked Toggle -->
        <div class="flex items-center p-0.5 bg-muted rounded-lg border border-border text-xs font-mono">
          <Button
            type="button"
            size="sm"
            data-testid="toggle-requests-mode"
            :variant="dataMode === 'requests' ? 'default' : 'ghost'"
            class="h-6 px-2.5 text-xs font-mono shadow-none"
            @click="dataMode = 'requests'"
          >
            REQUESTS
          </Button>
          <Button
            type="button"
            size="sm"
            data-testid="toggle-blocked-mode"
            :variant="dataMode === 'blocked' ? 'destructive' : 'ghost'"
            class="h-6 px-2.5 text-xs font-mono shadow-none"
            @click="dataMode = 'blocked'"
          >
            BLOCKED
          </Button>
        </div>
      </div>
    </div>

    <!-- Main Content: Canvas Globe (Left) + Country Leaderboard (Right) -->
    <div class="grid grid-cols-1 md:grid-cols-12 gap-5 items-center">
      <div class="md:col-span-7 flex items-center justify-center relative min-h-[320px]">
        <!-- 3D Dynamic Cobe Globe -->
        <GlobeCdn
          v-if="viewMode === '3d'"
          :markers="dynamicMarkers"
          :arcs="dynamicArcs"
          class="w-full max-w-[340px] aspect-square"
        />

        <!-- 2D World Map Flat View -->
        <canvas
          v-else
          ref="canvasRef"
          width="440"
          height="320"
          class="max-w-full h-auto rounded-xl"
        />
      </div>

      <!-- Country Distribution List -->
      <div class="md:col-span-5 space-y-2.5 max-h-[320px] overflow-y-auto pr-1">
        <div
          v-for="(country, idx) in countries"
          :key="country.key"
          data-testid="country-row"
          @click="emit('selectCountry', country.key)"
          :class="[
            'p-2 rounded-lg border transition-all cursor-pointer flex flex-col gap-1.5',
            selectedCountry === country.key
              ? 'bg-primary/10 border-primary/40 text-foreground'
              : 'bg-muted/30 border-transparent hover:border-border hover:bg-muted/60',
          ]"
        >
          <div class="flex items-center justify-between text-xs font-mono">
            <span class="flex items-center gap-1.5 font-semibold">
              <span class="text-muted-foreground text-xs">#{{ idx + 1 }}</span>
              <span class="truncate max-w-[120px]">{{ country.key }}</span>
              <Check v-if="selectedCountry === country.key" class="w-3 h-3 text-primary ml-1" />
            </span>
            <span class="font-bold tabular-nums">
              {{ formatCount(country.count) }}
            </span>
          </div>
          <div class="w-full bg-muted rounded-full h-1.5 overflow-hidden">
            <div
              :class="[
                'h-full rounded-full transition-all duration-300',
                dataMode === 'blocked' ? 'bg-threat' : 'bg-primary',
              ]"
              :style="{ width: `${Math.min(100, Math.max(4, (country.count / maxCountryCount) * 100))}%` }"
            />
          </div>
        </div>

        <div v-if="countries.length === 0" class="text-center py-10 text-xs text-muted-foreground font-mono">
          No geo distribution events recorded
        </div>
      </div>
    </div>
  </div>
</template>
