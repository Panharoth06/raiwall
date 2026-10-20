<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch } from 'vue';
import { Globe as GlobeIcon, Shield, Activity } from 'lucide-vue-next';
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

const canvasRef = ref<HTMLCanvasElement | null>(null);
const containerRef = ref<HTMLElement | null>(null);
const isVisible = ref(true);
let animationFrameId: number | null = null;
let rotation = 0;

interface Arc {
  startLat: number;
  startLon: number;
  endLat: number;
  endLon: number;
  progress: number;
  color: string;
  ruleID?: string;
}

const activeArcs = ref<Arc[]>([]);

function addAttackArc(event: ForensicEvent) {
  if (!event.geo_data || event.geo_data.latitude === undefined || event.geo_data.longitude === undefined) {
    return;
  }

  // Only animate threat attacks (blocks, bans, challenges)
  if (event.action === 'allow') return;

  const color = event.action === 'ban' ? '#c084fc' : event.action === 'challenge' ? '#fbbf24' : '#f43f5e';

  activeArcs.value.push({
    startLat: event.geo_data.latitude,
    startLon: event.geo_data.longitude,
    endLat: props.gatewayLat,
    endLon: props.gatewayLon,
    progress: 0,
    color,
    ruleID: event.rule_id,
  });

  // Cap active arcs at 25 to protect rendering performance
  if (activeArcs.value.length > 25) {
    activeArcs.value.shift();
  }
}

watch(
  () => props.events,
  (newEvents) => {
    if (newEvents && newEvents.length > 0) {
      addAttackArc(newEvents[0]);
    }
  },
  { deep: true }
);

function project(lat: number, lon: number, radius: number, rot: number) {
  const radLat = (lat * Math.PI) / 180;
  const radLon = ((lon + rot) * Math.PI) / 180;

  const x = radius * Math.cos(radLat) * Math.sin(radLon);
  const y = -radius * Math.sin(radLat);
  const z = radius * Math.cos(radLat) * Math.cos(radLon);

  return { x, y, z };
}

function renderGlobe() {
  if (!canvasRef.value || !isVisible.value) {
    animationFrameId = requestAnimationFrame(renderGlobe);
    return;
  }
  const canvas = canvasRef.value;

  let ctx: CanvasRenderingContext2D | null = null;
  try {
    ctx = canvas.getContext('2d');
  } catch {
    // jsdom test environment without native canvas
    return;
  }
  if (!ctx) return;

  const w = canvas.width;
  const h = canvas.height;
  const cx = w / 2;
  const cy = h / 2;
  const radius = Math.min(w, h) * 0.38;

  ctx.clearRect(0, 0, w, h);

  rotation = (rotation + 0.3) % 360;

  // 1. Draw Globe Base Atmosphere
  const grad = ctx.createRadialGradient(cx - radius * 0.2, cy - radius * 0.2, radius * 0.1, cx, cy, radius);
  grad.addColorStop(0, '#121824');
  grad.addColorStop(0.8, '#0d1117');
  grad.addColorStop(1, '#080a0f');

  ctx.beginPath();
  ctx.arc(cx, cy, radius, 0, 2 * Math.PI);
  ctx.fillStyle = grad;
  ctx.fill();
  ctx.strokeStyle = '#1e293b';
  ctx.lineWidth = 1.5;
  ctx.stroke();

  // 2. Latitude & Longitude grid lines
  ctx.strokeStyle = 'rgba(34, 211, 238, 0.08)';
  ctx.lineWidth = 0.8;
  for (let lat = -60; lat <= 60; lat += 30) {
    ctx.beginPath();
    for (let lon = 0; lon <= 360; lon += 10) {
      const p = project(lat, lon, radius, rotation);
      if (p.z > 0) {
        if (lon === 0) ctx.moveTo(cx + p.x, cy + p.y);
        else ctx.lineTo(cx + p.x, cy + p.y);
      }
    }
    ctx.stroke();
  }

  // 3. Draw Gateway Location Node
  const gw = project(props.gatewayLat, props.gatewayLon, radius, rotation);
  if (gw.z > 0) {
    ctx.beginPath();
    ctx.arc(cx + gw.x, cy + gw.y, 4, 0, 2 * Math.PI);
    ctx.fillStyle = '#22d3ee';
    ctx.shadowColor = '#22d3ee';
    ctx.shadowBlur = 10;
    ctx.fill();
    ctx.shadowBlur = 0;
  }

  // 4. Draw Animated Attack Arcs
  for (let i = activeArcs.value.length - 1; i >= 0; i--) {
    const arc = activeArcs.value[i];
    arc.progress += 0.02;

    const curLat = arc.startLat + (arc.endLat - arc.startLat) * Math.min(1, arc.progress);
    const curLon = arc.startLon + (arc.endLon - arc.startLon) * Math.min(1, arc.progress);

    // Altitude arc calculation
    const altBoost = Math.sin(arc.progress * Math.PI) * 25;
    const p1 = project(arc.startLat, arc.startLon, radius, rotation);
    const pCur = project(curLat, curLon, radius + altBoost, rotation);

    if (p1.z > -10 && pCur.z > -10) {
      ctx.beginPath();
      ctx.moveTo(cx + p1.x, cy + p1.y);
      ctx.lineTo(cx + pCur.x, cy + pCur.y);
      ctx.strokeStyle = arc.color;
      ctx.lineWidth = 2;
      ctx.shadowColor = arc.color;
      ctx.shadowBlur = 6;
      ctx.stroke();
      ctx.shadowBlur = 0;
    }

    if (arc.progress >= 1) {
      activeArcs.value.splice(i, 1);
    }
  }

  animationFrameId = requestAnimationFrame(renderGlobe);
}

let observer: IntersectionObserver | null = null;

onMounted(() => {
  // Respect browser tab visibility
  const onVisibilityChange = () => {
    isVisible.value = document.visibilityState === 'visible';
  };
  document.addEventListener('visibilitychange', onVisibilityChange);

  // IntersectionObserver for off-screen container throttling
  if (containerRef.value && 'IntersectionObserver' in window) {
    observer = new IntersectionObserver(([entry]) => {
      isVisible.value = entry.isIntersecting && document.visibilityState === 'visible';
    });
    observer.observe(containerRef.value);
  }

  // Pre-populate with sample attack arcs for demonstration
  activeArcs.value.push(
    { startLat: 39.9042, startLon: 116.4074, endLat: props.gatewayLat, endLon: props.gatewayLon, progress: 0.2, color: '#f43f5e' },
    { startLat: 55.7558, startLon: 37.6173, endLat: props.gatewayLat, endLon: props.gatewayLon, progress: 0.5, color: '#c084fc' }
  );

  renderGlobe();
});

onUnmounted(() => {
  if (animationFrameId !== null) {
    cancelAnimationFrame(animationFrameId);
  }
  if (observer) {
    observer.disconnect();
  }
});
</script>

<template>
  <div
    ref="containerRef"
    data-testid="attack-globe-container"
    class="flex flex-col items-center justify-center p-5 bg-[#0d0f14] text-zinc-100 rounded-xl border border-zinc-800 shadow-2xl relative overflow-hidden font-sans"
  >
    <!-- Header overlay -->
    <div class="absolute top-4 left-5 z-10 flex items-center gap-2">
      <GlobeIcon class="w-4 h-4 text-slate-400" />
      <span class="text-xs font-bold uppercase tracking-wider text-zinc-200">
        3D Attack Globe (Geolocated Threats)
      </span>
    </div>

    <!-- Active Arcs Counter -->
    <div class="absolute top-4 right-5 z-10 flex items-center gap-2 text-xs font-mono text-zinc-400">
      <span class="w-2 h-2 rounded-full bg-rose-500 animate-ping"></span>
      <span>{{ activeArcs.length }} Active Attack Arcs</span>
    </div>

    <!-- 3D Canvas -->
    <canvas
      ref="canvasRef"
      data-testid="attack-globe-canvas"
      :width="width"
      :height="height"
      class="max-w-full h-auto"
    />

    <!-- Bottom Gateway Tag -->
    <div class="absolute bottom-4 z-10 flex items-center gap-3 text-[11px] font-mono text-zinc-400 bg-zinc-900/80 px-3 py-1 rounded-full border border-zinc-800 backdrop-blur-md">
      <div class="flex items-center gap-1.5 text-slate-300 font-semibold">
        <Shield class="w-3.5 h-3.5 text-slate-400" />
        Protected Gateway
      </div>
      <span class="text-zinc-600">|</span>
      <span>Lat: {{ gatewayLat.toFixed(2) }}, Lon: {{ gatewayLon.toFixed(2) }}</span>
    </div>
  </div>
</template>
