<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch, computed } from 'vue';
import createGlobe from 'cobe';
import { useTheme } from '@/composables/useTheme';
import { tokenRgb01 } from '@/lib/theme-colors';
import { type CdnMarker, type CdnArc } from './cobeDefaults';

export interface GlobeCdnProps {
  markers?: CdnMarker[];
  arcs?: CdnArc[];
  className?: string;
  speed?: number;
  dataTestId?: string;
}

const props = withDefaults(defineProps<GlobeCdnProps>(), {
  markers: () => [],
  arcs: () => [],
  className: '',
  speed: 0.003,
  dataTestId: 'globe-cdn-canvas',
});

const { isDark } = useTheme();

const canvasRef = ref<HTMLCanvasElement | null>(null);
const containerRef = ref<HTMLDivElement | null>(null);
const pointerInteracting = ref<{ x: number; y: number } | null>(null);
const dragOffset = ref({ phi: 0, theta: 0 });
const phiOffsetRef = ref(0);
const thetaOffsetRef = ref(0);
const isPausedRef = ref(false);

watch(
  () => props.arcs,
  (newArcs) => {
    globe?.update({
      arcs: newArcs.map((a) => ({ from: a.from, to: a.to, id: a.id })),
    });
  },
  { deep: true }
);

watch(
  () => props.markers,
  (newMarkers) => {
    globe?.update({
      markers: newMarkers.map((m) => ({ location: m.location, size: 0.012, id: m.id })),
    });
  },
  { deep: true }
);

let globe: ReturnType<typeof createGlobe> | null = null;
let animationId = 0;
let phi = 0;
let resizeObserver: ResizeObserver | null = null;

function handlePointerDown(e: PointerEvent) {
  pointerInteracting.value = { x: e.clientX, y: e.clientY };
  if (canvasRef.value) canvasRef.value.style.cursor = 'grabbing';
  isPausedRef.value = true;
}

function handlePointerUp() {
  if (pointerInteracting.value !== null) {
    phiOffsetRef.value += dragOffset.value.phi;
    thetaOffsetRef.value += dragOffset.value.theta;
    dragOffset.value = { phi: 0, theta: 0 };
  }
  pointerInteracting.value = null;
  if (canvasRef.value) canvasRef.value.style.cursor = 'grab';
  isPausedRef.value = false;
}

function handlePointerMove(e: PointerEvent) {
  if (pointerInteracting.value !== null) {
    dragOffset.value = {
      phi: (e.clientX - pointerInteracting.value.x) / 300,
      theta: (e.clientY - pointerInteracting.value.y) / 1000,
    };
  }
}

const colorScheme = computed(() => ({
  dark: isDark.value ? 1 : 0,
  baseColor: tokenRgb01('--globe-base'),
  markerColor: tokenRgb01('--globe-marker'),
  glowColor: tokenRgb01('--globe-glow'),
  arcColor: tokenRgb01('--globe-arc'),
}));

function initGlobe() {
  const canvas = canvasRef.value;
  if (!canvas) return;
  if (typeof window === 'undefined' || !('WebGLRenderingContext' in window)) return;

  const width = canvas.offsetWidth || containerRef.value?.offsetWidth || 400;
  if (width === 0 || globe) return;

  try {
    globe = createGlobe(canvas, {
      devicePixelRatio: Math.min(window.devicePixelRatio || 1, 2),
      width,
      height: width,
      phi: 0,
      theta: 0.2,
      dark: colorScheme.value.dark,
      diffuse: 1.5,
      mapSamples: 16000,
      mapBrightness: 10,
      baseColor: colorScheme.value.baseColor,
      markerColor: colorScheme.value.markerColor,
      glowColor: colorScheme.value.glowColor,
      markerElevation: 0.02,
      markers: props.markers.map((m) => ({ location: m.location, size: 0.012, id: m.id })),
      arcs: props.arcs.map((a) => ({ from: a.from, to: a.to, id: a.id })),
      arcColor: colorScheme.value.arcColor,
      arcWidth: 0.5,
      arcHeight: 0.25,
      opacity: 0.7,
    });

    function animate() {
      if (!isPausedRef.value) phi += props.speed;
      globe?.update({
        phi: phi + phiOffsetRef.value + dragOffset.value.phi,
        theta: 0.2 + thetaOffsetRef.value + dragOffset.value.theta,
      });
      animationId = requestAnimationFrame(animate);
    }

    animate();
    setTimeout(() => {
      if (canvasRef.value) canvasRef.value.style.opacity = '1';
    }, 50);
  } catch {
    // Graceful test environment fallback
  }
}

watch(colorScheme, (newScheme) => {
  globe?.update(newScheme);
});

onMounted(() => {
  if (typeof window !== 'undefined') {
    window.addEventListener('pointermove', handlePointerMove, { passive: true });
    window.addEventListener('pointerup', handlePointerUp, { passive: true });
  }

  const canvas = canvasRef.value;
  if (canvas && canvas.offsetWidth > 0) {
    initGlobe();
  } else if (canvas && typeof ResizeObserver !== 'undefined') {
    resizeObserver = new ResizeObserver((entries) => {
      if (entries[0]?.contentRect.width > 0) {
        resizeObserver?.disconnect();
        resizeObserver = null;
        initGlobe();
      }
    });
    resizeObserver.observe(canvas);
  } else {
    initGlobe();
  }
});

onUnmounted(() => {
  if (animationId) cancelAnimationFrame(animationId);
  globe?.destroy();
  resizeObserver?.disconnect();

  if (typeof window !== 'undefined') {
    window.removeEventListener('pointermove', handlePointerMove);
    window.removeEventListener('pointerup', handlePointerUp);
  }
});

function pyramidFaceStyle(nth: number) {
  const transforms = [
    'rotateY(0deg) translateZ(4px) rotateX(19.5deg)',
    'rotateY(120deg) translateZ(4px) rotateX(19.5deg)',
    'rotateY(240deg) translateZ(4px) rotateX(19.5deg)',
    'rotateX(-90deg) rotateZ(60deg) translateY(4px)',
  ];
  const colors = isDark.value
    ? ['hsl(var(--primary))', 'hsl(var(--primary) / 0.85)', 'hsl(var(--primary) / 0.7)', 'hsl(var(--primary) / 0.55)']
    : ['hsl(var(--foreground))', 'hsl(var(--foreground) / 0.8)', 'hsl(var(--foreground) / 0.6)', 'hsl(var(--foreground) / 0.4)'];

  return {
    position: 'absolute' as const,
    left: '-0.5px',
    top: '0px',
    width: '0px',
    height: '0px',
    borderLeft: '6.5px solid transparent',
    borderRight: '6.5px solid transparent',
    borderBottom: `13px solid ${colors[nth]}`,
    transformOrigin: 'center bottom',
    transform: transforms[nth],
  };
}
</script>

<template>
  <div
    ref="containerRef"
    :class="['relative aspect-square select-none flex items-center justify-center overflow-hidden', className]"
  >
    <canvas
      ref="canvasRef"
      :data-testid="dataTestId"
      @pointerdown="handlePointerDown"
      class="w-full h-full cursor-grab opacity-0 rounded-full transition-opacity duration-1000 touch-none block"
    />

    <!-- Anchored Region Markers with 3D Spinning Pyramids -->
    <div
      v-for="m in markers"
      :key="m.id"
      class="cobe-marker-anchor"
      :style="{
        position: 'absolute',
        // @ts-expect-error CSS Anchor Positioning
        positionAnchor: `--cobe-${m.id}`,
        'position-anchor': `--cobe-${m.id}`,
        bottom: 'anchor(top)',
        left: 'anchor(center)',
        translate: '-50% 0',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: '6px',
        pointerEvents: 'none',
        opacity: `var(--cobe-visible-${m.id}, 0)`,
        filter: `blur(calc((1 - var(--cobe-visible-${m.id}, 0)) * 8px))`,
        transition: 'opacity 0.3s, filter 0.3s',
      }"
    >
      <div class="w-3 h-3 relative [transform-style:preserve-3d] animate-[pyramid-spin_4s_linear_infinite]">
        <div v-for="n in [0, 1, 2, 3]" :key="n" :style="pyramidFaceStyle(n)" />
      </div>

      <span
        class="font-mono text-xs text-foreground bg-card border border-border px-1.5 py-0.5 rounded shadow-xs tracking-wider whitespace-nowrap"
      >
        {{ m.region }}
      </span>
    </div>

  </div>
</template>

<style scoped>
@keyframes pyramid-spin {
  0% { transform: rotateX(20deg) rotateY(0deg); }
  100% { transform: rotateX(20deg) rotateY(360deg); }
}
</style>
