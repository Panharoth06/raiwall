<script setup lang="ts">
import { computed, ref } from 'vue';
import type { TimeBucketCount } from '@/types/telemetry';

const props = withDefaults(
  defineProps<{
    title: string;
    buckets: TimeBucketCount[];
    variant?: 'requests' | 'blocking';
    height?: number;
  }>(),
  {
    variant: 'requests',
    height: 140,
  }
);

const hoveredIdx = ref<number | null>(null);

const maxVal = computed(() => {
  let m = 0;
  for (const b of props.buckets) {
    const val = props.variant === 'requests' ? b.total : b.block;
    if (val > m) m = val;
  }
  return m;
});

function formatPeak(val: number): string {
  if (val >= 1_000_000) return (val / 1_000_000).toFixed(1) + 'M';
  if (val >= 1_000) return (val / 1_000).toFixed(1) + 'k';
  return val.toLocaleString();
}

interface Point {
  x: number;
  y: number;
  val: number;
  time: string;
}

const points = computed<Point[]>(() => {
  const list = props.buckets;
  if (!list || list.length === 0) return [];
  const w = 320;
  const h = props.height - 20;
  const max = maxVal.value || 1;

  return list.map((b, i) => {
    const x = list.length === 1 ? w / 2 : (i / (list.length - 1)) * w;
    const val = props.variant === 'requests' ? b.total : b.block;
    const y = h - (val / max) * (h - 15) + 10;
    return {
      x,
      y,
      val,
      time: new Date(b.bucket).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };
  });
});

// Build smooth cubic bezier SVG path
const linePath = computed(() => {
  const pts = points.value;
  if (pts.length === 0) return '';
  if (pts.length === 1) return `M ${pts[0].x} ${pts[0].y}`;

  let path = `M ${pts[0].x} ${pts[0].y}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const current = pts[i];
    const next = pts[i + 1];
    const controlX = (current.x + next.x) / 2;
    path += ` C ${controlX} ${current.y}, ${controlX} ${next.y}, ${next.x} ${next.y}`;
  }
  return path;
});

const areaPath = computed(() => {
  if (!linePath.value || points.value.length === 0) return '';
  const pts = points.value;
  const h = props.height;
  const first = pts[0];
  const last = pts[pts.length - 1];
  return `${linePath.value} L ${last.x} ${h} L ${first.x} ${h} Z`;
});

const strokeColor = computed(() => (props.variant === 'blocking' ? '#f43f5e' : '#14b8a6'));
const gradientId = computed(() => `grad-${props.variant}`);
</script>

<template>
  <div class="p-4 bg-card border border-border rounded-xl flex flex-col justify-between">
    <div class="flex items-center justify-between mb-2">
      <h4 class="text-xs font-bold text-foreground">{{ title }}</h4>
      <div class="flex items-center gap-1.5 text-xs font-mono">
        <span class="text-muted-foreground">Max</span>
        <span
          :class="[
            'font-bold tabular-nums',
            variant === 'blocking' ? 'text-threat' : 'text-primary',
          ]"
        >
          {{ formatPeak(maxVal) }}
        </span>
      </div>
    </div>

    <!-- Smooth Area Chart SVG -->
    <div class="relative w-full" :style="{ height: `${height}px` }">
      <svg
        viewBox="0 0 320 140"
        preserveAspectRatio="none"
        class="w-full h-full overflow-visible"
        @mouseleave="hoveredIdx = null"
      >
        <defs>
          <linearGradient :id="gradientId" x1="0" y1="0" x2="0" y2="1">
            <stop
              offset="0%"
              :stop-color="strokeColor"
              :stop-opacity="variant === 'blocking' ? 0.35 : 0.25"
            />
            <stop offset="100%" :stop-color="strokeColor" stop-opacity="0.0" />
          </linearGradient>
        </defs>

        <!-- Area fill -->
        <path v-if="areaPath" :d="areaPath" :fill="`url(#${gradientId})`" />

        <!-- Line stroke -->
        <path
          v-if="linePath"
          :d="linePath"
          fill="none"
          :stroke="strokeColor"
          stroke-width="2"
          stroke-linecap="round"
          stroke-linejoin="round"
        />

        <!-- Hover trigger columns & points -->
        <g v-for="(p, i) in points" :key="i">
          <rect
            :x="Math.max(0, p.x - 10)"
            y="0"
            width="20"
            height="140"
            fill="transparent"
            class="cursor-pointer"
            @mouseenter="hoveredIdx = i"
          />
          <circle
            v-if="hoveredIdx === i"
            :cx="p.x"
            :cy="p.y"
            r="4"
            :fill="strokeColor"
            stroke="#ffffff"
            stroke-width="1.5"
          />
        </g>
      </svg>

      <!-- Hover Tooltip -->
      <div
        v-if="hoveredIdx !== null && points[hoveredIdx]"
        class="absolute -top-7 px-2 py-0.5 rounded bg-popover border border-border text-popover-foreground text-[10px] font-mono shadow-xs pointer-events-none transform -translate-x-1/2 whitespace-nowrap z-20"
        :style="{
          left: `${(points[hoveredIdx].x / 320) * 100}%`,
        }"
      >
        <span class="font-bold">{{ points[hoveredIdx].val.toLocaleString() }}</span>
        <span class="text-muted-foreground ml-1">({{ points[hoveredIdx].time }})</span>
      </div>

      <!-- Empty state -->
      <div
        v-if="points.length === 0"
        class="absolute inset-0 flex items-center justify-center text-xs text-muted-foreground font-mono"
      >
        No telemetry time series recorded
      </div>
    </div>
  </div>
</template>
