<script setup lang="ts">
import { computed, ref } from 'vue'
import type { TimeBucketCount } from '@/types/telemetry'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { EmptyState } from '@/components/ui/empty-state'
import { Activity, ShieldAlert, BarChart3 } from 'lucide-vue-next'

const props = withDefaults(
  defineProps<{
    title: string
    buckets: TimeBucketCount[]
    variant?: 'requests' | 'blocking'
    height?: number
  }>(),
  {
    variant: 'requests',
    height: 140,
  }
)

const hoveredIdx = ref<number | null>(null)

const maxVal = computed(() => {
  let m = 0
  for (const b of props.buckets) {
    const val = props.variant === 'requests' ? b.total : b.block
    if (val > m) m = val
  }
  return m
})

const totalVal = computed(() => {
  return props.buckets.reduce((acc, b) => {
    return acc + (props.variant === 'requests' ? b.total : b.block)
  }, 0)
})

function formatPeak(val: number): string {
  if (val >= 1_000_000) return (val / 1_000_000).toFixed(1) + 'M'
  if (val >= 1_000) return (val / 1_000).toFixed(1) + 'k'
  return val.toLocaleString()
}

interface Point {
  x: number
  y: number
  val: number
  time: string
  rawTime: string
}

const points = computed<Point[]>(() => {
  const list = props.buckets
  if (!list || list.length === 0) return []

  const max = maxVal.value || 1

  return list.map((b, i) => {
    const x = list.length === 1
      ? 50
      : (i / (list.length - 1)) * 100
    const val = props.variant === 'requests' ? b.total : b.block
    // y goes from 6 (top margin) to 94 (bottom baseline)
    const y = 94 - (val / max) * 88

    let timeStr = b.bucket
    try {
      timeStr = new Date(b.bucket).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false })
    } catch {}

    return {
      x,
      y,
      val,
      time: timeStr,
      rawTime: b.bucket,
    }
  })
})

// Build smooth cubic bezier curve through all points
const linePath = computed(() => {
  const pts = points.value
  if (pts.length === 0) return ''
  if (pts.length === 1) return `M ${pts[0].x - 5} ${pts[0].y} L ${pts[0].x + 5} ${pts[0].y}`

  let path = `M ${pts[0].x} ${pts[0].y}`
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = i > 0 ? pts[i - 1] : pts[i]
    const p1 = pts[i]
    const p2 = pts[i + 1]
    const p3 = i < pts.length - 2 ? pts[i + 2] : p2

    const cp1x = p1.x + (p2.x - p0.x) / 6
    const cp1y = p1.y + (p2.y - p0.y) / 6
    const cp2x = p2.x - (p3.x - p1.x) / 6
    const cp2y = p2.y - (p3.y - p1.y) / 6

    path += ` C ${cp1x.toFixed(2)} ${cp1y.toFixed(2)}, ${cp2x.toFixed(2)} ${cp2y.toFixed(2)}, ${p2.x.toFixed(2)} ${p2.y.toFixed(2)}`
  }
  return path
})

const areaPath = computed(() => {
  if (!linePath.value || points.value.length === 0) return ''
  const pts = points.value
  const baseline = 94
  const first = pts[0]
  const last = pts[pts.length - 1]
  return `${linePath.value} L ${last.x} ${baseline} L ${first.x} ${baseline} Z`
})

const strokeColor = computed(() => (props.variant === 'blocking' ? 'hsl(var(--threat))' : 'hsl(var(--primary))'))
const gradientId = computed(() => `grad-trend-${props.variant}`)

const xAxisTicks = computed(() => {
  const pts = points.value
  if (pts.length === 0) return []
  if (pts.length <= 4) return pts

  const step = Math.ceil(pts.length / 4)
  const result: Point[] = []
  for (let i = 0; i < pts.length; i += step) {
    result.push(pts[i])
  }
  if (result[result.length - 1] !== pts[pts.length - 1]) {
    result.push(pts[pts.length - 1])
  }
  return result
})

const hoveredPoint = computed(() => {
  if (hoveredIdx.value !== null && points.value[hoveredIdx.value]) {
    return points.value[hoveredIdx.value]
  }
  return null
})
</script>

<template>
  <Card class="flex flex-col justify-between overflow-hidden">
    <CardHeader class="pb-2">
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-2">
          <div class="w-7 h-7 rounded-md bg-muted text-muted-foreground flex items-center justify-center">
            <ShieldAlert v-if="variant === 'blocking'" class="w-4 h-4 text-threat" />
            <BarChart3 v-else class="w-4 h-4 text-primary" />
          </div>
          <CardTitle class="text-base font-semibold text-foreground">
            {{ title }}
          </CardTitle>
        </div>
        <div class="flex items-center gap-2 text-xs font-mono">
          <span class="text-muted-foreground">Total:</span>
          <span class="font-semibold text-foreground tabular-nums">{{ formatPeak(totalVal) }}</span>
          <Badge
            :variant="variant === 'blocking' ? 'destructive' : 'default'"
            class="text-xs font-mono tabular-nums ml-1"
          >
            Peak {{ formatPeak(maxVal) }}
          </Badge>
        </div>
      </div>
    </CardHeader>

    <CardContent class="pt-1">
      <!-- Empty state: top-aligned -->
      <EmptyState
        v-if="!buckets || buckets.length === 0"
        :icon="Activity"
        title="No telemetry time series recorded"
        description="No traffic or block data detected in this time interval."
        class="py-6 pt-4"
      />

      <!-- High-Precision Area / Line Chart with Crisp HTML Axis Typography -->
      <div v-else class="flex flex-col w-full select-none">
        <!-- Main Plot Area: Y-Axis Column (HTML) + SVG Vector Canvas -->
        <div class="flex items-stretch w-full" :style="{ height: `${Math.max(80, height - 28)}px` }">
          <!-- Y-axis numeric labels: pure HTML, zero SVG aspect ratio distortion -->
          <div class="flex flex-col justify-between items-end pr-3 pb-1 shrink-0 text-xs font-mono text-muted-foreground/80 tabular-nums w-10 sm:w-11 select-none">
            <span class="leading-none">{{ formatPeak(maxVal) }}</span>
            <span class="leading-none opacity-80">{{ formatPeak(Math.round(maxVal / 2)) }}</span>
            <span class="leading-none opacity-60">0</span>
          </div>

          <!-- SVG Plotting Canvas for Grid, Curve, Area & Guide -->
          <div class="relative flex-1 h-full min-w-0" @mouseleave="hoveredIdx = null">
            <svg
              viewBox="0 0 100 100"
              preserveAspectRatio="none"
              class="w-full h-full overflow-visible"
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

              <!-- Grid horizontal reference lines -->
              <line
                x1="0"
                y1="6"
                x2="100"
                y2="6"
                stroke="currentColor"
                class="text-border/30"
                stroke-dasharray="3 3"
                vector-effect="non-scaling-stroke"
              />
              <line
                x1="0"
                y1="50"
                x2="100"
                y2="50"
                stroke="currentColor"
                class="text-border/25"
                stroke-dasharray="3 3"
                vector-effect="non-scaling-stroke"
              />
              <line
                x1="0"
                y1="94"
                x2="100"
                y2="94"
                stroke="currentColor"
                class="text-border/50"
                vector-effect="non-scaling-stroke"
              />

              <!-- Gradient Area Fill -->
              <path v-if="areaPath" :d="areaPath" :fill="`url(#${gradientId})`" />

              <!-- Smooth Spline Stroke Line -->
              <path
                v-if="linePath"
                :d="linePath"
                fill="none"
                :stroke="strokeColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
                vector-effect="non-scaling-stroke"
              />

              <!-- Vertical Tracking Guide Line on hover -->
              <line
                v-if="hoveredPoint"
                :x1="hoveredPoint.x"
                y1="6"
                :x2="hoveredPoint.x"
                y2="94"
                stroke="currentColor"
                class="text-muted-foreground/60"
                stroke-dasharray="2 2"
                vector-effect="non-scaling-stroke"
              />
            </svg>

            <!-- Data Points: Perfectly round HTML dots that never get oval-distorted -->
            <div
              v-for="(p, i) in points"
              :key="`dot-${i}`"
              class="absolute -translate-x-1/2 -translate-y-1/2 rounded-full border-2 transition-all duration-150 pointer-events-none"
              :class="hoveredIdx === i ? 'w-3 h-3 z-20 shadow-sm' : 'w-2 h-2 z-10'"
              :style="{
                left: `${p.x}%`,
                top: `${p.y}%`,
                borderColor: strokeColor,
                backgroundColor: hoveredIdx === i ? 'hsl(var(--background))' : strokeColor,
              }"
            />

            <!-- Hover Target Hit Columns -->
            <div class="absolute inset-0 flex">
              <div
                v-for="(p, i) in points"
                :key="`hit-${i}`"
                class="flex-1 h-full cursor-pointer"
                @mouseenter="hoveredIdx = i"
              />
            </div>

            <!-- Floating Tooltip -->
            <div
              v-if="hoveredPoint"
              class="absolute z-30 pointer-events-none px-2.5 py-1.5 rounded-lg bg-popover border border-border shadow-md text-xs font-mono transition-transform duration-75 whitespace-nowrap"
              :style="{
                left: `${hoveredPoint.x}%`,
                top: `${Math.max(4, hoveredPoint.y - 15)}%`,
                transform: 'translate(-50%, -100%)',
              }"
            >
              <div class="font-bold text-foreground flex items-center gap-1.5">
                <span class="w-2 h-2 rounded-full" :style="{ backgroundColor: strokeColor }" />
                <span>{{ hoveredPoint.val.toLocaleString() }} {{ variant === 'blocking' ? 'blocked' : 'requests' }}</span>
              </div>
              <div class="text-muted-foreground text-xs mt-0.5">
                {{ hoveredPoint.time }}
              </div>
            </div>
          </div>
        </div>

        <!-- X-axis Ticks: HTML row under plotting canvas, aligned with the graph line -->
        <div class="flex items-center justify-between ml-10 sm:ml-11 pt-2 text-xs font-mono text-muted-foreground tabular-nums select-none">
          <span
            v-for="(p, i) in xAxisTicks"
            :key="`tick-${i}`"
            :class="[
              i === 0 ? 'text-left' : i === xAxisTicks.length - 1 ? 'text-right' : 'text-center'
            ]"
          >
            {{ p.time }}
          </span>
        </div>
      </div>
    </CardContent>
  </Card>
</template>
