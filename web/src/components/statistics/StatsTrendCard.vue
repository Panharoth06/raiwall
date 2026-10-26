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

  const paddingLeft = 36
  const paddingRight = 16
  const paddingTop = 16
  const paddingBottom = 28
  const chartWidth = 400 - paddingLeft - paddingRight
  const chartHeight = props.height - paddingTop - paddingBottom
  const max = maxVal.value || 1

  return list.map((b, i) => {
    const x = list.length === 1
      ? paddingLeft + chartWidth / 2
      : paddingLeft + (i / (list.length - 1)) * chartWidth
    const val = props.variant === 'requests' ? b.total : b.block
    const y = paddingTop + chartHeight - (val / max) * chartHeight

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
  if (pts.length === 1) return `M ${pts[0].x - 20} ${pts[0].y} L ${pts[0].x + 20} ${pts[0].y}`

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

    path += ` C ${cp1x.toFixed(1)} ${cp1y.toFixed(1)}, ${cp2x.toFixed(1)} ${cp2y.toFixed(1)}, ${p2.x.toFixed(1)} ${p2.y.toFixed(1)}`
  }
  return path
})

const areaPath = computed(() => {
  if (!linePath.value || points.value.length === 0) return ''
  const pts = points.value
  const baseline = props.height - 28
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

      <!-- High-Precision SVG Area / Line Chart -->
      <div v-else class="relative w-full" :style="{ height: `${height}px` }">
        <svg
          viewBox="0 0 400 140"
          preserveAspectRatio="none"
          class="w-full h-full overflow-visible select-none"
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

          <!-- Grid horizontal dashed reference lines -->
          <line
            x1="36"
            y1="16"
            x2="384"
            y2="16"
            stroke="currentColor"
            class="text-border/30"
            stroke-dasharray="3 3"
          />
          <line
            x1="36"
            y1="64"
            x2="384"
            y2="64"
            stroke="currentColor"
            class="text-border/25"
            stroke-dasharray="3 3"
          />
          <line
            x1="36"
            y1="112"
            x2="384"
            y2="112"
            stroke="currentColor"
            class="text-border/50"
          />

          <!-- Y-axis numeric labels -->
          <text x="30" y="20" text-anchor="end" class="text-[12px] font-mono fill-muted-foreground tabular-nums">
            {{ formatPeak(maxVal) }}
          </text>
          <text x="30" y="68" text-anchor="end" class="text-[12px] font-mono fill-muted-foreground/70 tabular-nums">
            {{ formatPeak(Math.round(maxVal / 2)) }}
          </text>
          <text x="30" y="115" text-anchor="end" class="text-[12px] font-mono fill-muted-foreground/50 tabular-nums">
            0
          </text>

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
          />

          <!-- Vertical Tracking Guide Line on hover -->
          <line
            v-if="hoveredPoint"
            :x1="hoveredPoint.x"
            y1="16"
            :x2="hoveredPoint.x"
            y2="112"
            stroke="currentColor"
            class="text-muted-foreground/60"
            stroke-dasharray="2 2"
          />

          <!-- Data Points -->
          <circle
            v-for="(p, i) in points"
            :key="`pt-${i}`"
            :cx="p.x"
            :cy="p.y"
            :r="hoveredIdx === i ? 5 : 3"
            :fill="strokeColor"
            :stroke="hoveredIdx === i ? 'hsl(var(--background))' : 'transparent'"
            :stroke-width="hoveredIdx === i ? 2 : 0"
            class="transition-all duration-150"
          />

          <!-- X-axis Ticks -->
          <text
            v-for="(p, i) in xAxisTicks"
            :key="`tick-${i}`"
            :x="p.x"
            y="132"
            :text-anchor="i === 0 ? 'start' : i === xAxisTicks.length - 1 ? 'end' : 'middle'"
            class="text-[12px] font-mono fill-muted-foreground tabular-nums"
          >
            {{ p.time }}
          </text>

          <!-- Hover Target Hit Rectangles -->
          <g v-for="(p, i) in points" :key="`hit-${i}`">
            <rect
              :x="Math.max(0, p.x - (points.length > 1 ? 400 / points.length / 2 : 20))"
              y="0"
              :width="points.length > 1 ? 400 / points.length : 40"
              height="140"
              fill="transparent"
              class="cursor-pointer"
              @mouseenter="hoveredIdx = i"
            />
          </g>
        </svg>

        <!-- Floating Tooltip -->
        <div
          v-if="hoveredPoint"
          class="absolute z-30 pointer-events-none px-2.5 py-1.5 rounded-lg bg-popover border border-border shadow-md text-xs font-mono transition-transform duration-75 whitespace-nowrap"
          :style="{
            left: `${(hoveredPoint.x / 400) * 100}%`,
            top: `${Math.max(4, (hoveredPoint.y / 140) * 100 - 34)}%`,
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
    </CardContent>
  </Card>
</template>
