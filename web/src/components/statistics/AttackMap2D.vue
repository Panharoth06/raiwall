<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch, nextTick } from 'vue'
import * as echarts from 'echarts/core'
import { LinesChart, EffectScatterChart, MapChart } from 'echarts/charts'
import { GeoComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import * as topojson from 'topojson-client'
import worldAtlas from 'world-atlas/countries-110m.json'
import { useTheme } from '@/composables/useTheme'
import { countryCoords } from './geoData'
import { Button } from '@/components/ui/button'
import { ZoomIn, ZoomOut, RotateCcw, Globe } from 'lucide-vue-next'
import type { TopCount } from '@/types/telemetry'

// Register ECharts core modules
echarts.use([
  LinesChart,
  EffectScatterChart,
  MapChart,
  GeoComponent,
  TooltipComponent,
  CanvasRenderer,
])

// Register world map once
let isMapRegistered = false
function ensureWorldMapRegistered() {
  if (isMapRegistered) return
  try {
    const geojson = topojson.feature(
      worldAtlas as any,
      (worldAtlas as any).objects.countries
    )
    echarts.registerMap('world', geojson as any)
    isMapRegistered = true
  } catch (err) {
    console.error('Failed to register world map in ECharts:', err)
  }
}

const props = withDefaults(
  defineProps<{
    countries: TopCount[]
    selectedCountry?: string
    dataMode?: 'requests' | 'blocked'
    targetGateway?: { name: string; coord: [number, number] }
  }>(),
  {
    dataMode: 'requests',
  }
)

const emit = defineEmits<{
  (e: 'selectCountry', country: string): void
}>()

const chartRef = ref<HTMLDivElement | null>(null)
let chartInstance: echarts.ECharts | null = null
let isInitialized = false
const { isDark } = useTheme()

const DEFAULT_ZOOM = 1.18
const DEFAULT_CENTER: [number, number] = [12, 16]

let currentZoom = DEFAULT_ZOOM
let currentCenter: [number, number] = [...DEFAULT_CENTER]

// Coordinate resolver - strictly uses authentic GeoIP country centroids; zero fake fallbacks
function resolveCoords(countryName: string): [number, number] | null {
  const c = countryCoords[countryName]
  if (c) {
    return [c.lon, c.lat]
  }
  return null
}

function buildSeries(): echarts.SeriesOption[] {
  const isBlocked = props.dataMode === 'blocked'
  const lineColor = isBlocked ? '#f43f5e' : '#06b6d4'
  const series: echarts.SeriesOption[] = []

  // Source Origin Attacker / Traffic Nodes with Pulsing Ripple (ONLY verified countries)
  const sourceNodes = props.countries
    .map((c) => {
      const coord = resolveCoords(c.key)
      if (!coord) return null
      return {
        name: c.key,
        value: [...coord, c.count],
        count: c.count,
      }
    })
    .filter((n): n is { name: string; value: [number, number, number]; count: number } => n !== null)

  if (sourceNodes.length > 0) {
    series.push({
      name: isBlocked ? 'Threat Source' : 'Traffic Source',
      type: 'effectScatter',
      coordinateSystem: 'geo',
      zlevel: 3,
      rippleEffect: {
        period: 3,
        scale: 3.5,
        brushType: 'fill',
      },
      symbolSize: (val: any) => {
        const count = val[2] || 1
        return Math.min(22, Math.max(7, Math.round(Math.log10(count + 1) * 4.5)))
      },
      itemStyle: {
        color: lineColor,
        shadowBlur: 10,
        shadowColor: lineColor,
      },
      data: sourceNodes,
    })
  }

  // Trajectory lines (ONLY rendered if targetGateway is provided AND sourceNodes exist)
  if (props.targetGateway && sourceNodes.length > 0) {
    const attackLines = sourceNodes.map((n) => ({
      fromName: n.name,
      toName: props.targetGateway!.name,
      coords: [[n.value[0], n.value[1]], props.targetGateway!.coord],
      value: n.count,
      country: n.name,
    }))

    series.push({
      name: isBlocked ? 'Attack Trajectory' : 'Traffic Trajectory',
      type: 'lines',
      coordinateSystem: 'geo',
      zlevel: 2,
      effect: {
        show: true,
        period: 3.5,
        trailLength: 0.6,
        symbol: 'arrow',
        symbolSize: 6,
        color: lineColor,
      },
      lineStyle: {
        color: lineColor,
        width: 1.5,
        opacity: 0.45,
        curveness: 0.25,
      },
      data: attackLines,
    })

    series.push({
      name: 'Protected Gateway',
      type: 'effectScatter',
      coordinateSystem: 'geo',
      zlevel: 3,
      rippleEffect: {
        period: 4,
        scale: 4,
        brushType: 'stroke',
      },
      symbolSize: 10,
      itemStyle: {
        color: '#3b82f6',
        shadowBlur: 10,
        shadowColor: '#3b82f6',
      },
      data: [{
        name: props.targetGateway.name,
        value: [...props.targetGateway.coord, 1],
      }],
    })
  }

  return series
}

function updateChart() {
  if (!chartInstance) return

  try {
    const isDarkVal = isDark.value
    const isBlocked = props.dataMode === 'blocked'
    const lineColor = isBlocked ? '#f43f5e' : '#06b6d4'
    const landColor = isDarkVal ? '#181b20' : '#e2e8f0'
    const borderColor = isDarkVal ? '#2d3440' : '#cbd5e1'
    const textColor = isDarkVal ? '#f8fafc' : '#0f172a'

    const series = buildSeries()

    if (!isInitialized) {
      // First initialization: set initial viewport zoom & center
      const initialOption: echarts.EChartsOption = {
        backgroundColor: 'transparent',
        tooltip: {
          trigger: 'item',
          backgroundColor: isDarkVal ? 'rgba(15, 23, 42, 0.92)' : 'rgba(255, 255, 255, 0.95)',
          borderColor: isDarkVal ? '#334155' : '#e2e8f0',
          borderWidth: 1,
          padding: [8, 12],
          textStyle: {
            color: textColor,
            fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
            fontSize: 12,
          },
          formatter: (params: any) => {
            if (params.seriesType === 'lines') {
              return `
                <div style="font-family: ui-monospace, monospace; font-size: 12px;">
                  <div style="font-weight: 700; color: ${lineColor}; display: flex; align-items: center; gap: 6px;">
                    <span>${params.data.fromName}</span>
                    <span>➔</span>
                    <span>${params.data.toName}</span>
                  </div>
                  <div style="margin-top: 4px; color: ${isDarkVal ? '#94a3b8' : '#64748b'};">
                    <span style="font-weight: 700; color: ${textColor};">${params.data.value.toLocaleString()}</span> ${isBlocked ? 'threat blocks' : 'requests'}
                  </div>
                </div>
              `
            }
            if (params.seriesType === 'effectScatter') {
              if (params.seriesName === 'Protected Gateway') {
                return `
                  <div style="font-family: ui-monospace, monospace; font-size: 12px;">
                    <div style="font-weight: 700; color: #3b82f6;">🛡️ Protected WAF Gateway</div>
                    <div style="margin-top: 2px;">${params.data.name}</div>
                  </div>
                `
              }
              return `
                <div style="font-family: ui-monospace, monospace; font-size: 12px;">
                  <div style="font-weight: 700; color: ${lineColor};">${isBlocked ? '⚔️ Threat Origin' : '🌐 Traffic Origin'}: ${params.data.name}</div>
                  <div style="margin-top: 4px; color: ${textColor}; font-weight: 700;">
                    ${params.data.count?.toLocaleString() || ''} events recorded
                  </div>
                </div>
              `
            }
            return ''
          },
        },
        geo: {
          map: 'world',
          roam: true,
          scaleLimit: {
            min: 1,
            max: 12,
          },
          zoom: DEFAULT_ZOOM,
          center: DEFAULT_CENTER,
          aspectScale: 0.75,
          itemStyle: {
            areaColor: landColor,
            borderColor: borderColor,
            borderWidth: 0.75,
          },
          emphasis: {
            itemStyle: {
              areaColor: isDarkVal ? '#1e293b' : '#cbd5e1',
            },
            label: {
              show: false,
            },
          },
        },
        series,
      }

      chartInstance.setOption(initialOption, true)
      isInitialized = true
    } else {
      // Subsequent data updates (polling interval, dataMode, or dark mode toggle):
      // CRITICAL: Do NOT set zoom or center in geo object, and use notMerge = false.
      // ECharts will preserve the user's current zoom and pan coordinates without snapping back!
      chartInstance.setOption(
        {
          geo: {
            itemStyle: {
              areaColor: landColor,
              borderColor: borderColor,
              borderWidth: 0.75,
            },
            emphasis: {
              itemStyle: {
                areaColor: isDarkVal ? '#1e293b' : '#cbd5e1',
              },
            },
          },
          series,
        },
        false
      )
    }
  } catch {
    // Graceful fallback for non-canvas environments
  }
}

function zoomIn() {
  if (!chartInstance) return
  try {
    currentZoom = Math.min(12, currentZoom * 1.3)
    chartInstance.setOption({
      geo: {
        zoom: currentZoom,
      },
    })
  } catch {
    // Graceful fallback
  }
}

function zoomOut() {
  if (!chartInstance) return
  try {
    currentZoom = Math.max(1, currentZoom / 1.3)
    chartInstance.setOption({
      geo: {
        zoom: currentZoom,
      },
    })
  } catch {
    // Graceful fallback
  }
}

function resetZoom() {
  if (!chartInstance) return
  try {
    currentZoom = DEFAULT_ZOOM
    currentCenter = [...DEFAULT_CENTER]
    chartInstance.setOption({
      geo: {
        zoom: DEFAULT_ZOOM,
        center: DEFAULT_CENTER,
      },
    })
  } catch {
    // Graceful fallback
  }
}

function handleResize() {
  if (chartInstance) {
    try {
      chartInstance.resize()
    } catch {
      // Graceful fallback
    }
  }
}

function isCanvasSupported(): boolean {
  if (typeof window === 'undefined' || typeof document === 'undefined') return false
  if (typeof navigator !== 'undefined' && navigator.userAgent && navigator.userAgent.includes('jsdom')) {
    return false
  }
  const testCanvas = document.createElement('canvas')
  try {
    return Boolean(testCanvas.getContext && testCanvas.getContext('2d'))
  } catch {
    return false
  }
}

onMounted(async () => {
  if (!isCanvasSupported()) return

  ensureWorldMapRegistered()
  await nextTick()

  if (chartRef.value) {
    try {
      chartInstance = echarts.init(chartRef.value, null, {
        renderer: 'canvas',
        width: chartRef.value.clientWidth || 440,
        height: chartRef.value.clientHeight || 320,
      })

      // Track user roam events (wheel zoom and drag pan) to preserve position across refreshes
      chartInstance.on('georoam', () => {
        try {
          const opt = chartInstance?.getOption() as any
          if (opt?.geo?.[0]) {
            if (typeof opt.geo[0].zoom === 'number') {
              currentZoom = opt.geo[0].zoom
            }
            if (Array.isArray(opt.geo[0].center)) {
              currentCenter = [opt.geo[0].center[0], opt.geo[0].center[1]]
            }
          }
        } catch {
          // ignore
        }
      })

      chartInstance.on('click', (params: any) => {
        if (params.data && params.data.country) {
          emit('selectCountry', params.data.country)
        } else if (params.data && params.data.name && params.seriesName !== 'Protected Gateway') {
          emit('selectCountry', params.data.name)
        }
      })

      updateChart()
    } catch {
      // Graceful fallback for headless/JSDOM test environments
    }
  }

  window.addEventListener('resize', handleResize)
})

onUnmounted(() => {
  window.removeEventListener('resize', handleResize)
  if (chartInstance) {
    try {
      chartInstance.dispose()
    } catch {
      // Graceful fallback
    }
    chartInstance = null
  }
})

watch(
  [() => props.countries, () => props.dataMode, () => isDark.value, () => props.targetGateway],
  () => {
    updateChart()
  },
  { deep: true }
)
</script>

<template>
  <div class="relative w-full h-[320px] select-none">
    <div
      ref="chartRef"
      data-testid="echarts-attack-map"
      class="w-full h-full rounded-xl overflow-hidden cursor-grab active:cursor-grabbing"
    />

    <!-- Zero Mock / Empty State Overlay when no telemetry events exist -->
    <div
      v-if="props.countries.length === 0"
      class="absolute inset-0 z-10 flex items-center justify-center pointer-events-none p-4"
    >
      <div class="bg-background/85 backdrop-blur-xs border border-border px-4 py-3 rounded-lg shadow-xs text-center pointer-events-auto max-w-[280px]">
        <Globe class="w-6 h-6 text-muted-foreground mx-auto mb-1.5" />
        <p class="text-xs font-semibold text-foreground">No Geo Events Recorded</p>
        <p class="text-xs text-muted-foreground mt-0.5 leading-snug">
          No traffic telemetry captured for this time window.
        </p>
      </div>
    </div>

    <!-- Interactive Zoom / Pan Controls Overlay -->
    <div class="absolute bottom-3 left-3 z-10 flex items-center gap-1 bg-background/85 backdrop-blur-xs p-1 rounded-lg border border-border shadow-xs">
      <Button
        variant="ghost"
        size="icon"
        class="h-7 w-7 text-muted-foreground hover:text-foreground"
        title="Zoom In"
        data-testid="map-zoom-in"
        @click="zoomIn"
      >
        <ZoomIn class="w-3.5 h-3.5" />
      </Button>
      <Button
        variant="ghost"
        size="icon"
        class="h-7 w-7 text-muted-foreground hover:text-foreground"
        title="Zoom Out"
        data-testid="map-zoom-out"
        @click="zoomOut"
      >
        <ZoomOut class="w-3.5 h-3.5" />
      </Button>
      <Button
        variant="ghost"
        size="icon"
        class="h-7 w-7 text-muted-foreground hover:text-foreground"
        title="Reset View"
        data-testid="map-zoom-reset"
        @click="resetZoom"
      >
        <RotateCcw class="w-3.5 h-3.5" />
      </Button>
    </div>
  </div>
</template>
