<script setup lang="ts">
import { ShieldAlert, Terminal, Server, Copy, Check } from 'lucide-vue-next'
import { ref, computed } from 'vue'
import type { TopCount } from '@/types/telemetry'
import { cssToken } from '@/lib/theme-colors'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { EmptyState } from '@/components/ui/empty-state'
import { Button } from '@/components/ui/button'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'

const props = defineProps<{
  categories?: TopCount[]
  rules?: TopCount[]
  ips?: TopCount[]
  totalBlocked: number
}>()

const copiedIp = ref<string | null>(null)
const hoveredRuleIdx = ref<number | null>(null)
const hoveredCatIdx = ref<number | null>(null)

function copyToClipboard(text: string) {
  navigator.clipboard?.writeText(text)
  copiedIp.value = text
  setTimeout(() => {
    if (copiedIp.value === text) copiedIp.value = null
  }, 2000)
}

const donutColors = [1, 2, 3, 4, 5, 6, 7, 8].map((index) => cssToken(`--chart-${index}`))

const totalCategoryBlocks = computed(() => {
  if (props.totalBlocked > 0) return props.totalBlocked
  if (!props.categories || props.categories.length === 0) return 0
  return props.categories.reduce((acc, c) => acc + c.count, 0)
})

const totalRuleTriggers = computed(() => {
  if (!props.rules || props.rules.length === 0) return 0
  return props.rules.reduce((acc, r) => acc + r.count, 0)
})

const totalIpHits = computed(() => {
  if (!props.ips || props.ips.length === 0) return 0
  return props.ips.reduce((acc, ip) => acc + ip.count, 0)
})

// SVG Donut slices geometry for Top Block Rules
interface DonutSlice {
  index: number
  rule: TopCount
  color: string
  percent: number
  dashArray: string
  dashOffset: number
}

const donutSlices = computed<DonutSlice[]>(() => {
  const list = props.rules || []
  const total = totalRuleTriggers.value
  if (total === 0 || list.length === 0) return []

  const radius = 38
  const circumference = 2 * Math.PI * radius
  let accumulatedOffset = 0

  return list.map((rule, idx) => {
    const fraction = rule.count / total
    const strokeLength = fraction * circumference
    const dashOffset = -accumulatedOffset
    accumulatedOffset += strokeLength

    return {
      index: idx,
      rule,
      color: donutColors[idx % donutColors.length],
      percent: fraction * 100,
      dashArray: `${strokeLength.toFixed(2)} ${circumference.toFixed(2)}`,
      dashOffset,
    }
  })
})

const activeHovered = computed(() => {
  if (hoveredRuleIdx.value !== null && donutSlices.value[hoveredRuleIdx.value]) {
    return donutSlices.value[hoveredRuleIdx.value]
  }
  return null
})
</script>

<template>
  <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
    <!-- 1. Top Attack Categories: Horizontal Bar Distribution Chart (4 cols) -->
    <Card class="lg:col-span-4 flex flex-col h-full">
      <CardHeader class="pb-3">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-2">
            <div class="w-7 h-7 rounded-md bg-threat/10 text-threat flex items-center justify-center">
              <ShieldAlert class="w-4 h-4" />
            </div>
            <CardTitle class="text-base font-semibold text-foreground">
              Top Attack Types
            </CardTitle>
          </div>
          <Badge variant="outline" class="text-xs font-mono">
            {{ categories?.length || 0 }} types
          </Badge>
        </div>
      </CardHeader>

      <CardContent class="pt-0 flex-1 flex flex-col">
        <!-- Empty state: top-aligned -->
        <EmptyState
          v-if="!categories || categories.length === 0"
          :icon="ShieldAlert"
          title="No attack categories recorded"
          description="Zero categorized threat events in this observation window."
          class="py-6 pt-4 flex-1"
        />

        <!-- Horizontal Bar Chart -->
        <div v-else class="space-y-3 flex-1 overflow-y-auto max-h-[260px] pr-1">
          <div
            v-for="(cat, idx) in categories"
            :key="cat.key"
            data-testid="attack-category-row"
            class="space-y-1.5 p-2 rounded-lg transition-colors cursor-default"
            :class="hoveredCatIdx === idx ? 'bg-muted/70' : 'hover:bg-muted/40'"
            @mouseenter="hoveredCatIdx = idx"
            @mouseleave="hoveredCatIdx = null"
          >
            <div class="flex justify-between items-center text-xs font-mono">
              <span class="font-semibold text-foreground truncate max-w-[190px]">
                {{ cat.key }}
              </span>
              <div class="flex items-center gap-1.5 shrink-0">
                <span class="text-threat font-semibold tabular-nums">
                  {{ cat.count.toLocaleString() }}
                </span>
                <span class="text-muted-foreground text-xs tabular-nums">
                  ({{ totalCategoryBlocks > 0 ? ((cat.count / totalCategoryBlocks) * 100).toFixed(0) : 0 }}%)
                </span>
              </div>
            </div>

            <!-- Proportional Visual Bar -->
            <div class="w-full bg-muted rounded-full h-2 overflow-hidden">
              <div
                class="bg-gradient-to-r from-threat to-warning h-full rounded-full transition-all duration-300 ease-out"
                :style="{
                  width: `${totalCategoryBlocks > 0 ? Math.min(100, Math.max(4, (cat.count / totalCategoryBlocks) * 100)) : 0}%`,
                }"
              />
            </div>
          </div>
        </div>
      </CardContent>
    </Card>

    <!-- 2. Top Block Rules: Interactive SVG Donut Chart with Side Legend (5 cols) -->
    <Card class="lg:col-span-5 flex flex-col h-full">
      <CardHeader class="pb-3">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-2">
            <div class="w-7 h-7 rounded-md bg-primary/10 text-primary flex items-center justify-center">
              <Terminal class="w-4 h-4" />
            </div>
            <CardTitle class="text-base font-semibold text-foreground">
              Top Block Rules
            </CardTitle>
          </div>
          <Badge variant="outline" class="text-xs font-mono">
            {{ rules?.length || 0 }} rules
          </Badge>
        </div>
      </CardHeader>

      <CardContent class="pt-0 flex-1 flex flex-col">
        <!-- Empty state: top-aligned -->
        <EmptyState
          v-if="!rules || rules.length === 0"
          :icon="Terminal"
          title="No block rules recorded"
          description="Zero security rule trigger events in this timeframe."
          class="py-6 pt-4 flex-1"
        />

        <!-- Donut Chart & Side Legend Grid -->
        <div v-else class="grid grid-cols-1 sm:grid-cols-12 gap-4 items-center flex-1">
          <!-- SVG Donut Chart Canvas -->
          <div class="sm:col-span-5 flex items-center justify-center relative min-h-[170px]">
            <svg viewBox="0 0 100 100" class="w-36 h-36 transform -rotate-90 origin-center overflow-visible">
              <!-- Background ring -->
              <circle
                cx="50"
                cy="50"
                r="38"
                fill="transparent"
                stroke="currentColor"
                class="text-muted/40"
                stroke-width="13"
              />
              <!-- Slices -->
              <circle
                v-for="slice in donutSlices"
                :key="slice.index"
                cx="50"
                cy="50"
                r="38"
                fill="transparent"
                :stroke="slice.color"
                :stroke-dasharray="slice.dashArray"
                :stroke-dashoffset="slice.dashOffset"
                :stroke-width="hoveredRuleIdx === slice.index ? 15 : 13"
                class="transition-all duration-200 cursor-pointer hover:opacity-90"
                @mouseenter="hoveredRuleIdx = slice.index"
                @mouseleave="hoveredRuleIdx = null"
              />
            </svg>

            <!-- Center Metric Readout -->
            <div class="absolute inset-0 flex flex-col items-center justify-center pointer-events-none text-center px-1">
              <span class="text-xs font-mono text-muted-foreground uppercase truncate max-w-[85px]">
                {{ activeHovered ? activeHovered.rule.key : 'Total' }}
              </span>
              <span class="text-sm font-bold font-mono tabular-nums text-foreground mt-0.5">
                {{ activeHovered ? `${activeHovered.percent.toFixed(1)}%` : totalRuleTriggers.toLocaleString() }}
              </span>
              <span v-if="activeHovered" class="text-xs font-mono text-muted-foreground/80 tabular-nums">
                {{ activeHovered.rule.count.toLocaleString() }} hits
              </span>
            </div>
          </div>

          <!-- Side Interactive Legend -->
          <div class="sm:col-span-7 space-y-1.5 max-h-[220px] overflow-y-auto pr-1">
            <div
              v-for="slice in donutSlices"
              :key="slice.index"
              data-testid="block-rule-row"
              :class="[
                'flex items-center justify-between text-xs font-mono p-1.5 rounded-md transition-colors cursor-pointer',
                hoveredRuleIdx === slice.index ? 'bg-muted font-bold' : 'hover:bg-muted/50',
              ]"
              @mouseenter="hoveredRuleIdx = slice.index"
              @mouseleave="hoveredRuleIdx = null"
            >
              <div class="flex items-center gap-2 truncate max-w-[130px]">
                <span
                  class="w-2.5 h-2.5 rounded-full shrink-0"
                  :style="{ backgroundColor: slice.color }"
                />
                <span class="truncate text-foreground text-xs">{{ slice.rule.key }}</span>
              </div>
              <span class="text-muted-foreground text-xs tabular-nums shrink-0">
                {{ slice.rule.count.toLocaleString() }} ({{ slice.percent.toFixed(0) }}%)
              </span>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>

    <!-- 3. Top Suspicious IPs: Ranked Frequency Bar Chart (3 cols) -->
    <Card class="lg:col-span-3 flex flex-col h-full">
      <CardHeader class="pb-3">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-2">
            <div class="w-7 h-7 rounded-md bg-warning/10 text-warning flex items-center justify-center">
              <Server class="w-4 h-4" />
            </div>
            <CardTitle class="text-base font-semibold text-foreground">
              Top Suspicious IPs
            </CardTitle>
          </div>
          <Badge variant="outline" class="text-xs font-mono">
            {{ ips?.length || 0 }} IPs
          </Badge>
        </div>
      </CardHeader>

      <CardContent class="pt-0 flex-1 flex flex-col">
        <!-- Empty state: top-aligned -->
        <EmptyState
          v-if="!ips || ips.length === 0"
          :icon="Server"
          title="No suspicious client IPs recorded"
          description="No offending IP addresses captured in this interval."
          class="py-6 pt-4 flex-1"
        />

        <!-- Ranked Frequency List -->
        <div v-else class="space-y-2.5 flex-1 overflow-y-auto max-h-[260px] pr-1">
          <div
            v-for="(ip, idx) in ips"
            :key="ip.key"
            data-testid="suspicious-ip-row"
            class="p-2 rounded-lg bg-muted/30 hover:bg-muted/60 transition-colors border border-border/50 space-y-1.5"
          >
            <div class="flex items-center justify-between text-xs font-mono">
              <div class="flex items-center gap-1.5 truncate">
                <span class="text-muted-foreground font-semibold">#{{ idx + 1 }}</span>
                <span class="font-bold text-foreground truncate max-w-[105px]">{{ ip.key }}</span>
              </div>
              <div class="flex items-center gap-1.5 shrink-0">
                <span class="text-foreground font-semibold tabular-nums">{{ ip.count.toLocaleString() }}</span>
                <TooltipProvider :delay-duration="150">
                  <Tooltip>
                    <TooltipTrigger as-child>
                      <Button
                        variant="ghost"
                        size="icon"
                        class="h-5 w-5 rounded text-muted-foreground hover:text-foreground shrink-0"
                        @click="copyToClipboard(ip.key)"
                      >
                        <Check v-if="copiedIp === ip.key" class="w-3.5 h-3.5 text-success" />
                        <Copy v-else class="w-3.5 h-3.5" />
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent side="top">
                      <p class="text-xs">Copy IP address</p>
                    </TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              </div>
            </div>

            <!-- Proportional Visual Frequency Bar -->
            <div class="w-full bg-muted rounded-full h-1.5 overflow-hidden">
              <div
                class="bg-warning h-full rounded-full transition-all duration-300 ease-out"
                :style="{
                  width: `${totalIpHits > 0 ? Math.min(100, Math.max(5, (ip.count / totalIpHits) * 100)) : 0}%`,
                }"
              />
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  </div>
</template>
