<script setup lang="ts">
import { ShieldAlert, Terminal, Server, Copy, Check } from 'lucide-vue-next';
import { ref, computed } from 'vue';
import type { TopCount } from '@/types/telemetry';

const props = defineProps<{
  categories?: TopCount[];
  rules?: TopCount[];
  ips?: TopCount[];
  totalBlocked: number;
}>();

const copiedIp = ref<string | null>(null);
const hoveredRuleIdx = ref<number | null>(null);

function copyToClipboard(text: string) {
  navigator.clipboard?.writeText(text);
  copiedIp.value = text;
  setTimeout(() => {
    if (copiedIp.value === text) copiedIp.value = null;
  }, 2000);
}

const donutColors = [
  '#14b8a6', // teal
  '#06b6d4', // cyan
  '#6366f1', // indigo
  '#a855f7', // purple
  '#f43f5e', // rose/threat
  '#f59e0b', // amber
  '#10b981', // emerald
  '#ec4899', // pink
];

const totalRuleTriggers = computed(() => {
  if (!props.rules || props.rules.length === 0) return 0;
  return props.rules.reduce((acc, r) => acc + r.count, 0);
});

// SVG Donut slices geometry
interface DonutSlice {
  index: number;
  rule: TopCount;
  color: string;
  percent: number;
  dashArray: string;
  dashOffset: number;
}

const donutSlices = computed<DonutSlice[]>(() => {
  const list = props.rules || [];
  const total = totalRuleTriggers.value;
  if (total === 0 || list.length === 0) return [];

  const circumference = 2 * Math.PI * 40; // r = 40
  let accumulatedOffset = 0;

  return list.map((rule, idx) => {
    const fraction = rule.count / total;
    const strokeLength = fraction * circumference;
    const dashOffset = -accumulatedOffset;
    accumulatedOffset += strokeLength;

    return {
      index: idx,
      rule,
      color: donutColors[idx % donutColors.length],
      percent: fraction * 100,
      dashArray: `${strokeLength} ${circumference}`,
      dashOffset,
    };
  });
});

const activeHovered = computed(() => {
  if (hoveredRuleIdx.value !== null && donutSlices.value[hoveredRuleIdx.value]) {
    return donutSlices.value[hoveredRuleIdx.value];
  }
  return null;
});
</script>

<template>
  <div class="grid grid-cols-1 md:grid-cols-12 gap-4">
    <!-- 1. Top Attack Categories (4 cols) -->
    <div class="md:col-span-4 p-4 bg-card border border-border rounded-xl flex flex-col justify-between">
      <div class="flex items-center justify-between mb-3">
        <h4 class="text-xs font-bold text-foreground flex items-center gap-1.5 uppercase tracking-wider">
          <ShieldAlert class="w-3.5 h-3.5 text-threat" />
          <span>Top Attack Types</span>
        </h4>
        <span class="text-[10px] font-mono text-muted-foreground">{{ categories?.length || 0 }} categories</span>
      </div>

      <div class="space-y-2.5 flex-1 overflow-y-auto max-h-[220px]">
        <div
          v-for="cat in categories"
          :key="cat.key"
          data-testid="attack-category-row"
          class="space-y-1 text-xs font-mono"
        >
          <div class="flex justify-between items-center">
            <span class="font-semibold text-foreground truncate max-w-[170px]">{{ cat.key }}</span>
            <span class="text-muted-foreground tabular-nums">{{ cat.count.toLocaleString() }}</span>
          </div>
          <div class="w-full bg-muted rounded-full h-1.5 overflow-hidden">
            <div
              class="bg-gradient-to-r from-threat to-warning h-full rounded-full transition-all duration-300"
              :style="{
                width: `${totalBlocked > 0 ? Math.min(100, Math.max(5, (cat.count / totalBlocked) * 100)) : 0}%`,
              }"
            />
          </div>
        </div>

        <div v-if="!categories || categories.length === 0" class="text-center py-8 text-xs text-muted-foreground font-mono">
          No classified attack categories recorded
        </div>
      </div>
    </div>

    <!-- 2. Top Block Rules: Donut Chart & Legend (5 cols) -->
    <div class="md:col-span-5 p-4 bg-card border border-border rounded-xl flex flex-col justify-between">
      <div class="flex items-center justify-between mb-2">
        <h4 class="text-xs font-bold text-foreground flex items-center gap-1.5 uppercase tracking-wider">
          <Terminal class="w-3.5 h-3.5 text-primary" />
          <span>Top Block Rules</span>
        </h4>
        <span class="text-[10px] font-mono text-muted-foreground">{{ rules?.length || 0 }} rules</span>
      </div>

      <!-- Donut Chart & Side Legend Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-12 gap-3 items-center flex-1">
        <!-- SVG Donut Chart Canvas -->
        <div class="sm:col-span-6 flex items-center justify-center relative min-h-[160px]">
          <svg viewBox="0 0 100 100" class="w-36 h-36 transform -rotate-90">
            <!-- Background base circle -->
            <circle
              cx="50"
              cy="50"
              r="40"
              fill="transparent"
              stroke="currentColor"
              class="text-muted/40"
              stroke-width="14"
            />
            <!-- Slices -->
            <circle
              v-for="slice in donutSlices"
              :key="slice.index"
              cx="50"
              cy="50"
              r="40"
              fill="transparent"
              :stroke="slice.color"
              :stroke-dasharray="slice.dashArray"
              :stroke-dashoffset="slice.dashOffset"
              stroke-width="14"
              class="transition-all duration-200 cursor-pointer hover:opacity-90"
              @mouseenter="hoveredRuleIdx = slice.index"
              @mouseleave="hoveredRuleIdx = null"
            />
          </svg>

          <!-- Center Text Overlay -->
          <div class="absolute inset-0 flex flex-col items-center justify-center pointer-events-none text-center">
            <span class="text-[10px] font-mono text-muted-foreground uppercase">
              {{ activeHovered ? activeHovered.rule.key.slice(0, 10) : 'Total' }}
            </span>
            <span class="text-sm font-bold font-mono tabular-nums text-foreground">
              {{ activeHovered ? `${activeHovered.percent.toFixed(1)}%` : totalRuleTriggers.toLocaleString() }}
            </span>
          </div>
        </div>

        <!-- Legend List -->
        <div class="sm:col-span-6 space-y-1.5 max-h-[160px] overflow-y-auto pr-1">
          <div
            v-for="slice in donutSlices"
            :key="slice.index"
            data-testid="block-rule-row"
            :class="[
              'flex items-center justify-between text-xs font-mono p-1 rounded transition-colors cursor-pointer',
              hoveredRuleIdx === slice.index ? 'bg-muted font-bold' : 'hover:bg-muted/50',
            ]"
            @mouseenter="hoveredRuleIdx = slice.index"
            @mouseleave="hoveredRuleIdx = null"
          >
            <div class="flex items-center gap-1.5 truncate max-w-[120px]">
              <span
                class="w-2.5 h-2.5 rounded-full shrink-0"
                :style="{ backgroundColor: slice.color }"
              />
              <span class="truncate text-foreground text-[11px]">{{ slice.rule.key }}</span>
            </div>
            <span class="text-muted-foreground text-[10px] tabular-nums">
              {{ slice.rule.count }} ({{ slice.percent.toFixed(0) }}%)
            </span>
          </div>

          <div v-if="donutSlices.length === 0" class="text-center py-6 text-xs text-muted-foreground font-mono">
            No rules recorded
          </div>
        </div>
      </div>
    </div>

    <!-- 3. Top Suspicious IPs (3 cols) -->
    <div class="md:col-span-3 p-4 bg-card border border-border rounded-xl flex flex-col justify-between">
      <div class="flex items-center justify-between mb-3">
        <h4 class="text-xs font-bold text-foreground flex items-center gap-1.5 uppercase tracking-wider">
          <Server class="w-3.5 h-3.5 text-warning" />
          <span>Top Suspicious IPs</span>
        </h4>
        <span class="text-[10px] font-mono text-muted-foreground">{{ ips?.length || 0 }} IPs</span>
      </div>

      <div class="space-y-2 flex-1 overflow-y-auto max-h-[220px]">
        <div
          v-for="(ip, idx) in ips"
          :key="ip.key"
          data-testid="suspicious-ip-row"
          class="flex items-center justify-between text-xs font-mono p-1.5 rounded-lg bg-muted/40 hover:bg-muted/70 transition-colors"
        >
          <div class="flex items-center gap-2 truncate">
            <span class="text-muted-foreground text-[10px]">#{{ idx + 1 }}</span>
            <span class="font-bold text-foreground truncate">{{ ip.key }}</span>
          </div>
          <div class="flex items-center gap-2">
            <span class="text-muted-foreground tabular-nums">{{ ip.count.toLocaleString() }}</span>
            <button
              type="button"
              @click="copyToClipboard(ip.key)"
              title="Copy IP address"
              class="p-1 rounded hover:bg-background text-muted-foreground hover:text-foreground cursor-pointer"
            >
              <Check v-if="copiedIp === ip.key" class="w-3 h-3 text-success" />
              <Copy v-else class="w-3 h-3" />
            </button>
          </div>
        </div>

        <div v-if="!ips || ips.length === 0" class="text-center py-8 text-xs text-muted-foreground font-mono">
          No suspicious client IPs recorded
        </div>
      </div>
    </div>
  </div>
</template>
