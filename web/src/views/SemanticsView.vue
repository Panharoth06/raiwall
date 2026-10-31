<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { semanticsApi, type DetectorModule, type ModuleMode } from '@/api/semantics';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import SemanticsModeSegment from '@/components/SemanticsModeSegment.vue';
import SemanticsAppOverrides from '@/components/SemanticsAppOverrides.vue';
import DetectionHeroBanner from '@/components/detection/DetectionHeroBanner.vue';
import { useHeroBanner } from '@/components/detection/useHeroBanner';
import DetectionPageHeader from '@/components/detection/DetectionPageHeader.vue';
import DetectionStatRow from '@/components/detection/DetectionStatRow.vue';
import { Activity, HelpCircle, RefreshCw, RotateCcw, Sparkles } from 'lucide-vue-next';

const { showHero, toggleHero, dismissHero } = useHeroBanner('detection-semantics');
const modules = ref<DetectorModule[]>([]);
const loading = ref(true);
const resetting = ref(false);
const error = ref('');
const dirtyModules = ref<Set<string>>(new Set());
const activeCategory = ref('all');

const loadMatrix = async () => {
  loading.value = true;
  error.value = '';
  try {
    const matrix = await semanticsApi.getMatrix();
    modules.value = matrix.modules;
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to load semantic matrix';
  } finally {
    loading.value = false;
  }
};

const resetAllToBalanced = async () => {
  resetting.value = true;
  error.value = '';
  try {
    for (const m of modules.value) {
      if (m.mode !== 'balance') {
        m.mode = 'balance';
        await semanticsApi.setModuleMode(m.module, 'balance');
      }
    }
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to reset modules';
  } finally {
    resetting.value = false;
  }
};

const handleModeChange = async (module: DetectorModule, mode: ModuleMode) => {
  const previous = module.mode;
  // Optimistic swap; revert on failure so the grid never lies.
  module.mode = mode;
  dirtyModules.value.add(module.module);
  try {
    await semanticsApi.setModuleMode(module.module, mode);
  } catch (e) {
    module.mode = previous;
    dirtyModules.value.delete(module.module);
    error.value = e instanceof Error ? e.message : 'Mode change failed';
  }
};

const categories = computed(() => {
  const set = new Set<string>();
  for (const m of modules.value) {
    if (m.category) set.add(m.category);
  }
  return Array.from(set);
});

const filteredModules = computed(() => {
  if (activeCategory.value === 'all') return modules.value;
  return modules.value.filter((m) => m.category === activeCategory.value);
});

const strictCount = computed(() => modules.value.filter((m) => m.mode === 'strict').length);
const balanceCount = computed(() => modules.value.filter((m) => m.mode === 'balance').length);
const auditCount = computed(() => modules.value.filter((m) => m.mode === 'audit').length);

type StatItem = {
  label: string;
  value: string | number;
  hint?: string;
  tone?: 'default' | 'threat' | 'success' | 'warning' | 'muted';
};

const statItems = computed<StatItem[]>(() => [
  { label: 'Modules', value: modules.value.length, hint: 'bounded parsers' },
  { label: 'Strict', value: strictCount.value, tone: 'threat', hint: 'hard block' },
  { label: 'Balanced', value: balanceCount.value, tone: 'success', hint: 'lexical + AST' },
  { label: 'Audit', value: auditCount.value, tone: 'warning', hint: 'telemetry only' },
]);

onMounted(loadMatrix);
</script>

<template>
  <div class="space-y-4 font-sans">
    <DetectionPageHeader
      title="Semantic Detection Matrix"
      description="Pure-Go AST triage funnel (< 2µs). Set global operating modes; per-site overrides apply below."
      :icon="Activity"
    >
      <template #actions>
        <Button
          size="sm"
          variant="outline"
          class="h-8 text-xs gap-1.5"
          :data-testid="'hero-toggle-semantics'"
          @click="toggleHero"
        >
          <HelpCircle class="w-3.5 h-3.5 text-primary" />
          <span>{{ showHero ? 'Hide Guide' : 'Explain feature' }}</span>
        </Button>
        <Button
          size="sm"
          variant="outline"
          class="h-8 text-xs gap-1.5"
          :disabled="loading || resetting"
          @click="resetAllToBalanced"
        >
          <RotateCcw class="w-3.5 h-3.5" :class="resetting ? 'animate-spin' : ''" />
          <span>Reset to Balanced</span>
        </Button>
        <Button
          size="sm"
          variant="outline"
          class="h-8 text-xs gap-1.5"
          :disabled="loading || resetting"
          @click="loadMatrix"
        >
          <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
          <span>Refresh</span>
        </Button>
      </template>
    </DetectionPageHeader>

    <!-- Prominent Hero Section with Low-Opacity Background Icon -->
    <DetectionHeroBanner
      storage-key="detection-semantics"
      title="Semantic Detection Matrix & AST Parsers"
      badge="SEMANTIC AST ENGINES"
      description="Traditional regex firewalls trigger false alarms on innocent apostrophes or symbols. Raiwall parses HTTP parameters into real Abstract Syntax Trees (TiDB SQL parser, mvdan Shell parser, and tdewolff HTML/JS). Every parameter is evaluated in < 2µs with a hard 32 KB cap and 5 ms timeout. The default Balanced Defense preset tunes all 14 modules automatically."
      :icon="Activity"
      :highlights="[
        { label: 'Grammar Context Aware', text: 'Distinguishes between valid text comments and executable SQL/XSS tokens.' },
        { label: '< 2µs Lexical Triage', text: 'Pure-Go coraza/libinjection triage filters benign traffic before AST parsing.' },
        { label: 'Zero GC Pauses', text: 'Uses sync.Pool buffer pools to maintain sub-millisecond p99 latency.' },
      ]"
      v-model:open="showHero"
      @dismiss="dismissHero"
    />

    <div
      v-if="error"
      class="flex items-center justify-between gap-3 rounded-md border border-threat/30 bg-threat/10 px-3 py-2 text-xs text-threat"
      data-testid="matrix-error"
    >
      <span class="truncate">{{ error }}</span>
      <Button size="sm" variant="outline" class="h-7 text-xs shrink-0" @click="loadMatrix">
        Retry
      </Button>
    </div>

    <DetectionStatRow :items="statItems" />

    <div v-if="loading" class="space-y-2" data-testid="matrix-loading">
      <div v-for="n in 5" :key="n" class="h-9 rounded-md bg-muted/50 animate-pulse" />
    </div>

    <div v-else class="space-y-3">
      <div class="flex items-center gap-1.5 flex-wrap">
        <Button
          size="sm"
          variant="ghost"
          class="h-7 px-2.5 text-xs font-mono"
          :class="activeCategory === 'all' ? 'bg-primary/10 text-primary' : 'text-muted-foreground'"
          data-testid="matrix-filter-all"
          @click="activeCategory = 'all'"
        >
          all ({{ modules.length }})
        </Button>
        <Button
          v-for="cat in categories"
          :key="cat"
          size="sm"
          variant="ghost"
          class="h-7 px-2.5 text-xs font-mono"
          :class="activeCategory === cat ? 'bg-primary/10 text-primary' : 'text-muted-foreground'"
          :data-testid="`matrix-filter-${cat}`"
          @click="activeCategory = cat"
        >
          {{ cat }} ({{ modules.filter((m) => m.category === cat).length }})
        </Button>
      </div>

      <div class="max-h-[50vh] overflow-auto rounded-lg border border-border bg-card">
        <Table data-testid="module-matrix" container-class="overflow-visible">
          <TableHeader class="sticky top-0 z-10 bg-muted/95 backdrop-blur-sm border-b border-border">
            <TableRow>
              <TableHead class="text-xs uppercase font-semibold">Engine Module</TableHead>
              <TableHead class="w-28 text-xs uppercase font-semibold">Category</TableHead>
              <TableHead class="text-xs uppercase font-semibold">Parser Behavior & Specification</TableHead>
              <TableHead class="w-72 text-xs uppercase font-semibold">Operating Mode</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow
              v-for="module in filteredModules"
              :key="module.module"
              :data-testid="`module-row-${module.module}`"
            >
              <TableCell class="font-medium">
                <span class="font-mono text-xs text-foreground font-semibold">{{ module.name }}</span>
                <span v-if="dirtyModules.has(module.module)" class="text-warning ml-1">●</span>
              </TableCell>
              <TableCell>
                <Badge variant="outline" class="font-mono text-xs tracking-normal text-muted-foreground">
                  {{ module.category }}
                </Badge>
              </TableCell>
              <TableCell class="max-w-md text-muted-foreground text-xs">
                <TooltipProvider :delay-duration="150">
                  <Tooltip>
                    <TooltipTrigger as-child>
                      <span class="block truncate cursor-default">{{ module.description }}</span>
                    </TooltipTrigger>
                    <TooltipContent side="top" class="max-w-sm">
                      <p class="text-xs">{{ module.description }}</p>
                    </TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              </TableCell>
              <TableCell>
                <SemanticsModeSegment
                  :model-value="module.mode"
                  @update:model-value="(mode) => handleModeChange(module, mode as ModuleMode)"
                />
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </div>
    </div>

    <SemanticsAppOverrides :modules="modules" />
  </div>
</template>
