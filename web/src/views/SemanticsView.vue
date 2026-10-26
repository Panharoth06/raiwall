<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { semanticsApi, type DetectorModule, type ModuleMode } from '@/api/semantics';
import { Badge } from '@/components/ui/badge';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
import SemanticsModeSegment from '@/components/SemanticsModeSegment.vue';
import SemanticsAppOverrides from '@/components/SemanticsAppOverrides.vue';
import { Activity } from 'lucide-vue-next';

const modules = ref<DetectorModule[]>([]);
const loading = ref(true);
const error = ref('');
const dirtyModules = ref<Set<string>>(new Set());

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

onMounted(loadMatrix);
</script>

<template>
  <div class="h-full flex flex-col space-y-6 p-6 bg-card text-card-foreground rounded-xl border border-border font-sans overflow-hidden">
    <!-- Header -->
    <div class="flex items-center justify-between shrink-0">
      <div>
        <h1 class="text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
          <Activity class="w-5 h-5 text-muted-foreground" />
          <span>Semantic Detection Matrix</span>
        </h1>
        <p class="text-sm text-muted-foreground mt-1">
          {{ modules.length }}-module triage funnel — set global operating modes; per-site overrides below
        </p>
      </div>
      <Badge variant="outline" class="font-mono text-xs tracking-normal" data-testid="staged-note">
        Applies as staged draft → POST /config/apply
      </Badge>
    </div>

    <p v-if="error" class="text-xs text-destructive shrink-0" data-testid="matrix-error">{{ error }}</p>

    <!-- Skeleton -->
    <div v-if="loading" class="space-y-2 shrink-0" data-testid="matrix-loading">
      <div v-for="n in 5" :key="n" class="h-9 rounded-md bg-muted/50 animate-pulse" />
    </div>

    <!-- Global matrix -->
    <div v-else class="max-h-[52%] shrink-0 overflow-y-auto rounded-lg border border-border bg-card">
      <Table data-testid="module-matrix" container-class="overflow-visible">
        <TableHeader>
          <TableRow>
            <TableHead>Module</TableHead>
            <TableHead class="w-28">Category</TableHead>
            <TableHead>Behavior</TableHead>
            <TableHead class="w-72">Mode</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow
            v-for="module in modules"
            :key="module.module"
            :data-testid="`module-row-${module.module}`"
          >
            <TableCell class="font-medium">
              <span class="font-mono text-xs text-foreground">{{ module.name }}</span>
              <span v-if="dirtyModules.has(module.module)" class="text-warning ml-1">●</span>
            </TableCell>
            <TableCell>
              <Badge variant="secondary" class="font-mono text-xs tracking-normal">{{ module.category }}</Badge>
            </TableCell>
            <TableCell class="max-w-md truncate text-muted-foreground" :title="module.description">
              {{ module.description }}
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

    <!-- Per-site overrides -->
    <SemanticsAppOverrides :modules="modules" class="grow min-h-0" />
  </div>
</template>
