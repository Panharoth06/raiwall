<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { semanticsApi, type DetectorModule, type ModuleMode } from '@/api/semantics';
import { Badge } from '@/components/ui/badge';
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
  <div class="h-full flex flex-col space-y-4 p-6 bg-card text-card-foreground rounded-xl border border-border font-sans overflow-hidden">
    <!-- Header -->
    <div class="flex items-center justify-between shrink-0">
      <div>
        <h1 class="text-sm font-semibold uppercase tracking-wider text-foreground flex items-center gap-2">
          <Activity class="w-4 h-4 text-muted-foreground" />
          <span>Semantic Detection Matrix</span>
        </h1>
        <p class="text-xs text-muted-foreground mt-0.5">
          {{ modules.length }}-module triage funnel — set global operating modes; per-site overrides below
        </p>
      </div>
      <Badge variant="outline" class="font-mono text-[10px] tracking-normal" data-testid="staged-note">
        Applies as staged draft → POST /config/apply
      </Badge>
    </div>

    <p v-if="error" class="text-xs text-destructive shrink-0" data-testid="matrix-error">{{ error }}</p>

    <!-- Skeleton -->
    <div v-if="loading" class="space-y-2 shrink-0" data-testid="matrix-loading">
      <div v-for="n in 5" :key="n" class="h-9 rounded-md bg-muted/50 animate-pulse" />
    </div>

    <!-- Global matrix -->
    <div v-else class="overflow-y-auto border border-border rounded-lg shrink-0 max-h-[52%]">
      <table class="w-full text-xs" data-testid="module-matrix">
        <thead class="bg-muted/40 sticky top-0">
          <tr class="text-left text-muted-foreground">
            <th class="px-3 py-2 font-medium">Module</th>
            <th class="px-3 py-2 font-medium w-28">Category</th>
            <th class="px-3 py-2 font-medium">Behavior</th>
            <th class="px-3 py-2 font-medium w-72">Mode</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="module in modules"
            :key="module.module"
            class="border-t border-border hover:bg-muted/20"
            :data-testid="`module-row-${module.module}`"
          >
            <td class="px-3 py-2 font-mono text-[11px] font-medium text-foreground">
              {{ module.name }}
              <span v-if="dirtyModules.has(module.module)" class="text-warning ml-1">●</span>
            </td>
            <td class="px-3 py-2">
              <Badge variant="secondary" class="font-mono text-[10px] tracking-normal">{{ module.category }}</Badge>
            </td>
            <td class="px-3 py-2 text-muted-foreground max-w-md truncate" :title="module.description">
              {{ module.description }}
            </td>
            <td class="px-3 py-2">
              <SemanticsModeSegment
                :model-value="module.mode"
                @update:model-value="(mode) => handleModeChange(module, mode as ModuleMode)"
              />
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Per-site overrides -->
    <SemanticsAppOverrides :modules="modules" class="grow min-h-0" />
  </div>
</template>
