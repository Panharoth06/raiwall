<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { api, type Site } from '@/api/client';
import { semanticsApi, type DetectorModule, type ModuleMode } from '@/api/semantics';
import { Button } from '@/components/ui/button';
import { SearchInput } from '@/components/ui/search-input';
import { Badge } from '@/components/ui/badge';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/table';
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';
import SemanticsModeSegment from '@/components/SemanticsModeSegment.vue';
import { FileSliders, Loader2, Save } from 'lucide-vue-next';

const props = defineProps<{ modules: DetectorModule[] }>();

const sites = ref<Site[]>([]);
const selectedAppID = ref('');
const search = ref('');
const overrides = ref<Record<string, ModuleMode>>({});
const loading = ref(false);
const saving = ref(false);
const error = ref('');
const saved = ref(false);

const filteredSites = computed(() =>
  sites.value.filter((s) => s.name.toLowerCase().includes(search.value.toLowerCase()))
);

const loadSites = async () => {
  try {
    sites.value = await api.listSites();
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to load sites';
  }
};

const selectApp = async (appID: string) => {
  selectedAppID.value = appID;
  error.value = '';
  if (!appID) {
    overrides.value = {};
    return;
  }
  loading.value = true;
  try {
    const policy = await semanticsApi.getAppPolicy(appID);
    overrides.value = { ...(policy.overrides || {}) };
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to load policy';
  } finally {
    loading.value = false;
  }
};

const setOverride = (module: string, mode: ModuleMode | 'inherit') => {
  if (mode === 'inherit') {
    delete overrides.value[module];
    overrides.value = { ...overrides.value };
  } else {
    overrides.value = { ...overrides.value, [module]: mode };
  }
  saved.value = false;
};

const overrideCount = computed(() => Object.keys(overrides.value).length);

const saveOverrides = async () => {
  if (!selectedAppID.value) return;
  saving.value = true;
  error.value = '';
  try {
    await semanticsApi.setAppPolicy(selectedAppID.value, overrides.value);
    saved.value = true;
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Save failed';
  } finally {
    saving.value = false;
  }
};

onMounted(loadSites);
</script>

<template>
  <div class="border border-border rounded-lg flex flex-col min-h-0 bg-background">
    <!-- Panel header -->
    <div class="flex items-center justify-between px-3 py-2 border-b border-border shrink-0">
      <div class="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-foreground">
        <FileSliders class="w-3.5 h-3.5 text-muted-foreground" />
        Per-Site Overrides
      </div>
      <div class="flex items-center gap-2">
        <SearchInput
          v-model="search"
          clearable
          placeholder="Filter sites…"
          class="w-44"
          data-testid="site-filter"
        />
        <div class="w-44 relative">
          <Select
            :model-value="selectedAppID"
            @update:model-value="(val) => selectApp(val === '__none__' ? '' : (val as string))"
          >
            <SelectTrigger class="h-8 text-xs font-mono bg-card border-border text-foreground">
              <SelectValue placeholder="Select site…" />
            </SelectTrigger>
            <SelectContent class="border-border bg-popover text-popover-foreground">
              <SelectItem value="__none__" class="text-xs text-muted-foreground">Select site…</SelectItem>
              <SelectItem
                v-for="site in filteredSites"
                :key="site.id"
                :value="site.id"
                class="text-xs font-mono"
              >
                {{ site.name }}
              </SelectItem>
            </SelectContent>
          </Select>
          <select
            v-model="selectedAppID"
            class="sr-only"
            tabindex="-1"
            aria-hidden="true"
            data-testid="app-selector"
            @change="selectApp(($event.target as HTMLSelectElement).value)"
          >
            <option value="">Select site…</option>
            <option v-for="site in filteredSites" :key="site.id" :value="site.id">{{ site.name }}</option>
          </select>
        </div>
      </div>
    </div>

    <p v-if="error" class="px-3 py-1 text-xs text-destructive shrink-0" data-testid="override-error">{{ error }}</p>

    <!-- Empty state -->
    <div
      v-if="!selectedAppID"
      class="grow flex flex-col items-center justify-center gap-1 text-muted-foreground"
      data-testid="override-empty"
    >
      <p class="text-xs font-medium">No site selected</p>
      <p class="text-[11px]">Pick a site to shape its detection posture independently of the global matrix.</p>
    </div>

    <!-- Overrides table -->
    <div v-else class="grow overflow-y-auto min-h-0">
      <div v-if="loading" class="h-full flex items-center justify-center text-muted-foreground">
        <Loader2 class="w-4 h-4 animate-spin" />
      </div>
      <Table v-else data-testid="override-table" container-class="overflow-visible">
        <TableHeader>
          <TableRow>
            <TableHead>Module</TableHead>
            <TableHead class="w-32">Global</TableHead>
            <TableHead class="w-80">Site Override</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow
            v-for="module in props.modules"
            :key="module.module"
            :data-testid="`override-row-${module.module}`"
          >
            <TableCell class="font-mono text-[11px] text-foreground">{{ module.name }}</TableCell>
            <TableCell class="text-[10px] text-muted-foreground">global: {{ module.mode }}</TableCell>
            <TableCell class="w-80">
              <SemanticsModeSegment
                inherit
                :model-value="overrides[module.module] || 'inherit'"
                @update:model-value="(mode) => setOverride(module.module, mode)"
              />
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </div>

    <!-- Panel footer -->
    <div
      v-if="selectedAppID"
      class="flex items-center justify-between px-3 py-2 border-t border-border shrink-0"
    >
      <Badge variant="outline" class="font-mono text-[10px] tracking-normal" data-testid="override-count">
        {{ overrideCount }} overridden / {{ props.modules.length }}
      </Badge>
      <Button size="sm" class="h-7 text-xs gap-1" :disabled="saving" data-testid="save-overrides" @click="saveOverrides">
        <Loader2 v-if="saving" class="w-3 h-3 animate-spin" />
        <Save v-else class="w-3 h-3" />
        {{ saved ? 'Saved' : 'Save Overrides' }}
      </Button>
    </div>
  </div>
</template>
