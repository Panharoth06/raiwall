<script setup lang="ts">
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';
import { SearchInput } from '@/components/ui/search-input';
import { NumberInput } from '@/components/ui/number-input';

export type EngineFilter = 'all' | 'semantic' | 'crs';

const search = defineModel<string>('search', { required: true });
const action = defineModel<string>('action', { required: true });
const engine = defineModel<EngineFilter>('engine', { required: true });
const minScore = defineModel<number | null | undefined>('minScore');
</script>

<template>
  <SearchInput
    v-model="search"
    clearable
    placeholder="Filter IP, Rule, Method, Country…"
    data-testid="logs-search-input"
    class="w-48 sm:w-64"
  />

  <div class="relative z-30">
    <Select v-model="action">
      <SelectTrigger data-testid="logs-action-filter-select" aria-label="Action" class="h-8 w-32 border-input bg-background text-foreground text-xs">
        <SelectValue placeholder="All Actions" />
      </SelectTrigger>
      <SelectContent class="border-border bg-popover text-popover-foreground z-50">
        <SelectItem value="all">All Actions</SelectItem>
        <SelectItem value="allow">Allow</SelectItem>
        <SelectItem value="block">Block</SelectItem>
        <SelectItem value="challenge">Challenge</SelectItem>
        <SelectItem value="ban">Ban</SelectItem>
      </SelectContent>
    </Select>
  </div>

  <div class="relative z-30">
    <Select v-model="engine">
      <SelectTrigger data-testid="logs-engine-filter-select" aria-label="Detection engine" class="h-8 w-32 border-input bg-background text-foreground text-xs">
        <SelectValue placeholder="All Engines" />
      </SelectTrigger>
      <SelectContent class="border-border bg-popover text-popover-foreground z-50">
        <SelectItem value="all">All Engines</SelectItem>
        <SelectItem value="semantic">Semantic</SelectItem>
        <SelectItem value="crs">CRS</SelectItem>
      </SelectContent>
    </Select>
  </div>

  <!-- CRS anomaly score floor; semantic events store 0 -->
  <NumberInput
    v-model="minScore"
    :min="0"
    :step="1"
    placeholder="Min score"
    data-testid="logs-min-score-input"
    aria-label="Minimum anomaly score"
    class="w-28"
  />
</template>
