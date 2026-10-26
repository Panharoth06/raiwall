<script setup lang="ts">
import { computed } from 'vue';
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';
import { SearchInput } from '@/components/ui/search-input';

type InspectorView = 'events' | 'incidents';

const props = defineProps<{
  view: InspectorView;
  searchQuery: string;
  hostFilter: string;
  selectedAction: string;
  isConnected: boolean;
  eventCount: number;
  incidentCount: number;
}>();

const emit = defineEmits<{
  (e: 'update:searchQuery', value: string): void;
  (e: 'update:hostFilter', value: string): void;
  (e: 'update:selectedAction', value: string): void;
  (e: 'refresh-incidents'): void;
}>();

const searchModel = computed({
  get: () => props.searchQuery,
  set: (value: string) => emit('update:searchQuery', value),
});
</script>

<template>
  <div class="flex flex-wrap items-center justify-between gap-3 px-5 py-3 border-b border-border bg-card">
    <div class="flex items-center gap-3">
      <span data-testid="status-text" class="text-xs font-semibold tracking-wider uppercase text-muted-foreground">
        {{ isConnected ? 'Live Telemetry' : 'Disconnected' }}
      </span>
      <span class="text-xs text-muted-foreground/60">|</span>
      <span
        data-testid="view-count"
        class="text-xs font-mono tabular-nums text-muted-foreground"
      >
        {{ view === 'incidents' ? `${incidentCount} incidents` : `${eventCount} events` }}
      </span>
    </div>

    <div v-if="view === 'events'" class="flex items-center gap-2.5">
      <SearchInput
        v-model="searchModel"
        clearable
        placeholder="Filter IP, Rule, Method, Country…"
        data-testid="live-search-input"
        class="w-48 sm:w-64"
      />

      <button
        v-if="hostFilter"
        type="button"
        data-testid="host-filter-chip"
        class="inline-flex items-center gap-1 px-2 py-1 text-xs font-mono bg-muted border border-border rounded-md text-foreground cursor-pointer"
        title="Clear host filter"
        @click="emit('update:hostFilter', '')"
      >
        host:{{ hostFilter }} ×
      </button>

      <div class="relative z-30">
        <Select :model-value="selectedAction" @update:model-value="emit('update:selectedAction', String($event))">
          <SelectTrigger data-testid="action-filter-select" class="h-8 w-32 border-input bg-card text-foreground text-xs">
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
    </div>

    <button
      v-else
      type="button"
      data-testid="incidents-refresh"
      class="px-3 py-1.5 text-xs font-medium text-muted-foreground hover:text-foreground bg-muted hover:bg-muted/80 border border-border rounded-md transition-colors cursor-pointer"
      @click="emit('refresh-incidents')"
    >
      Refresh incidents
    </button>
  </div>
</template>
