<script setup lang="ts">
import { Search, Radio, Layers } from 'lucide-vue-next';
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';

type InspectorView = 'incidents' | 'logs';

defineProps<{
  view: InspectorView;
  searchQuery: string;
  hostFilter: string;
  selectedAction: string;
  isConnected: boolean;
  eventCount: number;
  incidentCount: number;
}>();

const emit = defineEmits<{
  (e: 'update:view', view: InspectorView): void;
  (e: 'update:searchQuery', value: string): void;
  (e: 'update:hostFilter', value: string): void;
  (e: 'update:selectedAction', value: string): void;
  (e: 'refresh-incidents'): void;
}>();
</script>

<template>
  <div class="flex flex-wrap items-center justify-between gap-3 px-5 py-3 border-b border-border bg-card">
    <div class="flex items-center gap-3">
      <div class="flex items-center rounded-lg border border-border overflow-hidden" role="tablist">
        <button
          type="button"
          role="tab"
          data-testid="view-tab-incidents"
          :aria-selected="view === 'incidents'"
          class="inline-flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wide transition-colors cursor-pointer"
          :class="view === 'incidents' ? 'bg-primary text-primary-foreground' : 'bg-background text-muted-foreground hover:text-foreground'"
          @click="emit('update:view', 'incidents')"
        >
          <Layers class="w-3.5 h-3.5" />
          Events
          <span class="font-mono tabular-nums opacity-80">{{ incidentCount }}</span>
        </button>
        <button
          type="button"
          role="tab"
          data-testid="view-tab-logs"
          :aria-selected="view === 'logs'"
          class="inline-flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wide transition-colors cursor-pointer"
          :class="view === 'logs' ? 'bg-primary text-primary-foreground' : 'bg-background text-muted-foreground hover:text-foreground'"
          @click="emit('update:view', 'logs')"
        >
          <Radio class="w-3.5 h-3.5" />
          Logs
          <span class="font-mono tabular-nums opacity-80">{{ eventCount }}</span>
        </button>
      </div>
      <span data-testid="status-text" class="text-[11px] font-semibold tracking-wider uppercase text-muted-foreground">
        {{ isConnected ? 'Live Telemetry' : 'Disconnected' }}
      </span>
    </div>

    <div v-if="view === 'logs'" class="flex items-center gap-2.5">
      <div class="relative">
        <Search class="absolute left-2.5 top-2.5 w-3.5 h-3.5 text-muted-foreground" />
        <input
          :value="searchQuery"
          type="text"
          placeholder="Filter IP, Rule, Method, Country..."
          data-testid="live-search-input"
          class="w-48 sm:w-64 pl-8 pr-3 py-1.5 text-xs bg-background border border-input rounded-lg text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring transition-all"
          @input="emit('update:searchQuery', ($event.target as HTMLInputElement).value)"
        />
      </div>

      <button
        v-if="hostFilter"
        type="button"
        data-testid="host-filter-chip"
        class="inline-flex items-center gap-1 px-2 py-1 text-[11px] font-mono bg-muted border border-border rounded-lg text-foreground"
        title="Clear host filter"
        @click="emit('update:hostFilter', '')"
      >
        host:{{ hostFilter }} ×
      </button>

      <div class="relative z-30">
        <Select :model-value="selectedAction" @update:model-value="emit('update:selectedAction', String($event))">
          <SelectTrigger class="h-8 w-32 border-input bg-background text-foreground text-xs">
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
        <select
          :value="selectedAction"
          data-testid="action-filter-select"
          class="sr-only"
          tabindex="-1"
          aria-hidden="true"
          @change="emit('update:selectedAction', ($event.target as HTMLSelectElement).value)"
        >
          <option value="all">All Actions</option>
          <option value="allow">Allow</option>
          <option value="block">Block</option>
          <option value="challenge">Challenge</option>
          <option value="ban">Ban</option>
        </select>
      </div>
    </div>

    <button
      v-else
      type="button"
      data-testid="incidents-refresh"
      class="px-3 py-1.5 text-[11px] font-medium text-muted-foreground hover:text-foreground bg-muted hover:bg-muted/80 border border-border rounded-lg transition-colors cursor-pointer"
      @click="emit('refresh-incidents')"
    >
      Refresh incidents
    </button>
  </div>
</template>
