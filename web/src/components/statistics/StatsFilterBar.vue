<script setup lang="ts">
import { ref } from 'vue';
import { RefreshCw, X, Calendar, Filter } from 'lucide-vue-next';
import { Tabs, type Tab } from '@/components/ui/tabs';
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';
import DatePicker from '@/components/ui/date-picker/DatePicker.vue';
import type { TimeRangePreset } from '@/composables/useStatistics';
import type { Site } from '@/api/client';

const props = defineProps<{
  activeTab: string;
  timeRange: TimeRangePreset;
  customStart: string;
  customEnd: string;
  selectedHost: string;
  selectedCountry: string;
  sites: Site[];
  loading: boolean;
  isConnected: boolean;
}>();

const emit = defineEmits<{
  (e: 'update:activeTab', tab: string): void;
  (e: 'update:timeRange', range: TimeRangePreset): void;
  (e: 'update:customStart', val: string): void;
  (e: 'update:customEnd', val: string): void;
  (e: 'update:selectedHost', host: string): void;
  (e: 'clearCountry'): void;
  (e: 'refresh'): void;
}>();

const tabs: Tab[] = [
  { id: 'traffic', label: 'TRAFFIC ANALYSIS', testId: 'tab-traffic-analysis' },
  { id: 'security', label: 'SECURITY POSTURE', testId: 'tab-security-posture' },
  { id: 'dashboard', label: 'DATA DASHBOARD', testId: 'tab-data-dashboard' },
];

const showCustomModal = ref(false);
const tempStart = ref(props.customStart || new Date(Date.now() - 86400000).toISOString().slice(0, 10));
const tempEnd = ref(props.customEnd || new Date().toISOString().slice(0, 10));

function onTimeRangeSelect(val: string) {
  if (val === 'custom') {
    showCustomModal.value = true;
  } else {
    emit('update:timeRange', val as TimeRangePreset);
  }
}

function applyCustomRange() {
  emit('update:customStart', tempStart.value);
  emit('update:customEnd', tempEnd.value);
  emit('update:timeRange', 'custom');
  showCustomModal.value = false;
}
</script>

<template>
  <div class="flex flex-col gap-4 border-b border-border pb-4">
    <div class="flex flex-wrap items-center justify-between gap-3">
      <!-- Left: Navigation Sub-Tabs using existing Tabs component -->
      <div class="flex items-center">
        <Tabs
          :tabs="tabs"
          :active-tab="activeTab"
          @tab-change="emit('update:activeTab', $event)"
        />
      </div>

      <!-- Right: Global Telemetry Controls using existing Select components -->
      <div class="flex flex-wrap items-center gap-2.5">
        <!-- Application Select Dropdown -->
        <div class="w-48">
          <Select
            :model-value="selectedHost || '__ALL__'"
            @update:model-value="val => emit('update:selectedHost', val === '__ALL__' ? '' : String(val))"
          >
            <SelectTrigger data-testid="app-filter-select" class="h-8 text-xs bg-card border-border">
              <SelectValue placeholder="All applications" />
            </SelectTrigger>
            <SelectContent class="bg-popover text-popover-foreground border-border max-h-60">
              <SelectItem value="__ALL__">All applications</SelectItem>
              <SelectItem
                v-for="site in sites"
                :key="site.id"
                :value="site.hostnames?.[0] || site.name"
              >
                {{ site.name }} ({{ site.hostnames?.[0] || '*' }})
              </SelectItem>
            </SelectContent>
          </Select>
        </div>

        <!-- Time Range Select Dropdown -->
        <div class="w-32">
          <Select
            :model-value="timeRange"
            @update:model-value="val => onTimeRangeSelect(String(val))"
          >
            <SelectTrigger data-testid="time-range-select" class="h-8 text-xs bg-card border-border">
              <SelectValue />
            </SelectTrigger>
            <SelectContent class="bg-popover text-popover-foreground border-border">
              <SelectItem value="1h">1 hour</SelectItem>
              <SelectItem value="6h">6 hours</SelectItem>
              <SelectItem value="24h">24 hours</SelectItem>
              <SelectItem value="7d">7 days</SelectItem>
              <SelectItem value="30d">30 days</SelectItem>
              <SelectItem value="custom">Custom Range...</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <!-- Active Country Filter Chip -->
        <div
          v-if="selectedCountry"
          class="flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono bg-primary/10 border border-primary/30 text-primary rounded-lg"
        >
          <Filter class="w-3 h-3" />
          <span>{{ selectedCountry }}</span>
          <button
            type="button"
            @click="emit('clearCountry')"
            class="hover:opacity-80 ml-0.5 cursor-pointer"
          >
            <X class="w-3 h-3" />
          </button>
        </div>

        <!-- Live SSE Stream Status -->
        <div
          class="flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-mono rounded-lg border border-border bg-card text-muted-foreground"
          :title="isConnected ? 'Real-time telemetry SSE active' : 'Connecting SSE telemetry...'"
        >
          <span
            :class="[
              'w-2 h-2 rounded-full transition-colors',
              isConnected ? 'bg-success animate-pulse' : 'bg-muted-foreground/50',
            ]"
          />
          <span class="hidden sm:inline">{{ isConnected ? 'LIVE' : 'SYNC' }}</span>
        </div>

        <!-- Refresh Button -->
        <button
          type="button"
          data-testid="refresh-stats-btn"
          @click="emit('refresh')"
          :disabled="loading"
          class="h-8 px-2.5 text-xs font-medium text-foreground hover:bg-muted bg-card border border-border rounded-lg transition-colors flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
        >
          <RefreshCw :class="['w-3.5 h-3.5', loading ? 'animate-spin' : '']" />
          <span class="hidden sm:inline">Refresh</span>
        </button>
      </div>
    </div>

    <!-- Custom Date Range Dialog featuring existing DatePicker -->
    <div
      v-if="showCustomModal"
      class="fixed inset-0 bg-background/80 backdrop-blur-xs flex items-center justify-center z-50 p-4"
    >
      <div class="bg-card border border-border rounded-xl p-5 max-w-sm w-full space-y-4 shadow-lg">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-2 text-sm font-bold text-foreground">
            <Calendar class="w-4 h-4 text-primary" />
            <span>Select Custom Date Range</span>
          </div>
          <button
            type="button"
            @click="showCustomModal = false"
            class="text-muted-foreground hover:text-foreground cursor-pointer"
          >
            <X class="w-4 h-4" />
          </button>
        </div>

        <div class="space-y-3 text-xs">
          <div>
            <label class="block text-muted-foreground mb-1 font-medium">Start Date</label>
            <DatePicker
              v-model="tempStart"
              placeholder="Pick start date"
              class="w-full"
            />
          </div>
          <div>
            <label class="block text-muted-foreground mb-1 font-medium">End Date</label>
            <DatePicker
              v-model="tempEnd"
              placeholder="Pick end date"
              class="w-full"
            />
          </div>
        </div>

        <div class="flex justify-end gap-2 pt-2">
          <button
            type="button"
            @click="showCustomModal = false"
            class="px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground cursor-pointer"
          >
            Cancel
          </button>
          <button
            type="button"
            @click="applyCustomRange"
            class="px-3 py-1.5 text-xs font-semibold bg-primary text-primary-foreground rounded-lg cursor-pointer hover:opacity-90"
          >
            Apply Range
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
