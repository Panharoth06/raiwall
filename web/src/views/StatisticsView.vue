<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useStatistics } from '@/composables/useStatistics'
import { useConfigStore } from '@/stores/config'
import StatsFilterBar from '@/components/statistics/StatsFilterBar.vue'
import StatsKpiCards from '@/components/statistics/StatsKpiCards.vue'
import StatsErrorRates from '@/components/statistics/StatsErrorRates.vue'
import StatsGeoPanel from '@/components/statistics/StatsGeoPanel.vue'
import StatsTrendCard from '@/components/statistics/StatsTrendCard.vue'
import StatsThreatDistribution from '@/components/statistics/StatsThreatDistribution.vue'
import SecurityPostureView from '@/components/statistics/SecurityPostureView.vue'
import { Button } from '@/components/ui/button'

const activeTab = ref<'traffic' | 'security' | 'dashboard'>('traffic')

const configStore = useConfigStore()
const {
  timeRange,
  customStart,
  customEnd,
  selectedHost,
  selectedCountry,
  stats,
  loading,
  error,
  liveQps,
  isConnected,
  fetchStats,
  handleCountrySelect,
  clearCountryFilter,
} = useStatistics()

onMounted(() => {
  if (configStore.sites.length === 0) {
    configStore.loadAll()
  }
})
</script>

<template>
  <div class="h-full w-full flex flex-col p-6 space-y-6 bg-background font-sans overflow-y-auto">
    <!-- Filter Bar (Tabs, App Selector, Time Presets, SSE live indicator, Refresh) -->
    <StatsFilterBar
      :active-tab="activeTab"
      :time-range="timeRange"
      :custom-start="customStart"
      :custom-end="customEnd"
      :selected-host="selectedHost"
      :selected-country="selectedCountry"
      :sites="configStore.sites"
      :loading="loading"
      :is-connected="isConnected"
      @update:active-tab="activeTab = $event as any"
      @update:time-range="timeRange = $event"
      @update:custom-start="customStart = $event"
      @update:custom-end="customEnd = $event"
      @update:selected-host="selectedHost = $event"
      @clear-country="clearCountryFilter"
      @refresh="fetchStats"
    />

    <!-- Error Banner with Retry -->
    <div
      v-if="error"
      class="p-4 bg-threat/10 border border-threat/30 rounded-xl text-threat text-sm flex items-center justify-between"
    >
      <span>{{ error }}</span>
      <Button
        variant="ghost"
        size="sm"
        class="text-threat hover:bg-threat/20 font-semibold"
        @click="fetchStats"
      >
        Retry
      </Button>
    </div>

    <!-- Tab 1: Traffic Analysis -->
    <div v-if="activeTab === 'traffic'" class="space-y-6">
      <!-- Row 1: KPI Cards Grid -->
      <StatsKpiCards :stats="stats" :live-qps="liveQps" />

      <!-- Row 2: Error & Blocked Rates -->
      <StatsErrorRates :stats="stats" />

      <!-- Main Middle Grid: Geo Location (Left) + Requests & Blocking Trends (Right) -->
      <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <!-- Left: Geo Location Panel -->
        <div class="lg:col-span-7">
          <StatsGeoPanel
            :countries="stats.top_countries"
            :selected-country="selectedCountry"
            :total-requests="stats.total_requests"
            :total-blocked="stats.total_blocked"
            @select-country="handleCountrySelect"
          />
        </div>

        <!-- Right: Requests Status & Blocking Status Stack -->
        <div class="lg:col-span-5 flex flex-col gap-6">
          <StatsTrendCard
            title="Requests Status"
            variant="requests"
            :buckets="stats.time_buckets"
          />
          <StatsTrendCard
            title="Blocking Status"
            variant="blocking"
            :buckets="stats.time_buckets"
          />
        </div>
      </div>

      <!-- Lower Section: Threat Distribution with Table & Progress -->
      <StatsThreatDistribution
        :categories="stats.top_categories"
        :rules="stats.top_rules"
        :ips="stats.top_ips"
        :total-blocked="stats.total_blocked"
      />
    </div>

    <!-- Tab 2: Security Posture -->
    <div v-else-if="activeTab === 'security'">
      <SecurityPostureView :stats="stats" />
    </div>

    <!-- Tab 3: Data Dashboard -->
    <div v-else-if="activeTab === 'dashboard'" class="space-y-6">
      <StatsKpiCards :stats="stats" :live-qps="liveQps" />
      <StatsThreatDistribution
        :categories="stats.top_categories"
        :rules="stats.top_rules"
        :ips="stats.top_ips"
        :total-blocked="stats.total_blocked"
      />
    </div>
  </div>
</template>
