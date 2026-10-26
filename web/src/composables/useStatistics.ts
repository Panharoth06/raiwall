import { ref, computed, watch, onMounted, onUnmounted } from 'vue';
import { telemetryApi } from '@/api/telemetry';
import { useEventStream } from '@/composables/useEventStream';
import type { AggregateStats, ForensicEvent } from '@/types/telemetry';

export type TimeRangePreset = '1h' | '6h' | '24h' | '7d' | '30d' | 'custom';

export function useStatistics() {
  const timeRange = ref<TimeRangePreset>('24h');
  const customStart = ref<string>('');
  const customEnd = ref<string>('');
  const selectedHost = ref<string>('');
  const selectedCountry = ref<string>('');

  const stats = ref<AggregateStats>({
    total_requests: 0,
    total_blocked: 0,
    block_ratio: 0,
    page_views: 0,
    unique_visitors: 0,
    unique_ips: 0,
    blocked_ips: 0,
    status_4xx: 0,
    status_4xx_rate: 0,
    status_4xx_blocked: 0,
    status_4xx_blocked_rate: 0,
    status_5xx: 0,
    status_5xx_rate: 0,
    qps: 0,
    time_buckets: [],
    top_countries: [],
    top_rules: [],
    top_ips: [],
    top_categories: [],
  });

  const loading = ref(false);
  const error = ref<string | null>(null);
  const liveQps = ref<number>(0);
  const lastUpdated = ref<Date>(new Date());

  const { isConnected, connect } = useEventStream();
  let pollInterval: ReturnType<typeof setInterval> | null = null;
  let recentEventCounter: number = 0;
  let qpsCalcInterval: ReturnType<typeof setInterval> | null = null;

  function getTimeBounds(): { start?: string; end?: string } {
    const now = new Date();
    if (timeRange.value === 'custom') {
      return {
        start: customStart.value ? new Date(customStart.value).toISOString() : undefined,
        end: customEnd.value ? new Date(customEnd.value).toISOString() : undefined,
      };
    }

    const hoursMap: Record<Exclude<TimeRangePreset, 'custom'>, number> = {
      '1h': 1,
      '6h': 6,
      '24h': 24,
      '7d': 168,
      '30d': 720,
    };

    const hours = hoursMap[timeRange.value] || 24;
    const start = new Date(now.getTime() - hours * 3600 * 1000);
    return {
      start: start.toISOString(),
      end: now.toISOString(),
    };
  }

  async function fetchStats() {
    loading.value = true;
    error.value = null;
    try {
      const { start, end } = getTimeBounds();
      const data = await telemetryApi.getStats({
        start_time: start,
        end_time: end,
        host: selectedHost.value || undefined,
        country: selectedCountry.value || undefined,
      });

      if (data) {
        stats.value = {
          ...stats.value,
          ...data,
          page_views: data.page_views ?? 0,
          unique_visitors: data.unique_visitors ?? data.unique_ips ?? 0,
          unique_ips: data.unique_ips ?? 0,
          blocked_ips: data.blocked_ips ?? 0,
          status_4xx: data.status_4xx ?? 0,
          status_4xx_rate: data.status_4xx_rate ?? 0,
          status_4xx_blocked: data.status_4xx_blocked ?? 0,
          status_4xx_blocked_rate: data.status_4xx_blocked_rate ?? 0,
          status_5xx: data.status_5xx ?? 0,
          status_5xx_rate: data.status_5xx_rate ?? 0,
          qps: data.qps ?? stats.value.qps,
        };
        if (data.qps !== undefined && recentEventCounter === 0) {
          liveQps.value = data.qps;
        }
      }
      lastUpdated.value = new Date();
    } catch (err: unknown) {
      error.value = err instanceof Error ? err.message : 'Failed to load telemetry stats';
    } finally {
      loading.value = false;
    }
  }

  function handleCountrySelect(country: string) {
    if (selectedCountry.value === country) {
      selectedCountry.value = '';
    } else {
      selectedCountry.value = country;
    }
  }

  function clearCountryFilter() {
    selectedCountry.value = '';
  }

  watch([timeRange, selectedHost, selectedCountry], () => {
    fetchStats();
  });

  onMounted(() => {
    fetchStats();
    connect();

    // 10s auto-refresh
    pollInterval = setInterval(() => {
      fetchStats();
    }, 10000);

    // Dynamic QPS calculation ticker
    qpsCalcInterval = setInterval(() => {
      if (recentEventCounter > 0) {
        liveQps.value = recentEventCounter;
        recentEventCounter = 0;
      } else if (stats.value.qps !== undefined) {
        liveQps.value = stats.value.qps;
      }
    }, 1000);
  });

  onUnmounted(() => {
    if (pollInterval) clearInterval(pollInterval);
    if (qpsCalcInterval) clearInterval(qpsCalcInterval);
  });

  return {
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
    lastUpdated,
    fetchStats,
    handleCountrySelect,
    clearCountryFilter,
  };
}
