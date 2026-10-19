import { ref, onUnmounted } from 'vue';
import type { ForensicEvent } from '@/types/telemetry';

export interface StreamFilter {
  action?: string;
  rule_id?: string;
  country?: string;
  min_severity?: string;
}

export function useEventStream(initialFilter?: StreamFilter, maxBuffer = 200) {
  const events = ref<ForensicEvent[]>([]);
  const isConnected = ref(false);
  const isPaused = ref(false);
  const error = ref<string | null>(null);

  let eventSource: EventSource | null = null;
  let reconnectTimer: any = null;
  let reconnectDelay = 1000;
  let currentFilter = initialFilter;
  let pausedQueue: ForensicEvent[] = [];

  function buildUrl(filter?: StreamFilter): string {
    const params = new URLSearchParams();
    if (filter?.action) params.set('action', filter.action);
    if (filter?.rule_id) params.set('rule_id', filter.rule_id);
    if (filter?.country) params.set('country', filter.country);
    if (filter?.min_severity) params.set('min_severity', filter.min_severity);

    const qs = params.toString();
    return `/.raiwall/api/events/stream${qs ? '?' + qs : ''}`;
  }

  function connect(filter?: StreamFilter) {
    disconnect();
    if (filter) {
      currentFilter = filter;
    }

    const url = buildUrl(currentFilter);
    try {
      eventSource = new EventSource(url);

      eventSource.onopen = () => {
        isConnected.value = true;
        error.value = null;
        reconnectDelay = 1000;
      };

      eventSource.onmessage = (e: MessageEvent) => {
        if (!e.data || e.data.startsWith(':')) return;

        try {
          const parsed: ForensicEvent = JSON.parse(e.data);
          if (isPaused.value) {
            pausedQueue.push(parsed);
            if (pausedQueue.length > maxBuffer) {
              pausedQueue.shift();
            }
          } else {
            addEvent(parsed);
          }
        } catch {
          // Ignore parse errors on comments or malformed frames
        }
      };

      eventSource.onerror = () => {
        isConnected.value = false;
        error.value = 'Connection lost. Reconnecting...';
        if (eventSource) {
          eventSource.close();
          eventSource = null;
        }

        clearTimeout(reconnectTimer);
        reconnectTimer = setTimeout(() => {
          reconnectDelay = Math.min(reconnectDelay * 1.5, 15000);
          connect(currentFilter);
        }, reconnectDelay);
      };
    } catch (err: any) {
      error.value = err?.message || 'Failed to initialize EventSource';
    }
  }

  function addEvent(event: ForensicEvent) {
    events.value.unshift(event);
    if (events.value.length > maxBuffer) {
      events.value.pop();
    }
  }

  function disconnect() {
    clearTimeout(reconnectTimer);
    if (eventSource) {
      eventSource.close();
      eventSource = null;
    }
    isConnected.value = false;
  }

  function pause() {
    isPaused.value = true;
  }

  function resume() {
    isPaused.value = false;
    if (pausedQueue.length > 0) {
      for (const ev of pausedQueue) {
        addEvent(ev);
      }
      pausedQueue = [];
    }
  }

  function clear() {
    events.value = [];
    pausedQueue = [];
  }

  onUnmounted(() => {
    disconnect();
  });

  return {
    events,
    isConnected,
    isPaused,
    error,
    connect,
    disconnect,
    pause,
    resume,
    clear,
  };
}
