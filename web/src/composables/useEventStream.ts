import { ref, onUnmounted } from 'vue';
import { api } from '@/api/client';
import type { ForensicEvent } from '@/types/telemetry';

export interface StreamFilter {
  action?: string;
  rule_id?: string;
  country?: string;
  min_severity?: string;
}

// Module-level shared reactive state so events persist across route navigations
const sharedEvents = ref<ForensicEvent[]>([]);
const isConnected = ref(false);
const isPaused = ref(false);
const error = ref<string | null>(null);

let eventSource: EventSource | null = null;
let reconnectTimer: any = null;
let reconnectDelay = 1000;
let currentFilter: StreamFilter | undefined;
let pausedQueue: ForensicEvent[] = [];
let subscriberCount = 0;

async function loadHistoricalEvents(maxBuffer: number, filter?: StreamFilter) {
  try {
    const res = await api.listEvents({
      limit: maxBuffer,
      action: filter?.action,
      rule_id: filter?.rule_id,
      country: filter?.country,
      min_severity: filter?.min_severity,
    });
    if (res && Array.isArray(res.events)) {
      const existingIds = new Set(sharedEvents.value.map((e) => e.event_id));
      const newItems = res.events.filter((e) => e.event_id && !existingIds.has(e.event_id));
      if (newItems.length > 0 || sharedEvents.value.length === 0) {
        const combined = [...sharedEvents.value, ...newItems];
        combined.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
        sharedEvents.value = combined.slice(0, maxBuffer);
      }
    }
  } catch {
    // Keep existing in-memory events if offline or mock environment
  }
}

export function useEventStream(initialFilter?: StreamFilter, maxBuffer = 200) {
  if (initialFilter && !currentFilter) {
    currentFilter = initialFilter;
  }

  function buildUrl(filter?: StreamFilter): string {
    const params = new URLSearchParams();
    if (filter?.action) params.set('action', filter.action);
    if (filter?.rule_id) params.set('rule_id', filter.rule_id);
    if (filter?.country) params.set('country', filter.country);
    if (filter?.min_severity) params.set('min_severity', filter.min_severity);

    const qs = params.toString();
    return `/.raiwall/api/events/stream${qs ? '?' + qs : ''}`;
  }

  function addEvent(event: ForensicEvent) {
    if (event.event_id) {
      const exists = sharedEvents.value.some((e) => e.event_id === event.event_id);
      if (exists) return;
    }
    sharedEvents.value.unshift(event);
    if (sharedEvents.value.length > maxBuffer) {
      sharedEvents.value.pop();
    }
  }

  function connect(filter?: StreamFilter) {
    subscriberCount++;
    if (filter) {
      currentFilter = filter;
    }

    // Hydrate existing attack and forensic history
    loadHistoricalEvents(maxBuffer, currentFilter);

    if (eventSource && eventSource.readyState !== EventSource.CLOSED) {
      isConnected.value = true;
      return;
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
        if (subscriberCount > 0) {
          reconnectTimer = setTimeout(() => {
            reconnectDelay = Math.min(reconnectDelay * 1.5, 15000);
            connect(currentFilter);
          }, reconnectDelay);
        }
      };
    } catch (err: any) {
      error.value = err?.message || 'Failed to initialize EventSource';
    }
  }

  function disconnect() {
    subscriberCount = Math.max(0, subscriberCount - 1);
    if (subscriberCount === 0) {
      clearTimeout(reconnectTimer);
      if (eventSource) {
        eventSource.close();
        eventSource = null;
      }
      isConnected.value = false;
    }
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
    sharedEvents.value = [];
    pausedQueue = [];
  }

  onUnmounted(() => {
    disconnect();
  });

  return {
    events: sharedEvents,
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
