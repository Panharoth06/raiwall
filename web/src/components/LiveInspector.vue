<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted } from 'vue';
import { useRoute, useRouter } from '@/router';
import { useEventStream } from '@/composables/useEventStream';
import { telemetryApi, type IncidentQueryParams } from '@/api/telemetry';
import type { ForensicEvent, ExceptionDraft, Incident, IPGroupOption, CurlState } from '@/types/telemetry';
import ForensicEventTable from './forensic/ForensicEventTable.vue';
import IncidentCardList from './forensic/IncidentCardList.vue';
import ForensicDrawer from './forensic/ForensicDrawer.vue';
import InspectorToolbar from './forensic/InspectorToolbar.vue';

type InspectorView = 'events' | 'incidents';

const props = withDefaults(
  defineProps<{
    view?: InspectorView;
    initialFilter?: { action?: string; rule_id?: string; country?: string };
    maxEvents?: number;
    streamComposable?: ReturnType<typeof useEventStream>;
    incidentLoader?: (params: IncidentQueryParams) => Promise<{ incidents: Incident[]; total_count: number }>;
    curlLoader?: (eventId: string) => Promise<{ curl: string }>;
    ipGroupLoader?: () => Promise<IPGroupOption[]>;
    ipGroupAdder?: (groupId: string, cidr: string, comment: string) => Promise<unknown>;
  }>(),
  {
    view: 'events',
    maxEvents: 200,
  }
);

const emit = defineEmits<{
  (e: 'update:view', view: InspectorView): void;
  (e: 'create-exception', draft: ExceptionDraft): void;
  (e: 'add-to-ipgroup', payload: { event: ForensicEvent; groupId: string }): void;
}>();

const route = useRoute();
const router = useRouter();

// Use injected or default event stream composable
const stream = props.streamComposable || useEventStream(props.initialFilter, props.maxEvents);
const { events, isConnected } = stream;

// View + filter state
const activeView = computed<InspectorView>(() => props.view);
const searchQuery = ref('');
const hostFilter = ref('');
const selectedAction = ref<string>('all');
const activeEvent = ref<ForensicEvent | null>(null);

// Incident clustering state
const incidents = ref<Incident[]>([]);
const incidentsTotal = ref(0);
const incidentsLoading = ref(false);
const incidentsError = ref<string | null>(null);
const incidentsLoaded = ref(false);

// Drawer action state
const curlState = ref<CurlState>('idle');
const ipGroups = ref<IPGroupOption[]>([]);
const groupsLoaded = ref(false);
const groupStatus = ref('');

onMounted(() => {
  if (!props.streamComposable) {
    stream.connect();
  }
  const query = route.value?.query || {};
  if (query.ip) searchQuery.value = query.ip;
  if (query.host) hostFilter.value = query.host;
  if (query.view === 'incidents') emit('update:view', 'incidents');
});

onUnmounted(() => {
  if (!props.streamComposable) {
    stream.disconnect();
  }
});

const filteredEvents = computed(() =>
  events.value.filter((ev) => {
    if (selectedAction.value !== 'all' && ev.action !== selectedAction.value) {
      return false;
    }
    if (hostFilter.value && ev.host !== hostFilter.value) {
      return false;
    }
    if (!searchQuery.value) return true;
    const q = searchQuery.value.toLowerCase();
    return (
      ev.client_ip.toLowerCase().includes(q) ||
      ev.host?.toLowerCase().includes(q) ||
      (ev.rule_id && ev.rule_id.toLowerCase().includes(q)) ||
      ev.method.toLowerCase().includes(q) ||
      ev.path.toLowerCase().includes(q) ||
      (ev.geo_data?.country && ev.geo_data.country.toLowerCase().includes(q))
    );
  })
);

watch(
  () => props.view,
  (view) => {
    if (view === 'incidents' && !incidentsLoaded.value) {
      void loadIncidents();
    }
  },
  { immediate: true }
);

async function loadIncidents() {
  incidentsLoading.value = true;
  incidentsError.value = null;
  try {
    const loader = props.incidentLoader ?? telemetryApi.listIncidents;
    const res = await loader({ limit: 50 });
    incidents.value = res?.incidents ?? [];
    incidentsTotal.value = res?.total_count ?? incidents.value.length;
    incidentsLoaded.value = true;
  } catch (err) {
    incidentsError.value = err instanceof Error ? err.message : 'Incident aggregation request failed';
  } finally {
    incidentsLoading.value = false;
  }
}

function openIncident(incident: Incident) {
  searchQuery.value = incident.client_ip;
  hostFilter.value = incident.host;
  // The route drives the parent tab bar back to the live Events view.
  const query = new URLSearchParams({
    tab: 'events',
    ip: incident.client_ip,
    host: incident.host,
  });
  void router.push(`/attacks?${query.toString()}`);
}

function openDrawer(ev: ForensicEvent) {
  activeEvent.value = ev;
  curlState.value = 'idle';
  groupStatus.value = '';
  if (!groupsLoaded.value) {
    void loadIPGroups();
  }
}

function closeDrawer() {
  activeEvent.value = null;
}

async function loadIPGroups() {
  try {
    const loader = props.ipGroupLoader ?? telemetryApi.listIPGroups;
    ipGroups.value = await loader();
    groupsLoaded.value = true;
  } catch {
    groupStatus.value = 'IP groups unavailable';
  }
}

async function handleAddToIPGroup(payload: { event: ForensicEvent; groupId: string }) {
  const group = ipGroups.value.find((g) => g.id === payload.groupId);
  const adder = props.ipGroupAdder ?? telemetryApi.addIPGroupEntry;
  groupStatus.value = 'Adding...';
  try {
    await adder(payload.groupId, payload.event.client_ip, `Forensic triage: ${payload.event.rule_id || 'WAF verdict'}`);
    groupStatus.value = `Added ${payload.event.client_ip} to ${group?.name ?? 'group'}`;
    emit('add-to-ipgroup', payload);
  } catch (err) {
    groupStatus.value = err instanceof Error ? `Add failed: ${err.message}` : 'Add failed';
  }
}

async function handleCopyCurl(ev: ForensicEvent) {
  curlState.value = 'loading';
  try {
    const loader = props.curlLoader ?? telemetryApi.getEventCurl;
    const res = await loader(ev.event_id);
    await navigator.clipboard.writeText(res.curl);
    curlState.value = 'copied';
  } catch {
    curlState.value = 'error';
  }
}

function handleCreateException(ev: ForensicEvent) {
  const cleanPath = ev.path.split('?')[0];
  const draft: ExceptionDraft = {
    host: ev.host || '*',
    path: cleanPath,
    method: ev.method,
    location: ev.payload_location
      ? ev.payload_location.toLowerCase()
      : ev.method === 'GET'
        ? 'query'
        : 'body',
    param: '*',
    rule_id: ev.rule_id || '*',
  };
  emit('create-exception', draft);
  closeDrawer();
}
</script>

<template>
  <div class="flex flex-col h-full bg-card text-card-foreground rounded-xl border border-border overflow-hidden font-sans">
    <InspectorToolbar
      :view="activeView"
      :search-query="searchQuery"
      :host-filter="hostFilter"
      :selected-action="selectedAction"
      :is-connected="isConnected"
      :event-count="filteredEvents.length"
      :incident-count="incidentsTotal"
      @update:search-query="searchQuery = $event"
      @update:host-filter="hostFilter = $event"
      @update:selected-action="selectedAction = $event"
      @refresh-incidents="loadIncidents"
    />

    <!-- Active view -->
    <IncidentCardList
      v-if="activeView === 'incidents'"
      :incidents="incidents"
      :loading="incidentsLoading"
      :error="incidentsError"
      @open="openIncident"
      @refresh="loadIncidents"
    />
    <ForensicEventTable
      v-else
      :events="filteredEvents"
      @inspect="openDrawer"
      @create-exception="handleCreateException"
    />

    <!-- Full-height forensic drawer -->
    <ForensicDrawer
      v-if="activeEvent"
      :event="activeEvent"
      :curl-state="curlState"
      :groups="ipGroups"
      :group-status="groupStatus"
      @close="closeDrawer"
      @copy-curl="handleCopyCurl"
      @create-exception="handleCreateException(activeEvent)"
      @add-to-ipgroup="handleAddToIPGroup"
    />
  </div>
</template>
