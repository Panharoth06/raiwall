<script setup lang="ts">
import { ref, watch } from 'vue';
import { useRoute, useRouter } from '@/router';
import LiveInspector from '@/components/LiveInspector.vue';
import LogsViewer from '@/components/LogsViewer.vue';
import { Radio, ScrollText } from 'lucide-vue-next';
import { Tabs, type Tab } from '@/components/ui/tabs';
import type { ExceptionDraft } from '@/types/telemetry';

type AttackSubTab = 'events' | 'logs';

const route = useRoute();
const router = useRouter();

const getInitialTab = (): AttackSubTab => {
  const tab = route.value?.query?.tab;
  if (tab === 'logs' || tab === 'events') {
    return tab;
  }
  return 'events';
};

const activeTab = ref<AttackSubTab>(getInitialTab());

watch(
  () => route.value?.query?.tab,
  (newTab) => {
    if (newTab === 'logs' || newTab === 'events') {
      activeTab.value = newTab;
    }
  }
);

const tabs: (Tab & { id: AttackSubTab })[] = [
  { id: 'events', label: 'Events', icon: Radio, description: 'Real-time telemetry event stream' },
  { id: 'logs', label: 'Logs', icon: ScrollText, description: 'Historical forensic security logs' },
];

function handleTabChange(tabId: string) {
  activeTab.value = tabId as AttackSubTab;
  router.push(`/attacks?tab=${tabId}`);
}

function handleCreateException(draft: ExceptionDraft) {
  const query = new URLSearchParams({
    create: 'true',
    host: draft.host || '*',
    path: draft.path || '/',
    method: draft.method || 'ALL',
    location: draft.location || 'query',
    param: draft.param || '*',
    rule_id: draft.rule_id || 'ALL',
  });
  router.push(`/exceptions?${query.toString()}`);
}
</script>

<template>
  <div class="h-full w-full flex flex-col space-y-4 font-sans">
    <!-- Sub-tab switcher: 2 options (Events and Logs) -->
    <div class="border-b border-border pb-1.5 shrink-0">
      <Tabs
        :tabs="tabs"
        :active-tab="activeTab"
        @tab-change="handleTabChange"
      />
    </div>

    <!-- Active View -->
    <div class="flex-1 min-h-0">
      <LiveInspector
        v-if="activeTab === 'events'"
        @create-exception="handleCreateException"
      />
      <LogsViewer
        v-else-if="activeTab === 'logs'"
        @create-exception="handleCreateException"
      />
    </div>
  </div>
</template>
