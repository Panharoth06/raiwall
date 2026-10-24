<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { useRoute, useRouter } from '@/router';
import LiveInspector from '@/components/LiveInspector.vue';
import LogsViewer from '@/components/LogsViewer.vue';
import { Radio, ScrollText } from 'lucide-vue-next';
import { Tabs, type Tab } from '@/components/ui/tabs';
import type { ExceptionDraft } from '@/types/telemetry';

type AttackSubTab = 'events' | 'logs';

const route = useRoute();
const router = useRouter();

const isSubTab = (tab: unknown): tab is AttackSubTab =>
  tab === 'events' || tab === 'logs';

const getInitialTab = (): AttackSubTab => {
  const query = route.value?.query;
  if (isSubTab(query?.tab)) return query.tab;
  return 'events';
};

const activeTab = ref<AttackSubTab>(getInitialTab());

watch(
  () => route.value?.query?.tab,
  (newTab) => {
    if (isSubTab(newTab)) {
      activeTab.value = newTab;
    }
  }
);

const tabs: (Tab & { id: AttackSubTab })[] = [
  {
    id: 'events',
    label: 'Events',
    icon: Radio,
    description: 'Real-time telemetry event stream',
    testId: 'tab-events',
  },
  {
    id: 'logs',
    label: 'Logs',
    icon: ScrollText,
    description: 'Historical forensic security logs',
    testId: 'tab-logs',
  },
];

function handleTabChange(tabId: string) {
  if (!isSubTab(tabId)) return;
  activeTab.value = tabId;
  const query = new URLSearchParams(route.value?.query ?? {});
  query.set('tab', tabId);
  query.delete('view');
  router.push(`/attacks?${query.toString()}`);
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
    <!-- Sub-tab switcher: Events and Logs -->
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
        view="events"
        @update:view="handleTabChange"
        @create-exception="handleCreateException"
      />
      <LogsViewer
        v-else
        @create-exception="handleCreateException"
      />
    </div>
  </div>
</template>
