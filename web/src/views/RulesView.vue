<script setup lang="ts">
import { ref, watch } from 'vue';
import { useRoute, useRouter } from '@/router';
import ExceptionsView from './ExceptionsView.vue';
import ACLsView from './ACLsView.vue';
import RateLimitingSettings from '@/components/http-flood/RateLimitingSettings.vue';
import { Shield, FileCode, Sliders } from 'lucide-vue-next';
import { Tabs, type Tab } from '@/components/ui/tabs';

type RuleSubTab = 'exceptions' | 'acls' | 'policies';

const route = useRoute();
const router = useRouter();

const getInitialTab = (): RuleSubTab => {
  const tab = route.value?.query?.tab;
  if (tab === 'acls' || tab === 'policies' || tab === 'exceptions') {
    return tab;
  }
  const path = route.value?.path || '';
  if (path.includes('acls')) return 'acls';
  if (path.includes('policies')) return 'policies';
  return 'exceptions';
};

const activeTab = ref<RuleSubTab>(getInitialTab());

watch(
  () => [route.value?.path, route.value?.query?.tab],
  ([newPath, newTab]) => {
    if (newTab === 'acls' || newTab === 'policies' || newTab === 'exceptions') {
      activeTab.value = newTab as RuleSubTab;
      return;
    }
    if (!newPath) return;
    if (newPath.includes('acls') && activeTab.value !== 'acls') {
      activeTab.value = 'acls';
    } else if (newPath.includes('policies') && activeTab.value !== 'policies') {
      activeTab.value = 'policies';
    } else if ((newPath.includes('exceptions') || newPath.includes('rules')) && activeTab.value !== 'exceptions') {
      activeTab.value = 'exceptions';
    }
  }
);

const tabs: (Tab & { id: RuleSubTab })[] = [
  { id: 'exceptions', label: 'Exceptions Gate', icon: Shield, description: 'Parameter-level false-positive bypasses' },
  { id: 'acls', label: 'ACL Bytecode Rules', icon: FileCode, description: 'Sub-15ns expr-lang boolean ACLs' },
  { id: 'policies', label: 'Rate Limits', icon: Sliders, description: 'Three-tier velocity, attack, and scanner limits' },
];

const handleTabChange = (tabId: string) => {
  activeTab.value = tabId as RuleSubTab;
  router.push(`/rules?tab=${tabId}`);
};
</script>

<template>
  <div class="h-full flex flex-col space-y-4 font-sans">
    <!-- Sub-tab switcher -->
    <div class="border-b border-border pb-1.5 shrink-0">
      <Tabs
        :tabs="tabs"
        :active-tab="activeTab"
        @tab-change="handleTabChange"
      />
    </div>

    <!-- Active Sub-View with inner scrolling -->
    <div class="flex-1 min-h-0 overflow-y-auto pr-1">
      <ExceptionsView v-if="activeTab === 'exceptions'" />
      <ACLsView v-else-if="activeTab === 'acls'" />
      <RateLimitingSettings v-else-if="activeTab === 'policies'" />
    </div>
  </div>
</template>
