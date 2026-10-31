<script setup lang="ts">
import { computed } from 'vue';
import { useRoute, useRouter } from '@/router';
import { Tabs, type Tab } from '@/components/ui/tabs';
import { Braces, FlaskConical, Gauge, ListChecks, Package, ShieldOff } from 'lucide-vue-next';

const route = useRoute();
const router = useRouter();

const tabs: Tab[] = [
  { id: '/detection', label: 'Overview', icon: Gauge, badge: 'Protection Center', testId: 'detection-tab-overview' },
  { id: '/detection/rules', label: 'Rule Catalog', icon: ListChecks, badge: '87 CVEs', testId: 'detection-tab-rules' },
  { id: '/detection/packs', label: 'Rule Packs', icon: Package, badge: 'Plugins', testId: 'detection-tab-packs' },
  { id: '/detection/modules', label: 'Semantic Matrix', icon: Braces, badge: '14 AST', testId: 'detection-tab-modules' },
  { id: '/detection/exceptions', label: 'Exceptions', icon: ShieldOff, badge: 'Bypasses', testId: 'detection-tab-exceptions' },
  { id: '/detection/tester', label: 'Rule Tester', icon: FlaskConical, badge: 'Simulator', testId: 'detection-tab-tester' },
];

const activeTab = computed(() => {
  const path = route.value.path || '';
  if (path.startsWith('/detection/rules') || path.startsWith('/inner-rules')) return '/detection/rules';
  if (path.startsWith('/detection/packs')) return '/detection/packs';
  if (path.startsWith('/detection/modules') || path === '/semantics') return '/detection/modules';
  if (path.startsWith('/detection/exceptions') || path === '/exceptions') return '/detection/exceptions';
  if (path.startsWith('/detection/tester')) return '/detection/tester';
  return '/detection';
});

const navigate = (tabId: string) => {
  router.push(tabId);
};
</script>

<template>
  <nav class="border-b border-border pb-1.5 shrink-0 overflow-x-auto" aria-label="Detection sections">
    <Tabs :tabs="tabs" :active-tab="activeTab" class="min-w-max" @tab-change="navigate">
      <template #tab="{ tab }">
        <span class="flex items-center gap-1.5">
          <span>{{ tab.label }}</span>
          <span
            v-if="tab.badge"
            class="px-1.5 py-0.5 rounded text-xs font-mono font-normal tracking-tight hidden sm:inline"
            :class="tab.id === activeTab ? 'bg-primary/15 text-primary' : 'bg-muted text-muted-foreground'"
          >
            {{ tab.badge }}
          </span>
        </span>
      </template>
    </Tabs>
  </nav>
</template>
