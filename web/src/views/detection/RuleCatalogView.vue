<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import type { DetectionRule, RuleFilters, RuleOverride } from '@/api/detection';
import { useAuthStore } from '@/stores/auth';
import { useDetectionRules } from '@/composables/useDetectionRules';
import { Button } from '@/components/ui/button';
import { EmptyState } from '@/components/ui/empty-state';
import AdminOnly from '@/components/auth/AdminOnly.vue';
import DetectionHeroBanner from '@/components/detection/DetectionHeroBanner.vue';
import { useHeroBanner } from '@/components/detection/useHeroBanner';
import DetectionPageHeader from '@/components/detection/DetectionPageHeader.vue';
import DetectionFilterBar from '@/components/detection/DetectionFilterBar.vue';
import RuleCatalogTable from '@/components/detection/RuleCatalogTable.vue';
import RuleDetailDialog from '@/components/detection/RuleDetailDialog.vue';
import RulePackImportModal from '@/components/detection/RulePackImportModal.vue';
import { TablePagination } from '@/components/ui/table-pagination';
import { HelpCircle, ListChecks, RefreshCw, ShieldCheck, Upload } from 'lucide-vue-next';

const auth = useAuthStore();
const canEdit = computed(() => auth.user?.role !== 'viewer');

const { showHero, toggleHero, dismissHero } = useHeroBanner('detection-rules');

const {
  rules,
  facets,
  total,
  loading,
  saving,
  error,
  offset,
  limit,
  filters,
  pending,
  load,
  updateRule,
  resetRule,
  bulkUpdate,
  setPage,
  setLimit,
} = useDetectionRules();

const selected = ref<Set<string>>(new Set());
const detailOpen = ref(false);
const detailRule = ref<DetectionRule | null>(null);
const showImport = ref(false);

const setFilters = (next: RuleFilters) => {
  Object.assign(filters, next);
};

const select = (id: string, checked: boolean) => {
  const next = new Set(selected.value);
  if (checked) next.add(id);
  else next.delete(id);
  selected.value = next;
};

const selectAll = (checked: boolean) => {
  selected.value = checked ? new Set(rules.value.map((rule) => rule.id)) : new Set();
};

const toggle = (rule: DetectionRule, enabled: boolean) => {
  updateRule(rule, { enabled });
};

const changeAction = (rule: DetectionRule, action: string) => {
  updateRule(rule, { action });
};

const openDetail = (rule: DetectionRule) => {
  detailRule.value = rule;
  detailOpen.value = true;
};

const saveDetail = async (rule: DetectionRule, override: RuleOverride) => {
  await updateRule(rule, override);
  detailOpen.value = false;
};

const resetDetail = async (rule: DetectionRule) => {
  await resetRule(rule);
  detailOpen.value = false;
};

const bulk = (override: RuleOverride) => {
  bulkUpdate(Array.from(selected.value), override);
  selected.value = new Set();
};

const clearFilters = () => {
  setFilters({ q: '', source: '', category: '', severity: '', enabled: '' });
};

const onImportSaved = () => {
  showImport.value = false;
  load();
};

onMounted(load);
</script>

<template>
  <div class="space-y-4 font-sans flex flex-col h-full min-h-0">
    <DetectionPageHeader
      title="Rule Catalog"
      description="Every detection unit in one place: semantic modules, virtual patches, and imported packs."
      :icon="ListChecks"
      class="shrink-0"
    >
      <template #actions>
        <Button
          size="sm"
          variant="outline"
          class="h-8 text-xs gap-1.5"
          :data-testid="'hero-toggle-rules'"
          @click="toggleHero"
        >
          <HelpCircle class="w-3.5 h-3.5 text-primary" />
          <span>{{ showHero ? 'Hide Guide' : 'Explain feature' }}</span>
        </Button>
        <AdminOnly>
          <Button size="sm" class="h-8 text-xs gap-1.5" @click="showImport = true">
            <Upload class="w-3.5 h-3.5" />
            <span>Import pack</span>
          </Button>
        </AdminOnly>
        <Button size="sm" variant="outline" class="h-8 text-xs gap-1.5" :disabled="loading" @click="load">
          <RefreshCw class="w-3.5 h-3.5" :class="loading ? 'animate-spin' : ''" />
          <span>Refresh</span>
        </Button>
      </template>
    </DetectionPageHeader>

    <!-- Prominent Hero Section with Low-Opacity Background Icon -->
    <DetectionHeroBanner
      storage-key="detection-rules"
      title="CVE Virtual Patching & Signature Catalog"
      badge="VIRTUAL PATCHES"
      description="Virtual patches stop known software vulnerabilities (CVEs) directly at the gateway before exploit payloads can reach your backend applications. Even if your upstream servers haven't applied the vendor patch yet, Raiwall intercepts attacks targeting Spring, Log4j, WebLogic, Apache, Shiro, and WordPress. You can also import custom CVEs or CRS bundles from Rule Packs."
      :icon="ListChecks"
      :highlights="[
        { label: 'Zero-Day Protection', text: 'Shields vulnerable backend apps from active in-the-wild exploit campaigns.' },
        { label: '87 Built-in Patches', text: 'Pre-compiled and tuned to run ahead of the deep semantic AST funnel.' },
        { label: 'Granular Toggles', text: 'Enable, disable, or set individual CVEs to audit-only mode per environment.' },
      ]"
      v-model:open="showHero"
      @dismiss="dismissHero"
      class="shrink-0"
    />

    <div
      v-if="error"
      class="flex items-center justify-between gap-3 rounded-md border border-threat/30 bg-threat/10 px-3 py-2 text-xs text-threat shrink-0"
      data-testid="catalog-error"
    >
      <span class="truncate">{{ error }}</span>
      <Button size="sm" variant="outline" class="h-7 text-xs shrink-0" @click="load">Retry</Button>
    </div>

    <!-- Filter Bar -->
    <div class="shrink-0">
      <DetectionFilterBar :facets="facets" :filters="filters" @update:filters="setFilters" />
    </div>

    <!-- Bulk Action Strip -->
    <div
      v-if="selected.size > 0"
      class="flex flex-wrap items-center gap-2 rounded-md border border-border bg-muted/40 px-3 py-2 shrink-0"
      data-testid="catalog-bulk-bar"
    >
      <span class="text-xs font-mono text-foreground font-semibold">{{ selected.size }} selected</span>
      <AdminOnly>
        <div class="flex items-center gap-1.5 flex-wrap">
          <Button size="sm" variant="outline" class="h-7 text-xs" :disabled="saving" @click="bulk({ enabled: true })">
            Enable
          </Button>
          <Button size="sm" variant="outline" class="h-7 text-xs" :disabled="saving" @click="bulk({ enabled: false })">
            Disable
          </Button>
          <Button size="sm" variant="outline" class="h-7 text-xs" :disabled="saving" @click="bulk({ action: 'alert' })">
            Alert only
          </Button>
          <Button size="sm" variant="outline" class="h-7 text-xs" :disabled="saving" @click="bulk({ action: 'block' })">
            Block
          </Button>
        </div>
      </AdminOnly>
      <Button size="sm" variant="ghost" class="h-7 text-xs ml-auto" @click="selected = new Set()">
        Clear selection
      </Button>
    </div>

    <!-- Skeletons -->
    <div v-if="loading" class="space-y-2 shrink-0" data-testid="catalog-loading">
      <div v-for="n in 8" :key="n" class="h-9 rounded-md bg-muted/50 animate-pulse" />
    </div>

    <!-- Empty State -->
    <div v-else-if="rules.length === 0" class="rounded-lg border border-border bg-card p-6 shrink-0">
      <EmptyState
        :icon="ListChecks"
        title="No rules match the current filters"
        description="Clear the search and facet filters to see the full catalog."
      >
        <Button size="sm" variant="outline" class="h-8 text-xs" @click="clearFilters">
          Clear filters
        </Button>
      </EmptyState>
    </div>

    <!-- Responsive Table Card: Bounded viewport with internal vertical scrolling and sticky header -->
    <template v-else>
      <div class="grow min-h-0 flex flex-col rounded-lg border border-border bg-card overflow-hidden">
        <div class="grow min-h-0 overflow-y-auto">
          <RuleCatalogTable
            :rules="rules"
            :pending="pending"
            :can-edit="canEdit"
            :selected="selected"
            @select="select"
            @select-all="selectAll"
            @toggle="toggle"
            @action="changeAction"
            @open="openDetail"
          />
        </div>

        <!-- Sticky Footer Pagination docked inside the table card -->
        <TablePagination
          :page="Math.floor(offset / limit) + 1"
          :page-size="limit"
          :total="total"
          :page-size-options="[10, 20, 50, 100]"
          :disabled="loading"
          item-label="rules"
          @update:page="(p) => setPage((p - 1) * limit)"
          @update:page-size="(s) => setLimit(s)"
        />
      </div>
    </template>

    <RuleDetailDialog
      :open="detailOpen"
      :rule="detailRule"
      :saving="saving"
      @close="detailOpen = false"
      @save="saveDetail"
      @reset="resetDetail"
    />

    <RulePackImportModal :open="showImport" @close="showImport = false" @saved="onImportSaved" />
  </div>
</template>
