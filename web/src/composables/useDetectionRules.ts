import { onBeforeUnmount, reactive, ref, watch } from 'vue';
import {
  detectionApi,
  type DetectionRule,
  type RuleFacets,
  type RuleFilters,
  type RuleOverride,
} from '@/api/detection';

const emptyFacets = (): RuleFacets => ({
  sources: [],
  categories: [],
  severities: [],
  packs: [],
});

export function useDetectionRules() {
  const rules = ref<DetectionRule[]>([]);
  const facets = ref<RuleFacets>(emptyFacets());
  const total = ref(0);
  const loading = ref(true);
  const saving = ref(false);
  const error = ref('');
  const offset = ref(0);
  const limit = ref(50);
  const pending = ref<Set<string>>(new Set());
  const filters = reactive<RuleFilters>({
    q: '',
    source: '',
    category: '',
    severity: '',
    enabled: '',
  });

  let debounce: ReturnType<typeof setTimeout> | null = null;

  const load = async () => {
    loading.value = true;
    error.value = '';
    try {
      const response = await detectionApi.listRules({
        ...filters,
        offset: offset.value,
        limit: limit.value,
      });
      rules.value = response.rules;
      facets.value = response.facets;
      total.value = response.total;
    } catch (e) {
      error.value = e instanceof Error ? e.message : 'Failed to load rule catalog';
    } finally {
      loading.value = false;
    }
  };

  const scheduleLoad = () => {
    if (debounce) clearTimeout(debounce);
    debounce = setTimeout(() => {
      offset.value = 0;
      load();
    }, 250);
  };

  watch(filters, scheduleLoad, { deep: true });
  onBeforeUnmount(() => {
    if (debounce) clearTimeout(debounce);
  });

  const mark = (id: string, active: boolean) => {
    const next = new Set(pending.value);
    if (active) next.add(id);
    else next.delete(id);
    pending.value = next;
  };

  const updateRule = async (rule: DetectionRule, override: RuleOverride) => {
    mark(rule.id, true);
    saving.value = true;
    error.value = '';
    try {
      await detectionApi.updateRule(rule.id, override);
      await load();
    } catch (e) {
      error.value = e instanceof Error ? e.message : 'Failed to update rule';
    } finally {
      mark(rule.id, false);
      saving.value = false;
    }
  };

  const resetRule = async (rule: DetectionRule) => {
    mark(rule.id, true);
    saving.value = true;
    error.value = '';
    try {
      await detectionApi.resetRule(rule.id);
      await load();
    } catch (e) {
      error.value = e instanceof Error ? e.message : 'Failed to reset rule';
    } finally {
      mark(rule.id, false);
      saving.value = false;
    }
  };

  const bulkUpdate = async (ids: string[], override: RuleOverride) => {
    if (!ids.length) return;
    saving.value = true;
    error.value = '';
    try {
      await detectionApi.bulkRules(ids, override);
      await load();
    } catch (e) {
      error.value = e instanceof Error ? e.message : 'Bulk update failed';
    } finally {
      saving.value = false;
    }
  };

  const setPage = (nextOffset: number) => {
    offset.value = Math.max(0, nextOffset);
    load();
  };

  const setLimit = (newLimit: number) => {
    limit.value = newLimit;
    offset.value = 0;
    load();
  };

  return {
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
  };
}
