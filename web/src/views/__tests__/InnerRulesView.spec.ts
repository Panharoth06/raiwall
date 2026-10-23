import { describe, it, expect, beforeEach, vi } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createPinia, setActivePinia } from 'pinia';
import InnerRulesView from '../InnerRulesView.vue';
import { semanticsApi, type InnerRulesLibrary } from '@/api/semantics';

vi.mock('@/api/semantics', () => ({
  semanticsApi: {
    getMatrix: vi.fn(),
    setModuleMode: vi.fn(),
    getAppPolicy: vi.fn(),
    setAppPolicy: vi.fn(),
    listInnerRules: vi.fn(),
    setInnerRuleEnabled: vi.fn(),
    setInnerRuleCategoryEnabled: vi.fn(),
  },
}));

const library: InnerRulesLibrary = {
  rules: [
    { id: 'CVE-2021-44228', name: 'Log4Shell JNDI RCE', category: 'rce', enabled: true },
    { id: 'CVE-2022-22965', name: 'Spring4Shell RCE', category: 'rce', enabled: true },
    { id: 'GIT-CONFIG-EXPOSURE', name: 'Git config disclosure', category: 'info-disclosure', enabled: false },
    { id: 'GENERIC-ENCODED-TRAVERSAL', name: 'Encoded traversal probe', category: 'file-inclusion', enabled: true },
  ],
  categories: [
    { category: 'rce', count: 2, disabled: 0 },
    { category: 'info-disclosure', count: 1, disabled: 1 },
    { category: 'file-inclusion', count: 1, disabled: 0 },
  ],
};

function findRow(wrapper: ReturnType<typeof mount>, ruleID: string) {
  return wrapper.find(`[data-testid="rule-row-${ruleID}"]`);
}

const switchStub = {
  props: ['checked'],
  emits: ['update:checked'],
  template: `<button data-testid="stub-switch" :data-checked="String(checked)" @click="$emit('update:checked', !checked)" />`,
};

const mountView = () =>
  mount(InnerRulesView, {
    global: { stubs: { Switch: switchStub } },
  });

describe('InnerRulesView.vue (Task 82)', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    vi.restoreAllMocks();
    // Deep-copy the library per test: the view mutates rule entries optimistically.
    vi.mocked(semanticsApi.listInnerRules).mockResolvedValue(JSON.parse(JSON.stringify(library)));
    vi.mocked(semanticsApi.setInnerRuleEnabled).mockResolvedValue({ success: true });
    vi.mocked(semanticsApi.setInnerRuleCategoryEnabled).mockResolvedValue({ success: true, count: 2 });
  });

  it('lists all bundled signatures with CVE tags', async () => {
    const wrapper = mountView();
    await flushPromises();

    expect(wrapper.find('[data-testid="rule-row-CVE-2021-44228"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="rule-row-GIT-CONFIG-EXPOSURE"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="rule-summary"]').text()).toContain('3 of 4');
  });

  it('filters through search on rule ID and name', async () => {
    const wrapper = mountView();
    await flushPromises();

    const searchBox = wrapper.find('[data-testid="rule-search"]');
    await searchBox.setValue('log4shell');
    expect(findRow(wrapper, 'CVE-2021-44228').exists()).toBe(true);
    expect(findRow(wrapper, 'CVE-2022-22965').exists()).toBe(false);

    await searchBox.setValue('spring4shell');
    expect(findRow(wrapper, 'CVE-2022-22965').exists()).toBe(true);
    expect(findRow(wrapper, 'CVE-2021-44228').exists()).toBe(false);
  });

  it('narrows the table with category filter chips', async () => {
    const wrapper = mountView();
    await flushPromises();

    await wrapper.find('[data-testid="category-chip-rce"]').trigger('click');
    expect(findRow(wrapper, 'CVE-2021-44228').exists()).toBe(true);
    expect(findRow(wrapper, 'GIT-CONFIG-EXPOSURE').exists()).toBe(false);
    // Category batch controls appear for the active filter.
    expect(wrapper.find('[data-testid="batch-disable-category"]').exists()).toBe(true);
  });

  it('emits setInnerRuleEnabled when a signature is toggled', async () => {
    const wrapper = mountView();
    await flushPromises();

    await findRow(wrapper, 'CVE-2021-44228').find('button[data-testid="rule-toggle-CVE-2021-44228"]').trigger('click');
    await flushPromises();

    expect(semanticsApi.setInnerRuleEnabled).toHaveBeenCalledWith('CVE-2021-44228', false);
  });

  it('batch-disables the active category in one mutation', async () => {
    const wrapper = mountView();
    await flushPromises();

    await wrapper.find('[data-testid="category-chip-rce"]').trigger('click');
    await wrapper.find('[data-testid="batch-disable-category"]').trigger('click');
    await flushPromises();

    expect(semanticsApi.setInnerRuleCategoryEnabled).toHaveBeenCalledWith('rce', false);
    const toggledOff = wrapper
      .findAll('button[data-testid^="rule-toggle-"]')
      .filter((s) => s.attributes('data-checked') === 'false');
    // Both rce rules now report enabled=false.
    expect(toggledOff.length).toBeGreaterThanOrEqual(2);
  });

  it('batch enable-all re-enables every disabled signature across categories', async () => {
    const wrapper = mountView();
    await flushPromises();

    await wrapper.find('[data-testid="batch-enable-all"]').trigger('click');
    await flushPromises();

    expect(semanticsApi.setInnerRuleCategoryEnabled).toHaveBeenCalledTimes(3);
    expect(wrapper.find('[data-testid="rule-summary"]').text()).toContain('4 of 4');
  });
});
