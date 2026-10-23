import { describe, it, expect, beforeEach, vi } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createPinia, setActivePinia } from 'pinia';
import SemanticsView from '../SemanticsView.vue';
import { semanticsApi, type DetectorMatrix } from '@/api/semantics';

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

function fakeModule(module: string) {
  return {
    module,
    name: `${module} engine`,
    category: 'injection',
    description: 'detects injection attempts',
    mode: 'balance' as const,
  };
}

const matrix: DetectorMatrix = {
  modules: [
    fakeModule('sql_inj'),
    fakeModule('xss'),
    { ...fakeModule('file_upload'), mode: 'disabled' as const },
  ],
  apps: [],
};

describe('SemanticsView.vue (Task 82)', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    vi.restoreAllMocks();
    vi.mocked(semanticsApi.getMatrix).mockResolvedValue(matrix);
    vi.mocked(semanticsApi.setModuleMode).mockResolvedValue({ success: true });
  });

  it('renders the module matrix with a row per module', async () => {
    const wrapper = mount(SemanticsView, {
      global: { stubs: { SemanticsAppOverrides: { template: '<div />' } } },
    });
    await flushPromises();

    expect(wrapper.find('[data-testid="module-matrix"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="module-row-sql_inj"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="module-row-xss"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="module-row-file_upload"]').exists()).toBe(true);
  });

  it('marks the selected global module mode as checked', async () => {
    const wrapper = mount(SemanticsView, {
      global: { stubs: { SemanticsAppOverrides: { template: '<div />' } } },
    });
    await flushPromises();

    const row = wrapper.find('[data-testid="module-row-sql_inj"]');
    expect(row.find('[data-testid="mode-balance"]').attributes('aria-checked')).toBe('true');
  });

  it('emits setModuleMode when a stronger mode is picked', async () => {
    const wrapper = mount(SemanticsView, {
      global: { stubs: { SemanticsAppOverrides: { template: '<div />' } } },
    });
    await flushPromises();

    const strictButton = wrapper.find('[data-testid="module-row-sql_inj"] [data-testid="mode-strict"]');
    await strictButton.trigger('click');
    await flushPromises();

    expect(semanticsApi.setModuleMode).toHaveBeenCalledWith('sql_inj', 'strict');
  });

  it('reverts the optimistic mode on API failure and surfaces the error', async () => {
    vi.mocked(semanticsApi.setModuleMode).mockRejectedValue(new Error('network down'));
    const wrapper = mount(SemanticsView, {
      global: { stubs: { SemanticsAppOverrides: { template: '<div />' } } },
    });
    await flushPromises();

    const row = wrapper.find('[data-testid="module-row-xss"]');
    await row.find('[data-testid="mode-audit"]').trigger('click');
    await flushPromises();

    expect(row.find('[data-testid="mode-balance"]').text()).toContain('Balance');
    expect(wrapper.find('[data-testid="matrix-error"]').text()).toContain('network down');
  });

  it('shows a loading skeleton before the matrix resolves', () => {
    vi.mocked(semanticsApi.getMatrix).mockReturnValue(new Promise(() => undefined));
    const wrapper = mount(SemanticsView, {
      global: { stubs: { SemanticsAppOverrides: { template: '<div />' } } },
    });
    expect(wrapper.find('[data-testid="matrix-loading"]').exists()).toBe(true);
  });
});
