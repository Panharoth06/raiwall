import { describe, it, expect, beforeEach, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import { setActivePinia, createPinia } from 'pinia';
import { nextTick } from 'vue';
import RulesView from '../RulesView.vue';
import { useConfigStore } from '@/stores/config';

class MockResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

beforeEach(() => {
  setActivePinia(createPinia());
  vi.restoreAllMocks();
  global.ResizeObserver = MockResizeObserver as unknown as typeof ResizeObserver;
});

describe('RulesView.vue', () => {
  it('renders Tabs with all three rule sub-tabs and defaults to exceptions', () => {
    const store = useConfigStore();
    store.exceptions = [];
    store.acls = [];

    const wrapper = mount(RulesView, {
      global: {
        stubs: {
          ExceptionsView: { template: '<div data-testid="exceptions-subview">Exceptions SubView</div>' },
          ACLsView: { template: '<div data-testid="acls-subview">ACLs SubView</div>' },
          PoliciesView: { template: '<div data-testid="policies-subview">Policies SubView</div>' },
        },
      },
    });

    const tabItems = wrapper.findAll('[data-testid="tab-item"]');
    expect(tabItems.length).toBe(3);
    expect(tabItems[0].text()).toContain('Exceptions Gate');
    expect(tabItems[1].text()).toContain('ACL Bytecode Rules');
    expect(tabItems[2].text()).toContain('Defense Policies');

    expect(wrapper.find('[data-testid="exceptions-subview"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="acls-subview"]').exists()).toBe(false);
  })

  it('switches sub-views when clicking tabs', async () => {
    const store = useConfigStore();
    store.exceptions = [];
    store.acls = [];

    const wrapper = mount(RulesView, {
      global: {
        stubs: {
          ExceptionsView: { template: '<div data-testid="exceptions-subview">Exceptions SubView</div>' },
          ACLsView: { template: '<div data-testid="acls-subview">ACLs SubView</div>' },
          PoliciesView: { template: '<div data-testid="policies-subview">Policies SubView</div>' },
        },
      },
    });

    const tabItems = wrapper.findAll('[data-testid="tab-item"]');

    // Click ACL Bytecode Rules tab
    await tabItems[1].trigger('click');
    await nextTick();

    expect(wrapper.find('[data-testid="exceptions-subview"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="acls-subview"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="policies-subview"]').exists()).toBe(false);

    // Click Defense Policies tab
    await tabItems[2].trigger('click');
    await nextTick();

    expect(wrapper.find('[data-testid="policies-subview"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="acls-subview"]').exists()).toBe(false);
  });
});
