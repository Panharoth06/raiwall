import { describe, it, expect, beforeEach, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import { setActivePinia, createPinia } from 'pinia';
import { nextTick } from 'vue';
import SettingsView from '../SettingsView.vue';
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

describe('SettingsView.vue', () => {
  it('renders Tabs with cluster and apikeys sub-tabs and defaults to cluster', () => {
    const store = useConfigStore();
    store.cluster = {
      mode: 'cluster',
      redis_connected: true,
      active_version: 3,
      channel: 'test',
    };

    const wrapper = mount(SettingsView, {
      global: {
        stubs: {
          ApiKeysManager: { template: '<div data-testid="apikeys-subview">API Keys Manager</div>' },
        },
      },
    });

    const tabItems = wrapper.findAll('[data-testid="tab-item"]');
    expect(tabItems.length).toBe(2);
    expect(tabItems[0].text()).toContain('Cluster Synchronization');
    expect(tabItems[1].text()).toContain('API Keys & Access');

    expect(wrapper.text()).toContain('Cluster Node & State Synchronization');
    expect(wrapper.find('[data-testid="apikeys-subview"]').exists()).toBe(false);
  });

  it('switches to API keys tab when clicking the second tab', async () => {
    const store = useConfigStore();
    store.cluster = {
      mode: 'standalone',
      redis_connected: false,
      active_version: 1,
      channel: '',
    };

    const wrapper = mount(SettingsView, {
      global: {
        stubs: {
          ApiKeysManager: { template: '<div data-testid="apikeys-subview">API Keys Manager</div>' },
        },
      },
    });

    const tabItems = wrapper.findAll('[data-testid="tab-item"]');
    await tabItems[1].trigger('click');
    await nextTick();

    expect(wrapper.find('[data-testid="apikeys-subview"]').exists()).toBe(true);
    expect(wrapper.text()).not.toContain('Cluster Node & State Synchronization');

    await tabItems[0].trigger('click');
    await nextTick();

    expect(wrapper.find('[data-testid="apikeys-subview"]').exists()).toBe(false);
    expect(wrapper.text()).toContain('Cluster Node & State Synchronization');
  });
});
