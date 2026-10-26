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
  const stubs = {
    ApiKeysManager: { template: '<div data-testid="apikeys-subview">API Keys Manager</div>' },
    CertificatesPanel: { template: '<div data-testid="certificates-subview">Certificates</div>' },
  };

  it('renders cluster, certificates, and apikeys sub-tabs and defaults to cluster', () => {
    const store = useConfigStore();
    store.cluster = {
      mode: 'cluster',
      redis_connected: true,
      active_version: 3,
      channel: 'test',
    };

    const wrapper = mount(SettingsView, {
      global: { stubs },
    });

    const tabItems = wrapper.findAll('[data-testid="tab-item"]');
    expect(tabItems.length).toBe(3);
    expect(tabItems[0].text()).toContain('Cluster Synchronization');
    expect(tabItems[1].text()).toContain('TLS Certificates');
    expect(tabItems[2].text()).toContain('API Keys & Access');

    expect(wrapper.text()).toContain('Cluster Node & State Synchronization');
    expect(wrapper.find('[data-testid="apikeys-subview"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="certificates-subview"]').exists()).toBe(false);
  });

  it('switches to the certificates tab', async () => {
    const wrapper = mount(SettingsView, { global: { stubs } });

    const tabItems = wrapper.findAll('[data-testid="tab-item"]');
    await tabItems[1].trigger('click');
    await nextTick();

    expect(wrapper.find('[data-testid="certificates-subview"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="apikeys-subview"]').exists()).toBe(false);
  });

  it('switches to API keys tab when clicking the third tab', async () => {
    const store = useConfigStore();
    store.cluster = {
      mode: 'standalone',
      redis_connected: false,
      active_version: 1,
      channel: '',
    };

    const wrapper = mount(SettingsView, {
      global: { stubs },
    });

    const tabItems = wrapper.findAll('[data-testid="tab-item"]');
    await tabItems[2].trigger('click');
    await nextTick();

    expect(wrapper.find('[data-testid="apikeys-subview"]').exists()).toBe(true);
    expect(wrapper.text()).not.toContain('Cluster Node & State Synchronization');

    await tabItems[0].trigger('click');
    await nextTick();

    expect(wrapper.find('[data-testid="apikeys-subview"]').exists()).toBe(false);
    expect(wrapper.text()).toContain('Cluster Node & State Synchronization');
  });
});
