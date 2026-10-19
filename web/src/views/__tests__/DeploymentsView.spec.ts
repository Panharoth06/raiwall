import { describe, it, expect, beforeEach, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import { setActivePinia, createPinia } from 'pinia';
import DeploymentsView from '../DeploymentsView.vue';
import { useConfigStore } from '@/stores/config';

describe('DeploymentsView.vue', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    vi.restoreAllMocks();
  });

  it('renders active version and diffs correctly', async () => {
    const store = useConfigStore();
    store.cluster = {
      mode: 'cluster',
      redis_connected: true,
      active_version: 42,
      channel: 'test',
    };
    store.diffs = [
      {
        type: 'exception',
        action: 'added',
        name: 'Search SQLi Bypass',
        details: 'path=/search param=q',
      },
    ];

    const wrapper = mount(DeploymentsView);

    expect(wrapper.text()).toContain('v42');
    expect(wrapper.text()).toContain('Deploy 1 Changes');
    expect(wrapper.text()).toContain('Search SQLi Bypass');
    expect(wrapper.text()).toContain('path=/search param=q');
  });

  it('renders snapshot history and 1-click rollback buttons', async () => {
    const store = useConfigStore();
    store.cluster = {
      mode: 'standalone',
      redis_connected: false,
      active_version: 2,
      channel: '',
    };
    store.history = [
      {
        version: 2,
        author: 'admin',
        description: 'Current live',
        applied_at: new Date().toISOString(),
        hash: 'hash2',
      },
      {
        version: 1,
        author: 'admin',
        description: 'Previous version',
        applied_at: new Date().toISOString(),
        hash: 'hash1',
      },
    ];

    const wrapper = mount(DeploymentsView);

    expect(wrapper.text()).toContain('v2');
    expect(wrapper.text()).toContain('Active');
    expect(wrapper.text()).toContain('v1');
    expect(wrapper.text()).toContain('1-Click Rollback');
  });
});
