import { describe, it, expect, beforeEach, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import { setActivePinia, createPinia } from 'pinia';
import SitesView from '../SitesView.vue';
import { useConfigStore } from '@/stores/config';

describe('SitesView.vue', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    vi.restoreAllMocks();
  });

  it('renders sites table with data from store', async () => {
    const store = useConfigStore();
    store.sites = [
      {
        id: 'site-1',
        name: 'Primary API',
        hostnames: ['api.example.com', 'edge.example.com'],
        mode: 'defense',
        upstreams: [
          { dial: '10.0.0.1:8080', weight: 1 },
          { dial: '10.0.0.2:8080', weight: 2 },
        ],
        block_status_code: 403,
        offline_status_code: 503,
      },
    ];

    const wrapper = mount(SitesView);

    expect(wrapper.text()).toContain('Primary API');
    expect(wrapper.text()).toContain('api.example.com');
    expect(wrapper.text()).toContain('Defense');
    expect(wrapper.text()).toContain('2 targets');
  });

  it('shows empty state when no sites are configured', async () => {
    const store = useConfigStore();
    store.sites = [];

    const wrapper = mount(SitesView);
    expect(wrapper.text()).toContain('No protected sites configured');
  });
});
