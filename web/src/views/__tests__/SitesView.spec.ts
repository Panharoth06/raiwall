import { describe, it, expect, beforeEach, vi } from 'vitest';
import { flushPromises, mount } from '@vue/test-utils';
import { setActivePinia, createPinia } from 'pinia';
import SitesView from '../SitesView.vue';
import { useConfigStore } from '@/stores/config';
import { api } from '@/api/client';

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

  it('renders architecture routing and TLS columns', () => {
    const store = useConfigStore();
    store.sites = [
      {
        id: 'site-1',
        name: 'Docs Portal',
        hostnames: ['docs.example.com'],
        mode: 'defense',
        ports: [{ port: 443, scheme: 'https' }],
        ssl_mode: 'manual',
        certificate_id: 'cert-1',
        routing_type: 'static',
        document_root: '/srv/docs',
        load_balancing: 'round_robin',
        upstreams: [],
        block_status_code: 403,
        offline_status_code: 503,
      },
      {
        id: 'site-2',
        name: 'Legacy Redirect',
        hostnames: ['old.example.com'],
        mode: 'audit',
        ports: [{ port: 80, scheme: 'http' }],
        ssl_mode: 'none',
        routing_type: 'redirect',
        redirect_url: 'https://example.com/new',
        redirect_status: 308,
        load_balancing: 'round_robin',
        upstreams: [],
        block_status_code: 403,
        offline_status_code: 503,
      },
    ];
    store.certificates = [
      {
        id: 'cert-1',
        name: 'docs cert',
        domains: ['docs.example.com'],
        source: 'self_signed',
        auto_renew: true,
        status: 'valid',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
      },
    ];

    const wrapper = mount(SitesView);

    expect(wrapper.text()).toContain('Static Files');
    expect(wrapper.text()).toContain('/srv/docs');
    expect(wrapper.text()).toContain('docs cert');
    expect(wrapper.text()).toContain('Redirect');
    expect(wrapper.text()).toContain('308');
  });

  it('shows the pending banner and applies the draft', async () => {
    const store = useConfigStore();
    store.sites = [];
    store.diffs = [
      { type: 'site', action: 'added', name: 'New Site', details: 'Site created' },
    ];
    vi.spyOn(api, 'getDraftDiff').mockResolvedValue({ has_changes: false, diffs: [] });
    vi.spyOn(api, 'listSites').mockResolvedValue([]);
    vi.spyOn(api, 'listExceptions').mockResolvedValue([]);
    vi.spyOn(api, 'listACLs').mockResolvedValue([]);
    vi.spyOn(api, 'getPolicies').mockResolvedValue({} as never);
    vi.spyOn(api, 'getConfigHistory').mockResolvedValue([]);
    vi.spyOn(api, 'listCertificates').mockResolvedValue([]);
    vi.spyOn(api, 'getClusterStatus').mockResolvedValue({
      mode: 'standalone',
      redis_connected: false,
      active_version: 1,
      channel: '',
    });
    const applyConfig = vi.spyOn(api, 'applyConfig').mockResolvedValue({ version: 2, hash: 'abc' });

    const wrapper = mount(SitesView);
    await flushPromises();

    expect(wrapper.text()).toContain('1 staged change');
    const applyButton = wrapper.find('[data-testid="sites-apply-now"]');
    expect(applyButton.exists()).toBe(true);

    await applyButton.trigger('click');
    await flushPromises();

    expect(applyConfig).toHaveBeenCalledTimes(1);
    expect(applyConfig).toHaveBeenCalledWith(
      expect.objectContaining({ author: expect.any(String), description: expect.any(String) })
    );
  });
});
