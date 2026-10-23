import { describe, it, expect, beforeEach, vi } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { setActivePinia, createPinia } from 'pinia';
import { nextTick } from 'vue';
import SiteDetailView from '../SiteDetailView.vue';
import ForwardingRulesEditor from '@/components/site-detail/ForwardingRulesEditor.vue';
import ProxyConfigEditor from '@/components/site-detail/ProxyConfigEditor.vue';
import ApiInventoryTable from '@/components/site-detail/ApiInventoryTable.vue';
import { router } from '@/router';
import { api, type Site, type ForwardingRule, type APIResource } from '@/api/client';

/** Stub radix-vue Switch — teleports to body in jsdom so wrapper.find misses it. */
const switchStub = {
  props: ['modelValue'],
  emits: ['update:modelValue'],
  inheritAttrs: true,
  template: `<button v-bind="$attrs" :data-checked="String(!!modelValue)" @click="$emit('update:modelValue', !modelValue)" />`,
};

vi.mock('@/api/client', async (importOriginal) => {
  const mod = await importOriginal<typeof import('@/api/client')>();
  return { ...mod, api: { ...mod.api, listSites: vi.fn(), updateSite: vi.fn(), listForwardingRules: vi.fn(), createForwardingRule: vi.fn(), deleteForwardingRule: vi.fn(), updateForwardingRule: vi.fn(), listAPIResources: vi.fn(), deleteAPIResource: vi.fn() } };
});

class MockResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const mockSite: Site = {
  id: 'site-1',
  name: 'Primary API',
  hostnames: ['api.example.com', 'edge.example.com'],
  mode: 'defense',
  upstreams: [{ dial: '10.0.0.1:8080', weight: 2 }],
  block_status_code: 403,
  offline_status_code: 503,
  custom_headers: { 'X-Frame-Options': 'DENY' },
  proxy_settings: {
    client_ip_source: 'xff',
    rewrite_xff: true,
    hsts: true,
    enable_sse: false,
    enable_compression: false,
    enable_ipv6: false,
    redirect_http: true,
  },
};

const mockRules: ForwardingRule[] = [
  {
    id: 'fwd-1',
    app_id: 'site-1',
    prefix: '/api/v2',
    upstreams: [{ dial: '10.0.0.9:9090', weight: 1 }],
    strip_prefix: true,
    host_header_override: '',
    comment: '',
    is_active: true,
  },
];

const mockResources: APIResource[] = [
  {
    id: 'res-1',
    app_id: 'site-1',
    method: 'GET',
    path_pattern: '/users/{id}',
    content_type: 'application/json',
    hit_count: 4812,
    last_seen: new Date().toISOString(),
  },
];

beforeEach(async () => {
  setActivePinia(createPinia());
  vi.restoreAllMocks();
  document.body.innerHTML = '';
  global.ResizeObserver = MockResizeObserver as unknown as typeof ResizeObserver;
  vi.mocked(api.listSites).mockResolvedValue([mockSite]);
  vi.mocked(api.listForwardingRules).mockResolvedValue(mockRules);
  vi.mocked(api.createForwardingRule).mockResolvedValue(mockRules[0]);
  vi.mocked(api.updateForwardingRule).mockResolvedValue(mockRules[0]);
  vi.mocked(api.deleteForwardingRule).mockResolvedValue({ status: 'deleted', id: 'fwd-1' });
  vi.mocked(api.listAPIResources).mockResolvedValue(mockResources);
  vi.mocked(api.deleteAPIResource).mockResolvedValue({ status: 'deleted', id: 'res-1' });
  vi.mocked(api.updateSite).mockResolvedValue(mockSite);
});

const stubs = { Switch: switchStub };

describe('SiteDetailView.vue (4-tab application detail)', () => {
  it('shows Basic Information by default on /sites/:id', async () => {
    await router.navigate('/sites/site-1');
    const wrapper = mount(SiteDetailView, { global: { stubs } });
    await flushPromises();

    expect(wrapper.find('[data-testid="site-panel-basic"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="site-name"]').text()).toContain('Primary API');
    expect(wrapper.text()).toContain('10.0.0.1:8080');
    expect(wrapper.text()).toContain('403 / 503');
  });

  it('shows a not-found empty state for unknown ids', async () => {
    await router.navigate('/sites/unknown');
    const wrapper = mount(SiteDetailView, { global: { stubs } });
    await flushPromises();
    expect(wrapper.find('[data-testid="site-error"]').exists()).toBe(true);
    wrapper.unmount();
  });

  it('swaps to the Forwarding Rules, Advanced Settings, and Inventory panels on sub-routes', async () => {
    await router.navigate('/sites/site-1/rules');
    let wrapper = mount(SiteDetailView, { global: { stubs } });
    await flushPromises();
    expect(wrapper.findComponent(ForwardingRulesEditor).exists()).toBe(true);
    expect(wrapper.find('[data-testid="fwd-row-0"]').exists()).toBe(true);
    expect(wrapper.text()).toContain('/api/v2');
    wrapper.unmount();

    await router.navigate('/sites/site-1/proxy');
    wrapper = mount(SiteDetailView, { global: { stubs } });
    await flushPromises();
    expect(wrapper.findComponent(ProxyConfigEditor).exists()).toBe(true);
    expect(wrapper.find('[data-testid="proxy-toggle-hsts"]').exists()).toBe(true);
    wrapper.unmount();

    await router.navigate('/sites/site-1/inventory');
    wrapper = mount(SiteDetailView, { global: { stubs } });
    await flushPromises();
    expect(wrapper.findComponent(ApiInventoryTable).exists()).toBe(true);
    expect(wrapper.text()).toContain('/users/{id}');
    wrapper.unmount();
  });
});

describe('ForwardingRulesEditor.vue', () => {
  it('creates a path-prefix rule with parsed upstream targets', async () => {
    const wrapper = mount(ForwardingRulesEditor, { props: { site: mockSite } });
    await flushPromises();

    await wrapper.find('[data-testid="fwd-add"]').trigger('click');
    await nextTick();
    await nextTick();

    setField('fwd-dialog-prefix', '/api/v3');
    setField('fwd-dialog-upstreams', '10.0.0.14:8080, 10.0.0.15:8080');
    const save = document.body.querySelector('[data-testid="fwd-dialog-save"]') as HTMLButtonElement;
    save.click();
    await flushPromises();

    expect(api.createForwardingRule).toHaveBeenCalledWith('site-1', expect.objectContaining({
      prefix: '/api/v3',
      strip_prefix: false,
    }));
    const payload = vi.mocked(api.createForwardingRule).mock.calls[0][1] as ForwardingRule;
    expect(payload.upstreams.map((u) => u.dial)).toEqual(['10.0.0.14:8080', '10.0.0.15:8080']);
    expect(wrapper.text()).toContain('path prefixes routing');
    wrapper.unmount();
  });

  it('rejects a rule whose prefix does not start with a slash', async () => {
    const wrapper = mount(ForwardingRulesEditor, { props: { site: mockSite } });
    await flushPromises();
    await wrapper.find('[data-testid="fwd-add"]').trigger('click');
    await nextTick();
    await nextTick();

    setField('fwd-dialog-prefix', 'api/v3');
    setField('fwd-dialog-upstreams', '10.0.0.14:8080');
    const save = document.body.querySelector('[data-testid="fwd-dialog-save"]') as HTMLButtonElement;
    save.click();
    await nextTick();
    await nextTick();

    expect(api.createForwardingRule).not.toHaveBeenCalled();
    expect(document.body.textContent).toContain('Prefix must start with "/".');
    wrapper.unmount();
  });

  it('prunes a forwarding rule', async () => {
    const wrapper = mount(ForwardingRulesEditor, { props: { site: mockSite } });
    await flushPromises();
    await wrapper.find('[data-testid="fwd-delete-0"]').trigger('click');
    await flushPromises();
    expect(api.deleteForwardingRule).toHaveBeenCalledWith('site-1', 'fwd-1');
    expect(wrapper.find('[data-testid="fwd-empty"]').exists()).toBe(true);
    wrapper.unmount();
  });
});

describe('ProxyConfigEditor.vue', () => {
  it('applies the proxy matrix to the site', async () => {
    const wrapper = mount(ProxyConfigEditor, {
      props: { site: mockSite },
      global: { stubs },
    });
    await nextTick();

    // Flip SSE streaming on via the stubbed Switch button.
    await wrapper.find('[data-testid="proxy-toggle-enable_sse"]').trigger('click');
    await nextTick();
    const apply = wrapper.find('[data-testid="proxy-apply"]');
    expect((apply.element as HTMLButtonElement).disabled).toBe(false);
    await apply.trigger('click');
    await flushPromises();

    expect(api.updateSite).toHaveBeenCalledWith('site-1', {
      proxy_settings: expect.objectContaining({
        client_ip_source: 'xff',
        enable_sse: true,
        rewrite_xff: true,
        hsts: true,
        redirect_http: true,
      }),
    });
  });
});

describe('ApiInventoryTable.vue', () => {
  it('lists discovered endpoints and prunes a stale entry', async () => {
    const wrapper = mount(ApiInventoryTable, { props: { siteId: 'site-1' } });
    await flushPromises();

    expect(wrapper.text()).toContain('/users/{id}');
    expect(wrapper.text()).toContain('4812');
    await wrapper.find('[data-testid="inventory-prune-0"]').trigger('click');
    await flushPromises();

    expect(api.deleteAPIResource).toHaveBeenCalledWith('site-1', 'res-1');
    expect(wrapper.find('[data-testid="inventory-empty"]').exists()).toBe(true);
    wrapper.unmount();
  });
});

// --- helpers ---------------------------------------------------------------

function setField(testId: string, value: string) {
  const input = document.body.querySelector(`[data-testid="${testId}"] input`) as HTMLInputElement;
  expect(input).toBeTruthy();
  input.value = value;
  input.dispatchEvent(new Event('input'));
}
