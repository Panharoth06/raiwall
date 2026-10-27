import { describe, it, expect, beforeEach, vi } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createPinia, setActivePinia } from 'pinia';
import BlockPagesView from '../BlockPagesView.vue';
import { templatesApi } from '@/api/templates';

vi.mock('@/api/templates', () => ({
  TEMPLATE_STATUS_CODES: [
    { code: 403, name: 'Forbidden (WAF Block)', category: 'Security', description: 'WAF block' },
    { code: 404, name: 'Not Found', category: 'Standard', description: 'Not found' },
    { code: 429, name: 'Too Many Requests', category: 'Rate Limit', description: 'Rate limit' },
    { code: 465, name: 'Virtual Waiting Room', category: 'Waiting Room', description: 'Waiting room' },
    { code: 466, name: 'Maintenance Mode', category: 'Offline', description: 'Maintenance' },
    { code: 467, name: 'Identity Gateway Auth', category: 'Identity', description: 'Identity' },
    { code: 468, name: 'PoW Bot Challenge', category: 'Bot Defense', description: 'Bot PoW' },
    { code: 502, name: 'Bad Gateway', category: 'Upstream', description: 'Upstream down' },
    { code: 504, name: 'Gateway Timeout', category: 'Upstream', description: 'Timeout' },
  ],
  templatesApi: {
    listTemplates: vi.fn(),
    getTemplate: vi.fn(),
    updateTemplate: vi.fn(),
    resetTemplate: vi.fn(),
    previewTemplate: vi.fn(),
  },
}));

describe('BlockPagesView.vue (Task 95)', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    vi.clearAllMocks();

    vi.mocked(templatesApi.listTemplates).mockResolvedValue([
      {
        id: 'tmpl-403',
        status_code: 403,
        title: 'Security Violation',
        content_html: '<h1>Blocked {{.EventID}}</h1>',
        custom_css: 'body { color: red; }',
        brand_name: 'Raiwall',
        logo_url: '',
        is_custom: false,
      },
    ]);

    vi.mocked(templatesApi.getTemplate).mockResolvedValue({
      id: 'tmpl-403',
      status_code: 403,
      title: 'Security Violation',
      content_html: '<h1>Blocked {{.EventID}}</h1>',
      custom_css: 'body { color: red; }',
      brand_name: 'Raiwall',
      logo_url: '',
      is_custom: false,
    });

    vi.mocked(templatesApi.previewTemplate).mockResolvedValue({
      rendered_html: '<!DOCTYPE html><html><body><h1>Blocked preview-123</h1></body></html>',
    });
  });

  it('renders status code pills for deterministic response codes', async () => {
    const wrapper = mount(BlockPagesView);
    await flushPromises();

    expect(wrapper.text()).toContain('Block Pages & Response Templates');
    expect(wrapper.text()).toContain('403');
    expect(wrapper.text()).toContain('404');
    expect(wrapper.text()).toContain('429');
    expect(wrapper.text()).toContain('465');
    expect(wrapper.text()).toContain('466');
    expect(wrapper.text()).toContain('467');
    expect(wrapper.text()).toContain('468');
    expect(wrapper.text()).toContain('502');
    expect(wrapper.text()).toContain('504');
  });

  it('renders sandboxed live preview iframe and viewport controls', async () => {
    const wrapper = mount(BlockPagesView);
    await flushPromises();

    const iframe = wrapper.find('iframe');
    expect(iframe.exists()).toBe(true);
    expect(iframe.attributes('sandbox')).toBe('allow-same-origin');

    const tabletBtn = wrapper.find('button[title*="Tablet"]');
    expect(tabletBtn.exists()).toBe(true);
    await tabletBtn.trigger('click');

    const iframeContainer = wrapper.find('[style*="768px"]');
    expect(iframeContainer.exists()).toBe(true);
  });

  it('saves template modifications via API', async () => {
    vi.mocked(templatesApi.updateTemplate).mockResolvedValue({
      id: 'tmpl-403',
      status_code: 403,
      title: 'Custom 403',
      content_html: '<h1>Custom Blocked</h1>',
      custom_css: 'body { color: blue; }',
      brand_name: 'AcmeCorp',
      logo_url: '',
      is_custom: true,
    });

    const wrapper = mount(BlockPagesView);
    await flushPromises();

    const saveBtn = wrapper.find('[data-testid="btn-save-template"]');
    expect(saveBtn.exists()).toBe(true);
    await saveBtn.trigger('click');
    await flushPromises();

    expect(templatesApi.updateTemplate).toHaveBeenCalledWith(403, expect.objectContaining({
      brand_name: 'Raiwall',
      content_html: '<h1>Blocked {{.EventID}}</h1>',
      custom_css: 'body { color: red; }',
    }));
  });
});
