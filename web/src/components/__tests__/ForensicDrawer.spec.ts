import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import { nextTick } from 'vue';
import ForensicDrawer from '@/components/forensic/ForensicDrawer.vue';
import type { ForensicEvent, IPGroupOption } from '@/types/telemetry';

const event: ForensicEvent = {
  event_id: 'evt-drawer-1',
  timestamp: '2026-10-20T09:00:00Z',
  host: 'shop.example.com',
  path: '/search?q=1%27%20OR%201%3D1--',
  method: 'GET',
  client_ip: '203.0.113.42',
  ja4: 't13d1516h2_8daaf6152771_b186095e22b6',
  geo_data: { country: 'US' },
  rule_id: 'SEMANTIC_SQLI',
  action: 'block',
  severity: 'critical',
  headers: { 'User-Agent': 'sqlmap/1.8', Cookie: 'sid=[REDACTED]' },
  truncated_payload: "q=1' OR 1=1--",
  latency: 2400000,
  status_code: 403,
  payload_location: 'QUERY',
  matched_token: "' OR 1=1--",
  attack_category: 'SQL Injection',
  response_headers: { 'Content-Type': ['application/json'] },
  // base64 of {"error":"blocked"}
  response_body: 'eyJlcnJvciI6ImJsb2NrZWQifQ==',
};

const groups: IPGroupOption[] = [
  { id: 'grp-mal', name: 'malicious_ips', entry_count: 12 },
  { id: 'grp-custom', name: 'custom_blocklist', entry_count: 0 },
];

describe('ForensicDrawer.vue', () => {
  it('renders parameter location, attack category, JA4 link and highlighted token', () => {
    const wrapper = mount(ForensicDrawer, { props: { event } });

    expect(wrapper.find('[data-testid="payload-location"]').text()).toBe('QUERY');
    expect(wrapper.text()).toContain('SQL Injection');
    expect(wrapper.text()).toContain('SEMANTIC_SQLI');

    const ja4Link = wrapper.find('[data-testid="ja4-link"]');
    expect(ja4Link.exists()).toBe(true);
    expect(ja4Link.attributes('href')).toContain('t13d1516h2_8daaf6152771_b186095e22b6');

    const highlighted = wrapper.findAll('[data-testid="matched-token"]');
    expect(highlighted.length).toBeGreaterThan(0);
    expect(highlighted[0].text()).toBe("' OR 1=1--");
  });

  it('switches between REQUEST and RESPONSE and decodes the captured body', async () => {
    const wrapper = mount(ForensicDrawer, { props: { event } });

    expect(wrapper.find('[data-testid="encoding-select"]').exists()).toBe(true);
    expect(wrapper.text()).toContain('sqlmap/1.8');

    await wrapper.find('[data-testid="drawer-tab-response"]').trigger('click');
    await nextTick();

    expect(wrapper.find('[data-testid="encoding-select"]').exists()).toBe(false);
    expect(wrapper.text()).toContain('HTTP 403');
    expect(wrapper.text()).toContain('Content-Type: application/json');
    expect(wrapper.text()).toContain('{"error":"blocked"}');

    await wrapper.find('[data-testid="drawer-tab-request"]').trigger('click');
    await nextTick();
    expect(wrapper.find('[data-testid="encoding-select"]').exists()).toBe(true);
  });

  it('emits copy-curl and create-exception from the footer actions', async () => {
    const wrapper = mount(ForensicDrawer, { props: { event } });

    await wrapper.find('[data-testid="copy-curl-btn"]').trigger('click');
    await wrapper.find('[data-testid="modal-create-exception-btn"]').trigger('click');

    expect(wrapper.emitted('copy-curl')?.[0]).toEqual([event]);
    expect(wrapper.emitted('create-exception')).toBeTruthy();
  });

  it('emits add-to-ipgroup with the selected group', async () => {
    const wrapper = mount(ForensicDrawer, { props: { event, groups } });

    const select = wrapper.find('[data-testid="ipgroup-select"]');
    await select.setValue('grp-custom');
    await wrapper.find('[data-testid="add-to-ipgroup-btn"]').trigger('click');

    expect(wrapper.emitted('add-to-ipgroup')?.[0]).toEqual([{ event, groupId: 'grp-custom' }]);
  });

  it('blocks clipboard actions while a curl command is being generated', () => {
    const wrapper = mount(ForensicDrawer, { props: { event, curlState: 'loading' } });
    const button = wrapper.find('[data-testid="copy-curl-btn"]');
    expect(button.text()).toContain('Generating');
    expect((button.element as HTMLButtonElement).disabled).toBe(true);
  });

  it('hides exception controls for allowed traffic', () => {
    const wrapper = mount(ForensicDrawer, {
      props: { event: { ...event, action: 'allow', status_code: 200 } },
    });
    expect(wrapper.find('[data-testid="modal-create-exception-btn"]').exists()).toBe(false);
    expect(wrapper.text()).toContain('Traffic Telemetry Context');
  });
});
