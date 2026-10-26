import { describe, it, expect, vi } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { ref } from 'vue';
import LiveInspector from '@/components/LiveInspector.vue';
import { Select } from '@/components/ui/select';
import { router } from '@/router';
import type { ForensicEvent, Incident } from '@/types/telemetry';

describe('LiveInspector.vue', () => {
  const sampleEvents: ForensicEvent[] = [
    {
      event_id: 'evt-1',
      timestamp: '2026-10-19T10:00:00Z',
      host: 'example.com',
      path: '/api/v1/login?user=admin',
      method: 'POST',
      client_ip: '192.168.1.10',
      ja4: 't13d1516h2_8daaf6152771_b186095e22b6',
      geo_data: { country: 'US', city: 'Ashburn', asn: 15169 },
      rule_id: 'SEMANTIC_SQLI',
      action: 'block',
      severity: 'high',
      headers: { 'User-Agent': 'curl/8.1.2', Authorization: '[REDACTED]' },
      truncated_payload: 'SELECT * FROM users',
      latency: 1500000,
      status_code: 403,
    },
    {
      event_id: 'evt-2',
      timestamp: '2026-10-19T10:01:00Z',
      host: 'example.com',
      path: '/public/styles.css',
      method: 'GET',
      client_ip: '10.0.0.5',
      action: 'allow',
      severity: 'info',
      geo_data: { country: 'DE' },
      latency: 500000,
      status_code: 200,
    },
  ];

  function createMockStream(initialEvents = sampleEvents) {
    const eventsRef = ref<ForensicEvent[]>([...initialEvents]);
    const isConnectedRef = ref(true);
    const isPausedRef = ref(false);
    const errorRef = ref<string | null>(null);

    const pause = vi.fn(() => {
      isPausedRef.value = true;
    });
    const resume = vi.fn(() => {
      isPausedRef.value = false;
    });
    const clear = vi.fn(() => {
      eventsRef.value = [];
    });
    const connect = vi.fn();
    const disconnect = vi.fn();

    return {
      events: eventsRef,
      isConnected: isConnectedRef,
      isPaused: isPausedRef,
      error: errorRef,
      pause,
      resume,
      clear,
      connect,
      disconnect,
    };
  }

  it('renders live event table and clean status text without green dot', () => {
    const stream = createMockStream();
    const wrapper = mount(LiveInspector, {
      props: {
        streamComposable: stream as any,
      },
    });

    const statusText = wrapper.find('[data-testid="status-text"]');
    expect(statusText.exists()).toBe(true);
    expect(statusText.text()).toBe('Live Telemetry');
    expect(wrapper.find('[data-testid="status-indicator"]').exists()).toBe(false);

    const rows = wrapper.findAll('[data-testid="event-row"]');
    expect(rows.length).toBe(2);
    expect(wrapper.text()).toContain('SEMANTIC_SQLI');
    expect(wrapper.text()).toContain('192.168.1.10');
  });

  it('filters events in real-time by search query', async () => {
    const stream = createMockStream();
    const wrapper = mount(LiveInspector, {
      props: {
        streamComposable: stream as any,
      },
    });

    const searchInput = wrapper.find('[data-testid="live-search-input"]');
    await searchInput.setValue('SQLI');

    const rows = wrapper.findAll('[data-testid="event-row"]');
    expect(rows.length).toBe(1);
    expect(wrapper.text()).toContain('192.168.1.10');
    expect(wrapper.text()).not.toContain('10.0.0.5');
  });

  it('filters events by action dropdown', async () => {
    const stream = createMockStream();
    const wrapper = mount(LiveInspector, {
      props: {
        streamComposable: stream as any,
      },
    });

    const actionSelect = wrapper.findComponent(Select);
    actionSelect.vm.$emit('update:modelValue', 'allow');
    await flushPromises();

    const rows = wrapper.findAll('[data-testid="event-row"]');
    expect(rows.length).toBe(1);
    expect(wrapper.text()).toContain('/public/styles.css');
  });

  it('does not render pause or clear buttons', () => {
    const stream = createMockStream();
    const wrapper = mount(LiveInspector, {
      props: {
        streamComposable: stream as any,
      },
    });

    expect(wrapper.find('[data-testid="pause-resume-btn"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="clear-events-btn"]').exists()).toBe(false);
  });

  it('opens detail modal and emits create-exception action', async () => {
    const stream = createMockStream();
    const wrapper = mount(LiveInspector, {
      props: {
        streamComposable: stream as any,
      },
    });

    // Click on row to open modal
    const row = wrapper.find('[data-testid="event-row"]');
    await row.trigger('click');

    const modal = wrapper.find('[data-testid="forensic-modal"]');
    expect(modal.exists()).toBe(true);
    expect(modal.text()).toContain('Forensic Incident Context');
    expect(modal.text()).toContain('SELECT * FROM users');

    // Click Create Exception in modal
    const createExBtn = wrapper.find('[data-testid="modal-create-exception-btn"]');
    await createExBtn.trigger('click');

    const emitted = wrapper.emitted('create-exception');
    expect(emitted).toBeTruthy();
    expect(emitted![0][0]).toEqual({
      host: 'example.com',
      path: '/api/v1/login',
      method: 'POST',
      location: 'body',
      param: '*',
      rule_id: 'SEMANTIC_SQLI',
    });

    // Modal should close
    expect(wrapper.find('[data-testid="forensic-modal"]').exists()).toBe(false);
  });

  it('emits create-exception directly from table row quick action', async () => {
    const stream = createMockStream();
    const wrapper = mount(LiveInspector, {
      props: {
        streamComposable: stream as any,
      },
    });

    const quickBtn = wrapper.find('[data-testid="create-exception-quick-btn"]');
    await quickBtn.trigger('click');

    const emitted = wrapper.emitted('create-exception');
    expect(emitted).toBeTruthy();
    expect(emitted![0][0]).toEqual({
      host: 'example.com',
      path: '/api/v1/login',
      method: 'POST',
      location: 'body',
      param: '*',
      rule_id: 'SEMANTIC_SQLI',
    });
  });

  const sampleIncidents: Incident[] = [
    {
      id: 'inc-1',
      client_ip: '192.168.1.10',
      host: 'example.com',
      start_time: '2026-10-19T10:00:00Z',
      end_time: '2026-10-19T10:04:30Z',
      total_events: 12,
      total_blocked: 9,
      category: 'SQL Injection',
      max_severity: 'high',
      top_rule_id: 'SEMANTIC_SQLI',
      country: 'US',
    },
    {
      id: 'inc-2',
      client_ip: '198.51.100.7',
      host: 'admin.example.com',
      start_time: '2026-10-19T09:10:00Z',
      end_time: '2026-10-19T09:11:00Z',
      total_events: 3,
      total_blocked: 3,
      category: 'XSS',
      max_severity: 'medium',
      top_rule_id: 'SEMANTIC_XSS',
    },
  ];

  it('switches between aggregated incidents and granular events views', async () => {
    await router.navigate('/attacks');
    const stream = createMockStream();
    const incidentLoader = vi.fn().mockResolvedValue({ incidents: sampleIncidents, total_count: 2 });

    const wrapper = mount(LiveInspector, {
      props: { streamComposable: stream as any, incidentLoader, view: 'events' },
    });

    expect(wrapper.findAll('[data-testid="event-row"]').length).toBe(2);
    expect(incidentLoader).not.toHaveBeenCalled();

    await wrapper.setProps({ view: 'incidents' });
    await flushPromises();

    expect(incidentLoader).toHaveBeenCalledTimes(1);
    expect(wrapper.findAll('[data-testid="incident-card"]').length).toBe(2);
    expect(wrapper.text()).toContain('SQL Injection');
    expect(wrapper.text()).toContain('12 events');

    await wrapper.setProps({ view: 'events' });
    expect(wrapper.findAll('[data-testid="event-row"]').length).toBe(2);
    wrapper.unmount();
  });

  it('opens granular events filtered by the clicked incident and syncs URL query', async () => {
    await router.navigate('/attacks');
    const stream = createMockStream();
    const incidentLoader = vi.fn().mockResolvedValue({ incidents: sampleIncidents, total_count: 2 });

    const wrapper = mount(LiveInspector, {
      props: { streamComposable: stream as any, incidentLoader, view: 'incidents' },
    });

    await flushPromises();
    await wrapper.findAll('[data-testid="incident-card"]')[0].trigger('click');
    await flushPromises();

    expect(wrapper.emitted('update:view')).toBeUndefined();
    expect(router.current.value.query.tab).toBe('events');

    // The parent tab bar drives the view; simulate it switching back to events.
    await wrapper.setProps({ view: 'events' });
    await flushPromises();

    expect(wrapper.findAll('[data-testid="event-row"]').length).toBe(1);
    expect(wrapper.text()).toContain('192.168.1.10');
    expect(wrapper.text()).not.toContain('10.0.0.5');

    const chip = wrapper.find('[data-testid="host-filter-chip"]');
    expect(chip.exists()).toBe(true);
    expect(chip.text()).toContain('example.com');

    expect(router.current.value.query.ip).toBe('192.168.1.10');
    expect(router.current.value.query.host).toBe('example.com');
    wrapper.unmount();
  });

  it('copies a generated cURL command from the forensic drawer', async () => {
    await router.navigate('/attacks');
    const stream = createMockStream();
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });

    const curlLoader = vi.fn().mockResolvedValue({ curl: "curl -X POST 'http://example.com/api/v1/login'" });
    const ipGroupLoader = vi.fn().mockResolvedValue([]);

    const wrapper = mount(LiveInspector, {
      props: { streamComposable: stream as any, curlLoader, ipGroupLoader },
    });

    await wrapper.find('[data-testid="event-row"]').trigger('click');
    await flushPromises();
    await wrapper.find('[data-testid="copy-curl-btn"]').trigger('click');
    await flushPromises();

    expect(curlLoader).toHaveBeenCalledWith('evt-1');
    expect(writeText).toHaveBeenCalledWith("curl -X POST 'http://example.com/api/v1/login'");
    expect(wrapper.find('[data-testid="copy-curl-btn"]').text()).toContain('Copied');
    wrapper.unmount();
  });

  it('adds the offending client IP to a named IP group from the drawer', async () => {
    await router.navigate('/attacks');
    const stream = createMockStream();
    const ipGroupLoader = vi.fn().mockResolvedValue([{ id: 'grp-mal', name: 'malicious_ips' }]);
    const ipGroupAdder = vi.fn().mockResolvedValue({});

    const wrapper = mount(LiveInspector, {
      props: { streamComposable: stream as any, ipGroupLoader, ipGroupAdder },
    });

    await wrapper.find('[data-testid="event-row"]').trigger('click');
    await flushPromises();
    await wrapper.find('[data-testid="add-to-ipgroup-btn"]').trigger('click');
    await flushPromises();

    expect(ipGroupAdder).toHaveBeenCalledWith('grp-mal', '192.168.1.10', expect.stringContaining('SEMANTIC_SQLI'));
    expect(wrapper.text()).toContain('Added 192.168.1.10 to malicious_ips');
    expect(wrapper.emitted('add-to-ipgroup')?.[0]).toEqual([
      { event: expect.objectContaining({ event_id: 'evt-1' }), groupId: 'grp-mal' },
    ]);
    wrapper.unmount();
  });
});
