import { describe, it, expect, beforeEach, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import LogsViewer from '@/components/LogsViewer.vue';
import { api } from '@/api/client';
import type { ForensicEvent, EventsQueryResult } from '@/api/client';

vi.mock('@/api/client', () => ({
  api: {
    listEvents: vi.fn(),
  },
}));

describe('LogsViewer.vue', () => {
  const sampleLogs: ForensicEvent[] = [
    {
      event_id: 'log-1',
      timestamp: '2026-10-21T18:00:00Z',
      host: 'api.example.com',
      path: '/api/v1/auth?user=admin',
      method: 'POST',
      client_ip: '198.51.100.1',
      ja4: 't13d1516h2_abc123',
      geo_data: { country: 'US', city: 'Dallas', asn: 13335 },
      rule_id: 'SEMANTIC_SQLI',
      action: 'block',
      severity: 'high',
      headers: { 'User-Agent': 'python-requests/2.28' },
      truncated_payload: '1 UNION SELECT username, password FROM users',
      latency: 1200000,
      status_code: 403,
    },
    {
      event_id: 'log-2',
      timestamp: '2026-10-21T18:05:00Z',
      host: 'app.example.com',
      path: '/dashboard',
      method: 'GET',
      client_ip: '203.0.113.50',
      action: 'allow',
      severity: 'info',
      geo_data: { country: 'FR' },
      latency: 450000,
      status_code: 200,
    },
  ];

  beforeEach(() => {
    vi.restoreAllMocks();
    vi.mocked(api.listEvents).mockResolvedValue({
      events: sampleLogs,
      total: 2,
      limit: 20,
      offset: 0,
    } as EventsQueryResult);
  });

  it('renders forensic logs table with fetched records', async () => {
    const wrapper = mount(LogsViewer, {
      props: {
        pageSize: 20,
      },
    });

    await vi.waitFor(() => {
      expect(api.listEvents).toHaveBeenCalled();
    });

    // Wait for DOM update
    await wrapper.vm.$nextTick();

    expect(wrapper.find('[data-testid="logs-title"]').text()).toBe('Forensic Logs');
    const rows = wrapper.findAll('[data-testid="log-row"]');
    expect(rows.length).toBe(2);
    expect(wrapper.text()).toContain('SEMANTIC_SQLI');
    expect(wrapper.text()).toContain('198.51.100.1');
    expect(wrapper.text()).toContain('2 records');
  });

  it('filters logs by action select', async () => {
    const wrapper = mount(LogsViewer);

    await vi.waitFor(() => {
      expect(api.listEvents).toHaveBeenCalled();
    });

    const actionSelect = wrapper.find('[data-testid="logs-action-filter-select"]');
    await actionSelect.setValue('block');

    expect(api.listEvents).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'block',
      })
    );
  });

  it('filters logs by search query', async () => {
    vi.useFakeTimers();
    const wrapper = mount(LogsViewer);

    const searchInput = wrapper.find('[data-testid="logs-search-input"]');
    await searchInput.setValue('198.51.100.1');

    vi.advanceTimersByTime(350);

    expect(api.listEvents).toHaveBeenCalledWith(
      expect.objectContaining({
        client_ip: '198.51.100.1',
      })
    );
    vi.useRealTimers();
  });

  it('opens detail modal and emits create-exception action', async () => {
    const wrapper = mount(LogsViewer);

    await vi.waitFor(() => {
      expect(api.listEvents).toHaveBeenCalled();
    });
    await wrapper.vm.$nextTick();

    const row = wrapper.find('[data-testid="log-row"]');
    await row.trigger('click');

    const modal = wrapper.find('[data-testid="forensic-modal"]');
    expect(modal.exists()).toBe(true);
    expect(modal.text()).toContain('Forensic Incident Context');
    expect(modal.text()).toContain('UNION SELECT');

    const createExBtn = wrapper.find('[data-testid="log-modal-create-exception-btn"]');
    await createExBtn.trigger('click');

    const emitted = wrapper.emitted('create-exception');
    expect(emitted).toBeTruthy();
    expect(emitted![0][0]).toEqual({
      host: 'api.example.com',
      path: '/api/v1/auth',
      method: 'POST',
      location: 'body',
      param: '*',
      rule_id: 'SEMANTIC_SQLI',
    });
  });

  it('emits create-exception directly from log row quick action', async () => {
    const wrapper = mount(LogsViewer);

    await vi.waitFor(() => {
      expect(api.listEvents).toHaveBeenCalled();
    });
    await wrapper.vm.$nextTick();

    const quickBtn = wrapper.find('[data-testid="log-create-exception-quick-btn"]');
    await quickBtn.trigger('click');

    const emitted = wrapper.emitted('create-exception');
    expect(emitted).toBeTruthy();
    expect(emitted![0][0]).toEqual({
      host: 'api.example.com',
      path: '/api/v1/auth',
      method: 'POST',
      location: 'body',
      param: '*',
      rule_id: 'SEMANTIC_SQLI',
    });
  });
});
