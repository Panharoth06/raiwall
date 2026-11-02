import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mount, flushPromises, type VueWrapper } from '@vue/test-utils';
import AuditPanel from '../AuditPanel.vue';
import { api, type AuditEvent } from '@/api/client';

vi.mock('@/api/client', () => ({
  api: { listAuditEvents: vi.fn(), verifyAuditChain: vi.fn() },
}));

const mocked = vi.mocked(api);

const event = (overrides: Partial<AuditEvent> = {}): AuditEvent => ({
  id: 'e-1',
  occurred_at: '2026-01-01T00:00:00Z',
  actor_type: 'user',
  actor_name: 'alice',
  role: 'admin',
  action: 'update',
  target_type: 'site',
  target_id: 'app-1',
  method: 'PUT',
  path: '/api/v1/sites/app-1',
  status_code: 200,
  client_ip: '203.0.113.5',
  ...overrides,
});

describe('AuditPanel.vue', () => {
  let wrapper: VueWrapper | undefined;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(mocked.listAuditEvents).mockResolvedValue({ events: [], limit: 50, offset: 0 });
  });

  afterEach(() => {
    wrapper?.unmount();
    wrapper = undefined;
  });

  it('renders audit rows', async () => {
    vi.mocked(mocked.listAuditEvents).mockResolvedValue({ events: [event()], limit: 50, offset: 0 });
    wrapper = mount(AuditPanel);
    await flushPromises();

    expect(wrapper.text()).toContain('alice');
    expect(wrapper.text()).toContain('update');
    expect(wrapper.text()).toContain('site/app-1');
    expect(wrapper.text()).toContain('203.0.113.5');
  });

  it('shows the empty state', async () => {
    wrapper = mount(AuditPanel);
    await flushPromises();
    expect(wrapper.text()).toContain('No audit events');
  });

  it('surfaces errors with retry', async () => {
    vi.mocked(mocked.listAuditEvents)
      .mockRejectedValueOnce(new Error('audit unavailable'))
      .mockResolvedValueOnce({ events: [event()], limit: 50, offset: 0 });

    wrapper = mount(AuditPanel);
    await flushPromises();
    expect(wrapper.text()).toContain('audit unavailable');

    const retry = wrapper.findAll('button').find((button) => button.text().includes('Retry'));
    await retry?.trigger('click');
    await flushPromises();
    expect(wrapper.text()).toContain('alice');
  });

  it('verifies the hash chain on demand', async () => {
    vi.mocked(mocked.verifyAuditChain).mockResolvedValue({
      valid: true,
      checked: 42,
      unchained: 0,
      first_seq: 1,
      last_seq: 42,
      anchors: {
        enabled: true,
        count: 2,
        checked: 2,
        valid: true,
        key_fingerprint: 'sha256:0123456789abcdef',
      },
    });

    wrapper = mount(AuditPanel);
    await flushPromises();

    const verify = wrapper.findAll('button').find((button) => button.text().includes('Verify chain'));
    await verify?.trigger('click');
    await flushPromises();

    expect(mocked.verifyAuditChain).toHaveBeenCalledTimes(1);
    expect(wrapper.text()).toContain('Chain intact');
    expect(wrapper.text()).toContain('42 events');
    expect(wrapper.text()).toContain('2 anchors');
    expect(wrapper.text()).toContain('sha256:0123456789abcdef');
  });

  it('reports a broken chain with the failing sequence', async () => {
    vi.mocked(mocked.verifyAuditChain).mockResolvedValue({
      valid: false,
      checked: 10,
      unchained: 0,
      first_seq: 1,
      last_seq: 10,
      broken_at_seq: 7,
      reason: 'event contents do not match the recorded hash',
      anchors: { enabled: true, count: 1, checked: 1, valid: true },
    });

    wrapper = mount(AuditPanel);
    await flushPromises();

    const verify = wrapper.findAll('button').find((button) => button.text().includes('Verify chain'));
    await verify?.trigger('click');
    await flushPromises();

    expect(wrapper.text()).toContain('Chain broken at sequence 7');
    expect(wrapper.text()).toContain('event contents do not match the recorded hash');
  });
});
