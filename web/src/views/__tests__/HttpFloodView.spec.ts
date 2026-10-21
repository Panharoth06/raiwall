import { describe, it, expect, beforeEach, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import { setActivePinia, createPinia } from 'pinia';
import { nextTick } from 'vue';
import HttpFloodView from '../HttpFloodView.vue';
import { router } from '@/router';
import { useConfigStore } from '@/stores/config';
import { api, type BanEntry, type WaitingRoomMetrics } from '@/api/client';

class MockResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const mockBans: BanEntry[] = [
  {
    key: '198.51.100.10|t13d1516h2_bot',
    client_ip: '198.51.100.10',
    ja4: 't13d1516h2_bot',
    reason: 'tier1_velocity_limit',
    remaining_seconds: 120,
    banned_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 120000).toISOString(),
  },
  {
    key: '198.51.100.20',
    client_ip: '198.51.100.20',
    reason: 'tier3_scanner_trap',
    remaining_seconds: 3600,
    banned_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 3600000).toISOString(),
  },
];

const mockMetrics: WaitingRoomMetrics = {
  active_in_flight: 42,
  total_waiting: 15,
  peak_queue_depth: 60,
  avg_wait_seconds: 4.5,
  bounce_rate: 2.3,
  total_admitted: 350,
  total_enqueued: 365,
  total_abandoned: 8,
};

beforeEach(async () => {
  setActivePinia(createPinia());
  vi.restoreAllMocks();
  await router.navigate('/http-flood/limits');
  global.ResizeObserver = MockResizeObserver as unknown as typeof ResizeObserver;

  vi.spyOn(api, 'listBans').mockResolvedValue([...mockBans]);
  vi.spyOn(api, 'releaseBan').mockResolvedValue({ status: 'released', target: '198.51.100.10', released: true });
  vi.spyOn(api, 'releaseAllBans').mockResolvedValue({ status: 'unblocked_all', cleared: 2 });
  vi.spyOn(api, 'getWaitingRoomMetrics').mockResolvedValue(mockMetrics);
});

describe('HttpFloodView.vue', () => {
  it('renders Rate Limiting Table by default on /http-flood/limits', async () => {
    const wrapper = mount(HttpFloodView);
    await nextTick();
    await nextTick();

    expect(api.listBans).toHaveBeenCalled();
    expect(wrapper.text()).toContain('198.51.100.10');
    expect(wrapper.text()).toContain('tier1_velocity_limit');
    expect(wrapper.text()).toContain('UNBLOCK ALL');
    expect(wrapper.text()).toContain('SETTINGS');
  });

  it('performs single ban release when clicking Unblock button', async () => {
    const wrapper = mount(HttpFloodView);
    await nextTick();
    await nextTick();

    const unblockButtons = wrapper.findAll('tbody button');
    expect(unblockButtons.length).toBe(2);

    await unblockButtons[0].trigger('click');
    expect(api.releaseBan).toHaveBeenCalledWith({
      key: '198.51.100.10|t13d1516h2_bot',
      ip: '198.51.100.10',
    });

    await nextTick();
    expect(wrapper.text()).not.toContain('198.51.100.10|t13d1516h2_bot');
    expect(wrapper.text()).toContain('198.51.100.20');
  });

  it('opens confirmation modal and executes emergency unblock all', async () => {
    const wrapper = mount(HttpFloodView);
    await nextTick();
    await nextTick();

    const unblockAllBtn = wrapper.findAll('button').find((b) => b.text().includes('UNBLOCK ALL'));
    expect(unblockAllBtn).toBeDefined();

    await unblockAllBtn!.trigger('click');
    await nextTick();

    const confirmBtn = Array.from(document.body.querySelectorAll('button')).find((b) =>
      b.textContent?.includes('Confirm Emergency Unblock')
    );
    expect(confirmBtn).toBeDefined();

    confirmBtn!.click();
    await nextTick();
    await nextTick();
    expect(api.releaseAllBans).toHaveBeenCalled();

    await nextTick();
    expect(wrapper.text()).toContain('No active client bans');
  });

  it('renders 3-Tier Limits configuration in settings view only (/http-flood/limits/settings)', async () => {
    await router.navigate('/http-flood/limits/settings');
    const wrapper = mount(HttpFloodView);
    await nextTick();

    expect(wrapper.text()).toContain('Access Limiting');
    expect(wrapper.text()).toContain('Basic Access Limit');
    expect(wrapper.text()).toContain('Attack Limiting');
    expect(wrapper.text()).toContain('Basic Attack Limit');
    expect(wrapper.text()).toContain('Error Limiting');
    expect(wrapper.text()).toContain('Basic Error Limit');
  });

  it('renders Waiting Room Dashboard on /http-flood/waiting-room', async () => {
    await router.navigate('/http-flood/waiting-room');
    const wrapper = mount(HttpFloodView);
    await nextTick();

    expect(api.getWaitingRoomMetrics).toHaveBeenCalled();
    expect(wrapper.text()).toContain('Virtual Waiting Room Engine (HTTP 465)');
    expect(wrapper.text()).toContain('Users Waiting');
    expect(wrapper.text()).toContain('Client Bounce Rate');
  });

  it('formats remaining ban countdown with hours when duration exceeds 3600s', async () => {
    const wrapper = mount(HttpFloodView);
    await nextTick();
    await nextTick();

    expect(wrapper.text()).toContain('1h 00m 00s');
    expect(wrapper.text()).toContain('2m 00s');
  });
});
