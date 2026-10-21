import { describe, it, expect, beforeEach, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import { setActivePinia, createPinia } from 'pinia';
import { nextTick } from 'vue';
import HttpFloodView from '../HttpFloodView.vue';
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

beforeEach(() => {
  setActivePinia(createPinia());
  vi.restoreAllMocks();
  global.ResizeObserver = MockResizeObserver as unknown as typeof ResizeObserver;

  vi.spyOn(api, 'listBans').mockResolvedValue([...mockBans]);
  vi.spyOn(api, 'releaseBan').mockResolvedValue({ status: 'released', target: '198.51.100.10', released: true });
  vi.spyOn(api, 'releaseAllBans').mockResolvedValue({ status: 'unblocked_all', cleared: 2 });
  vi.spyOn(api, 'getWaitingRoomMetrics').mockResolvedValue(mockMetrics);
});

describe('HttpFloodView.vue', () => {
  it('renders tab headers and defaults to Active Blocked Clients', async () => {
    const wrapper = mount(HttpFloodView);
    await nextTick();

    const tabItems = wrapper.findAll('[data-testid="tab-item"]');
    const tabTexts = tabItems.map((b) => b.text());

    expect(tabTexts.some((t) => t.includes('Active Blocked Clients'))).toBe(true);
    expect(tabTexts.some((t) => t.includes('3-Tier Limits Configuration'))).toBe(true);
    expect(tabTexts.some((t) => t.includes('Waiting Room Dashboard'))).toBe(true);

    // Active bans table should be rendered by default
    expect(api.listBans).toHaveBeenCalled();
    await nextTick();
    expect(wrapper.text()).toContain('198.51.100.10');
    expect(wrapper.text()).toContain('tier1_velocity_limit');
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
    // After unblocking first item, only second item remains
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

    // Confirm button inside teleported dialog
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

  it('switches to 3-Tier Limits tab and saves configuration to draft', async () => {
    const configStore = useConfigStore();
    const saveSpy = vi.spyOn(configStore, 'savePolicies').mockResolvedValue();

    const wrapper = mount(HttpFloodView);
    await nextTick();

    // Switch to limits tab
    const limitsTabBtn = wrapper.findAll('[data-testid="tab-item"]').find((b) => b.text().includes('3-Tier Limits Configuration'));
    expect(limitsTabBtn).toBeDefined();
    await limitsTabBtn!.trigger('click');
    await nextTick();

    expect(wrapper.text()).toContain('Tier 1: Access Velocity Limiting');
    expect(wrapper.text()).toContain('Tier 2: Attack Frequency Auto-Ban');
    expect(wrapper.text()).toContain('Tier 3: Upstream Scanner Trap');

    // Click Save to Draft
    const saveBtn = wrapper.findAll('button').find((b) => b.text().includes('Save to Draft'));
    expect(saveBtn).toBeDefined();
    await saveBtn!.trigger('click');

    expect(saveSpy).toHaveBeenCalled();
    await nextTick();
    expect(wrapper.text()).toContain('Volumetric defense policies saved to draft');
  });

  it('switches to Waiting Room Dashboard tab and displays live telemetry', async () => {
    const wrapper = mount(HttpFloodView);
    await nextTick();

    // Switch to waiting room tab
    const wrTabBtn = wrapper.findAll('[data-testid="tab-item"]').find((b) => b.text().includes('Waiting Room Dashboard'));
    expect(wrTabBtn).toBeDefined();
    await wrTabBtn!.trigger('click');
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

    // 198.51.100.20 has remaining_seconds: 3600 -> should format as '1h 00m 00s'
    expect(wrapper.text()).toContain('1h 00m 00s');
    // 198.51.100.10 has remaining_seconds: 120 -> should format as '2m 00s'
    expect(wrapper.text()).toContain('2m 00s');
  });

  it('allows updating waiting room capacity from dashboard', async () => {
    const wrapper = mount(HttpFloodView);
    await nextTick();

    // Switch to waiting room tab
    const wrTabBtn = wrapper.findAll('[data-testid="tab-item"]').find((b) => b.text().includes('Waiting Room Dashboard'));
    await wrTabBtn!.trigger('click');
    await nextTick();

    const capacityInput = wrapper.find('input[type="number"]');
    expect(capacityInput.exists()).toBe(true);

    await capacityInput.setValue('2500');
    await nextTick();

    // Switch to limits tab or save and verify policy capacity updated
    const saveBtn = wrapper.findAll('button').find((b) => b.text().includes('Save to Draft'));
    const configStore = useConfigStore();
    const saveSpy = vi.spyOn(configStore, 'savePolicies').mockResolvedValue();
    await saveBtn!.trigger('click');

    expect(saveSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        waiting_room_max_concurrent: 2500,
      })
    );
  });
});
