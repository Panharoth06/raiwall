import { describe, it, expect, beforeEach, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import { setActivePinia, createPinia } from 'pinia';
import { nextTick } from 'vue';
import RateLimitingTable from '@/components/http-flood/RateLimitingTable.vue';
import RateLimitingSettings from '@/components/http-flood/RateLimitingSettings.vue';
import HttpFloodView from '../HttpFloodView.vue';
import DashboardLayout from '@/layouts/DashboardLayout.vue';
import { router } from '@/router';
import { useConfigStore } from '@/stores/config';
import { api, type BanEntry } from '@/api/client';

const mockBans: BanEntry[] = [
  {
    key: '51.12.209.81|t13d1516h2_bot',
    client_ip: '51.12.209.81',
    ja4: 't13d1516h2_bot',
    country: 'Sweden',
    reason: 'tier1_velocity_limit',
    remaining_seconds: 60,
    banned_at: '2026-10-21T12:16:12Z',
    expires_at: '2026-10-21T12:17:12Z',
  },
  {
    key: '159.89.13.98',
    client_ip: '159.89.13.98',
    country: 'Germany',
    reason: 'tier2_attack_frequency',
    remaining_seconds: 1800,
    banned_at: '2026-10-21T10:50:37Z',
    expires_at: '2026-10-21T11:20:37Z',
  },
];

beforeEach(async () => {
  setActivePinia(createPinia());
  vi.restoreAllMocks();
  await router.navigate('/http-flood/limits');

  vi.spyOn(api, 'listBans').mockResolvedValue([...mockBans]);
  vi.spyOn(api, 'releaseBan').mockResolvedValue({ status: 'released', target: '51.12.209.81', released: true });
  vi.spyOn(api, 'releaseAllBans').mockResolvedValue({ status: 'unblocked_all', cleared: 2 });
});

describe('SafeLine HTTP Flood Workflow', () => {
  describe('RateLimitingTable.vue', () => {
    it('renders SafeLine filter bar, shadcn date pickers, and action buttons', async () => {
      const wrapper = mount(RateLimitingTable);
      await nextTick();
      await nextTick();

      expect(wrapper.text()).toContain('UNBLOCK ALL');
      expect(wrapper.text()).toContain('SETTINGS');
      expect(wrapper.text()).toContain('Start At');
      expect(wrapper.text()).toContain('End At');

      // Table headers
      expect(wrapper.text()).toContain('IP Addr');
      expect(wrapper.text()).toContain('Application');
      expect(wrapper.text()).toContain('Detail');
      expect(wrapper.text()).toContain('Blocked');
      expect(wrapper.text()).toContain('Start At');
      expect(wrapper.text()).toContain('Action');
    });

    it('renders IP rows with GeoIP country and JA4 badge', async () => {
      const wrapper = mount(RateLimitingTable);
      await nextTick();
      await nextTick();

      expect(wrapper.text()).toContain('51.12.209.81');
      expect(wrapper.text()).toContain('Sweden');
      expect(wrapper.text()).toContain('t13d1516h2_bot');
      expect(wrapper.text()).toContain('Dashboard Proxy');
      expect(wrapper.text()).toContain('Match All Host');
    });

    it('navigates to settings when clicking the SETTINGS button', async () => {
      const pushSpy = vi.spyOn(router, 'push');
      const wrapper = mount(RateLimitingTable);
      await nextTick();

      const settingsBtn = wrapper.findAll('button').find((b) => b.text().includes('SETTINGS'));
      expect(settingsBtn).toBeDefined();

      await settingsBtn!.trigger('click');
      expect(pushSpy).toHaveBeenCalledWith('/http-flood/limits/settings');
    });

    it('filters records by IP address input', async () => {
      const wrapper = mount(RateLimitingTable);
      await nextTick();
      await nextTick();

      const ipInput = wrapper.find('input[placeholder="Filter by IP address"]');
      expect(ipInput.exists()).toBe(true);

      await ipInput.setValue('159.89');
      await nextTick();

      expect(wrapper.text()).toContain('159.89.13.98');
      expect(wrapper.text()).not.toContain('51.12.209.81');
    });

    it('opens slide-over details drawer when clicking table row or Details button', async () => {
      const wrapper = mount(RateLimitingTable);
      await nextTick();
      await nextTick();

      const detailsBtn = wrapper.find('[role="button"]');
      expect(detailsBtn.exists()).toBe(true);
      expect(detailsBtn.text()).toContain('Details');

      await detailsBtn.trigger('click');
      await nextTick();

      // Drawer should be open in body Teleport
      expect(document.body.textContent).toContain('Defense Trigger');
      expect(document.body.textContent).toContain('Raw Violation Diagnostics');
      expect(document.body.textContent).toContain('Unblock Client IP');
    });
  });

  describe('RateLimitingSettings.vue', () => {
    it('renders the 3 SafeLine limiting sections with natural language sentences', async () => {
      const wrapper = mount(RateLimitingSettings);
      await nextTick();

      expect(wrapper.text()).toContain('Access Limiting');
      expect(wrapper.text()).toContain('Basic Access Limit');
      expect(wrapper.text()).toContain('Attack Limiting');
      expect(wrapper.text()).toContain('Basic Attack Limit');
      expect(wrapper.text()).toContain('Error Limiting');
      expect(wrapper.text()).toContain('Basic Error Limit');

      expect(wrapper.text()).toContain('An IP that makes');
      expect(wrapper.text()).toContain('Anti-Bot challenge');
      expect(wrapper.text()).toContain('automatically blocked');
    });

    it('navigates back to Rate Limiting when clicking Back button', async () => {
      const pushSpy = vi.spyOn(router, 'push');
      const wrapper = mount(RateLimitingSettings);
      await nextTick();

      const backBtn = wrapper.findAll('button').find((b) => b.text().includes('Back to Rate Limiting'));
      expect(backBtn).toBeDefined();

      await backBtn!.trigger('click');
      expect(pushSpy).toHaveBeenCalledWith('/http-flood/limits');
    });

    it('toggles a rule and automatically persists to configuration draft', async () => {
      const configStore = useConfigStore();
      const saveSpy = vi.spyOn(configStore, 'savePolicies').mockResolvedValue();

      const wrapper = mount(RateLimitingSettings);
      await nextTick();

      // Find switch buttons (radix switch renders role="switch")
      const switches = wrapper.findAll('button[role="switch"]');
      expect(switches.length).toBeGreaterThanOrEqual(3);

      await switches[0].trigger('click');
      await nextTick();

      expect(saveSpy).toHaveBeenCalled();
    });
  });

  describe('Arrow Nested Dropdown Navigation in DashboardLayout.vue and HttpFloodView.vue', () => {
    it('renders HTTP Flood with arrow chevron and toggles nested menu in DashboardLayout', async () => {
      await router.navigate('/http-flood/limits');
      const wrapper = mount(DashboardLayout);
      await nextTick();

      expect(wrapper.find('[data-testid="nav-http-flood"]').exists()).toBe(true);
      const chevron = wrapper.find('[data-testid="nav-http-flood-chevron"]');
      expect(chevron.exists()).toBe(true);

      // Initially dropped on /http-flood/limits
      expect(wrapper.find('[data-testid="nav-http-flood-limits"]').exists()).toBe(true);
      expect(wrapper.find('[data-testid="nav-http-flood-waiting-room"]').exists()).toBe(true);

      // Click arrow chevron to collapse nested menu
      await chevron.trigger('click');
      await nextTick();

      expect(wrapper.find('[data-testid="nav-http-flood-limits"]').exists()).toBe(false);
      expect(wrapper.find('[data-testid="nav-http-flood-waiting-room"]').exists()).toBe(false);

      // Click arrow chevron again to drop nested menu
      await chevron.trigger('click');
      await nextTick();

      expect(wrapper.find('[data-testid="nav-http-flood-limits"]').exists()).toBe(true);
      expect(wrapper.find('[data-testid="nav-http-flood-waiting-room"]').exists()).toBe(true);
    });

    it('renders sub-tabs for Rate Limiting and Waiting Room inside HttpFloodView', async () => {
      await router.navigate('/http-flood/limits');
      const wrapper = mount(HttpFloodView);
      await nextTick();

      expect(wrapper.find('[data-testid="tab-http-flood-limits"]').exists()).toBe(true);
      expect(wrapper.find('[data-testid="tab-http-flood-waiting-room"]').exists()).toBe(true);
      expect(wrapper.text()).toContain('HTTP Flood & Rate Limiting Defense');
    });
  });
});
