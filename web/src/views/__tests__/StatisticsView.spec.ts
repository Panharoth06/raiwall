import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import { createPinia, setActivePinia } from 'pinia';
import StatisticsView from '@/views/StatisticsView.vue';
import type { AggregateStats } from '@/types/telemetry';

const mockStats: AggregateStats = {
  total_requests: 13200,
  total_blocked: 5000,
  block_ratio: 0.3788,
  page_views: 5300,
  unique_visitors: 930,
  unique_ips: 336,
  blocked_ips: 10,
  status_4xx: 3400,
  status_4xx_rate: 0.2546,
  status_4xx_blocked: 7700,
  status_4xx_blocked_rate: 0.5801,
  status_5xx: 1500,
  status_5xx_rate: 0.0013,
  qps: 12,
  time_buckets: [
    { bucket: '2026-10-24T12:00:00Z', total: 6400, block: 4100 },
    { bucket: '2026-10-24T13:00:00Z', total: 3200, block: 1500 },
  ],
  top_countries: [
    { key: 'China', count: 11300 },
    { key: 'Bulgaria', count: 894 },
    { key: 'Netherlands', count: 435 },
    { key: 'United States', count: 291 },
  ],
  top_rules: [
    { key: 'SEMANTIC_SQLI', count: 3200 },
    { key: 'RATE_LIMIT_TIER2', count: 1800 },
  ],
  top_ips: [
    { key: '198.51.100.1', count: 420 },
    { key: '203.0.113.5', count: 310 },
  ],
  top_categories: [
    { key: 'SQL Injection', count: 3200 },
    { key: 'Rate Limiting', count: 1800 },
  ],
};

describe('StatisticsView.vue (SafeLine Redesign)', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation((url: string) => {
        if (url.includes('/telemetry/events/stats') || url.includes('/events/stats')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: () => Promise.resolve(mockStats),
          });
        }
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: () => Promise.resolve([]),
        });
      })
    );
  });

  it('renders all SafeLine KPI metric cards correctly from backend data', async () => {
    const wrapper = mount(StatisticsView);
    await new Promise((r) => setTimeout(r, 50));

    expect(wrapper.find('[data-testid="metric-requests"]').text()).toBe('13.2k');
    expect(wrapper.find('[data-testid="metric-page-views"]').text()).toBe('5.3k');
    expect(wrapper.find('[data-testid="metric-unique-visitors"]').text()).toBe('930');
    expect(wrapper.find('[data-testid="metric-unique-ips"]').text()).toBe('336');
    expect(wrapper.find('[data-testid="metric-blocked"]').text()).toBe('5.0k');
    expect(wrapper.find('[data-testid="metric-blocked-ips"]').text()).toBe('10');
  });

  it('renders SafeLine 4xx/5xx error and blocked rate metrics correctly', async () => {
    const wrapper = mount(StatisticsView);
    await new Promise((r) => setTimeout(r, 50));

    expect(wrapper.find('[data-testid="metric-4xx-errors"]').text()).toBe('3.4k');
    expect(wrapper.find('[data-testid="metric-4xx-rate"]').text()).toBe('25.46%');
    expect(wrapper.find('[data-testid="metric-4xx-blocked"]').text()).toBe('7.7k');
    expect(wrapper.find('[data-testid="metric-blocked-rate"]').text()).toBe('58.01%');
    expect(wrapper.find('[data-testid="metric-5xx-errors"]').text()).toBe('1.5k');
    expect(wrapper.find('[data-testid="metric-5xx-rate"]').text()).toBe('0.13%');
  });

  it('renders Geo Location panel with 3D/2D toggle and country leaderboard', async () => {
    const wrapper = mount(StatisticsView);
    await new Promise((r) => setTimeout(r, 50));

    expect(wrapper.text()).toContain('Geo Location');
    expect(wrapper.find('[data-testid="toggle-3d"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="toggle-2d"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="toggle-requests-mode"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="toggle-blocked-mode"]').exists()).toBe(true);

    const countryRows = wrapper.findAll('[data-testid="country-row"]');
    expect(countryRows.length).toBe(4);
    expect(wrapper.text()).toContain('China');
    expect(wrapper.text()).toContain('Bulgaria');
  });

  it('filters by country when clicking a country leaderboard row', async () => {
    const wrapper = mount(StatisticsView);
    await new Promise((r) => setTimeout(r, 50));

    const countryRows = wrapper.findAll('[data-testid="country-row"]');
    await countryRows[0].trigger('click');

    expect(wrapper.text()).toContain('China');
  });

  it('switches between sub-navigation tabs', async () => {
    const wrapper = mount(StatisticsView);
    await new Promise((r) => setTimeout(r, 50));

    // Initially in traffic analysis
    expect(wrapper.find('[data-testid="metric-requests"]').exists()).toBe(true);

    // Switch to Security Posture
    const secTab = wrapper.find('[data-testid="tab-security-posture"]');
    await secTab.trigger('click');
    expect(wrapper.text()).toContain('Under Active Protection');

    // Switch to Data Dashboard
    const dataTab = wrapper.find('[data-testid="tab-data-dashboard"]');
    await dataTab.trigger('click');
    expect(wrapper.find('[data-testid="metric-requests"]').exists()).toBe(true);

    // Switch back to Traffic Analysis
    const trafficTab = wrapper.find('[data-testid="tab-traffic-analysis"]');
    await trafficTab.trigger('click');
    expect(wrapper.find('[data-testid="metric-requests"]').exists()).toBe(true);
  });
});
