import { describe, it, expect, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import ThreatAnalytics from '@/components/ThreatAnalytics.vue';
import AttackGlobe from '@/components/AttackGlobe.vue';
import type { AggregateStats, ForensicEvent } from '@/types/telemetry';

describe('ThreatAnalytics.vue', () => {
  const sampleStats: AggregateStats = {
    total_requests: 12500,
    total_blocked: 850,
    block_ratio: 0.068,
    time_buckets: [
      { bucket: '2026-10-19T08:00:00Z', total: 3000, block: 200 },
      { bucket: '2026-10-19T09:00:00Z', total: 4500, block: 350 },
      { bucket: '2026-10-19T10:00:00Z', total: 5000, block: 300 },
    ],
    top_countries: [
      { key: 'CN', count: 420 },
      { key: 'RU', count: 210 },
      { key: 'US', count: 120 },
    ],
    top_rules: [
      { key: 'SEMANTIC_SQLI', count: 500 },
      { key: 'RATE_LIMIT_TIER2', count: 250 },
      { key: 'ACL_GEO_FENCE', count: 100 },
    ],
    top_ips: [
      { key: '198.51.100.1', count: 180 },
      { key: '203.0.113.5', count: 95 },
    ],
  };

  it('renders KPI summary cards with formatted metrics', () => {
    const wrapper = mount(ThreatAnalytics, {
      props: { stats: sampleStats },
    });

    const totalReq = wrapper.find('[data-testid="metric-total-requests"]');
    expect(totalReq.text()).toBe('12,500');

    const totalBlocked = wrapper.find('[data-testid="metric-total-blocked"]');
    expect(totalBlocked.text()).toBe('850');

    const topCountry = wrapper.find('[data-testid="metric-top-country"]');
    expect(topCountry.text()).toBe('CN');

    const topRule = wrapper.find('[data-testid="metric-top-rule"]');
    expect(topRule.text()).toBe('SEMANTIC_SQLI');
  });

  it('renders time bucket bars and threat breakdown', () => {
    const wrapper = mount(ThreatAnalytics, {
      props: { stats: sampleStats },
    });

    const chart = wrapper.find('[data-testid="time-buckets-chart"]');
    expect(chart.exists()).toBe(true);

    const ruleRows = wrapper.findAll('[data-testid="rule-row"]');
    expect(ruleRows.length).toBe(3);
    expect(wrapper.text()).toContain('SEMANTIC_SQLI');
    expect(wrapper.text()).toContain('RATE_LIMIT_TIER2');
  });

  it('emits refresh event on click', async () => {
    const wrapper = mount(ThreatAnalytics, {
      props: { stats: sampleStats },
    });

    const btn = wrapper.find('[data-testid="refresh-stats-btn"]');
    await btn.trigger('click');
    expect(wrapper.emitted('refresh')).toBeTruthy();
  });
});

describe('AttackGlobe.vue', () => {
  it('mounts with canvas element and renders protected gateway coordinates', () => {
    const wrapper = mount(AttackGlobe, {
      props: {
        gatewayLat: 37.7749,
        gatewayLon: -122.4194,
        width: 400,
        height: 300,
      },
    });

    const canvas = wrapper.find('[data-testid="attack-globe-canvas"]');
    expect(canvas.exists()).toBe(true);
    expect(wrapper.text()).toContain('Protected Gateway');
    expect(wrapper.text()).toContain('Lat: 37.77, Lon: -122.42');
  });

  it('accepts incoming threat events and pushes attack arcs', async () => {
    const event: ForensicEvent = {
      event_id: 'evt-threat',
      timestamp: '2026-10-19T10:00:00Z',
      host: 'example.com',
      path: '/api/login',
      method: 'POST',
      client_ip: '185.220.101.5',
      action: 'block',
      severity: 'critical',
      rule_id: 'SQLI_ATTACK',
      geo_data: {
        country: 'NL',
        latitude: 52.3676,
        longitude: 4.9041,
      },
      latency: 1200000,
      status_code: 403,
    };

    const wrapper = mount(AttackGlobe, {
      props: {
        events: [event],
      },
    });

    expect(wrapper.find('[data-testid="attack-globe-container"]').exists()).toBe(true);
    expect(wrapper.text()).toContain('Attack Arcs');
  });
});
