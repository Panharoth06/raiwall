import { describe, it, expect, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import StatsGeoPanel from '@/components/statistics/StatsGeoPanel.vue';
import type { GeoIPStatus, TopCount } from '@/types/telemetry';

const geoIPDisabled: GeoIPStatus = { country_db: false, city_db: false, asn_db: false };
const geoIPActive: GeoIPStatus = { country_db: true, city_db: true, asn_db: false };

function mountPanel(props: {
  countries?: TopCount[];
  geoip?: GeoIPStatus | null;
}) {
  return mount(StatsGeoPanel, {
    props: {
      countries: props.countries ?? [],
      totalRequests: 10,
      totalBlocked: 2,
      geoip: props.geoip ?? null,
    },
  });
}

describe('StatsGeoPanel.vue', () => {
  it('flags a disabled GeoIP database instead of reporting an empty window', () => {
    const wrapper = mountPanel({ geoip: geoIPDisabled });

    expect(wrapper.find('[data-testid="geoip-disabled-badge"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="geoip-disabled-empty"]').exists()).toBe(true);
    expect(wrapper.text()).toContain('GeoIP lookup is disabled');
  });

  it('explains private client IPs when GeoIP is active but no country was recorded', () => {
    const wrapper = mountPanel({ geoip: geoIPActive });

    expect(wrapper.find('[data-testid="geoip-disabled-badge"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="geoip-disabled-empty"]').exists()).toBe(false);
    expect(wrapper.text()).toContain('No public client IP was recorded');
  });

  it('plots only countries that have known coordinates', () => {
    const wrapper = mountPanel({
      countries: [
        { key: 'DE', count: 120 },
        { key: 'ZZ', count: 4 },
      ],
      geoip: geoIPActive,
    });

    expect(wrapper.findAll('[data-testid="country-row"]').length).toBe(2);
    // ZZ has no centroid, so only DE produces a globe marker.
    expect(wrapper.findAll('.cobe-marker-anchor').length).toBe(1);
  });

  it('copies the GeoIP setup snippet from the empty state action', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    });

    const wrapper = mountPanel({ geoip: geoIPDisabled });
    const button = wrapper.find('[data-testid="geoip-disabled-empty"] button');
    await button.trigger('click');
    await wrapper.vm.$nextTick();

    expect(writeText).toHaveBeenCalledOnce();
    expect(writeText.mock.calls[0][0]).toContain('RAIWALL_GEOIP_LICENSE_KEY');
    expect(button.text()).toContain('Copied');
  });
});
