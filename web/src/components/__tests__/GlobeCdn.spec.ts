import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import GlobeCdn from '@/components/GlobeCdn.vue';
import type { CdnMarker, CdnArc } from '@/components/cobeDefaults';

describe('GlobeCdn.vue', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  it('mounts with default markers, default arcs, and canvas element', () => {
    const wrapper = mount(GlobeCdn);
    const canvas = wrapper.find('canvas');
    expect(canvas.exists()).toBe(true);

    // Verify default markers exist
    const markerTags = wrapper.findAll('.cobe-marker-anchor');
    expect(markerTags.length).toBe(10);
    expect(wrapper.text()).toContain('iad1');
    expect(wrapper.text()).toContain('sfo1');
    expect(wrapper.text()).toContain('sin1');
  });

  it('renders custom dynamic markers and arcs passed via props', async () => {
    const customMarkers: CdnMarker[] = [
      { id: 'gw-primary', location: [37.77, -122.42], region: 'US-WEST' },
      { id: 'edge-tokyo', location: [35.68, 139.69], region: 'AP-NORTHEAST' },
    ];
    const customArcs: CdnArc[] = [
      { id: 'arc-traffic-1', from: [37.77, -122.42], to: [35.68, 139.69], value: 750 },
    ];

    const wrapper = mount(GlobeCdn, {
      props: {
        markers: customMarkers,
        arcs: customArcs,
        speed: 0.005,
      },
    });

    const markerTags = wrapper.findAll('.cobe-marker-anchor');
    expect(markerTags.length).toBe(2);
    expect(wrapper.text()).toContain('US-WEST');
    expect(wrapper.text()).toContain('AP-NORTHEAST');

    const trafficPills = wrapper.findAll('.cobe-traffic-anchor');
    expect(trafficPills.length).toBe(1);
    expect(wrapper.text()).toContain('750k req/s');
  });

  it('dynamically fluctuates traffic values on interval tick', async () => {
    const customArcs: CdnArc[] = [
      { id: 'live-arc', from: [40.71, -74.0], to: [51.5, -0.12], value: 500 },
    ];

    const wrapper = mount(GlobeCdn, {
      props: {
        arcs: customArcs,
      },
    });

    expect(wrapper.text()).toContain('500k req/s');

    // Advance timer to trigger dynamic interval
    vi.advanceTimersByTime(250);
    await wrapper.vm.$nextTick();

    // Value should still be rendered and formatted with 'k req/s'
    const trafficPill = wrapper.find('.cobe-traffic-anchor');
    expect(trafficPill.exists()).toBe(true);
    expect(trafficPill.text()).toMatch(/\d+k req\/s/);
  });
});
